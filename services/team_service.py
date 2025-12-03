"""
团队管理服务
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from django.utils import timezone
from django.conf import settings

from ..models import Team, TeamMember, User, Workspace, UserWorkspaceActions
from ..constants import (
    ROLE_PERMISSIONS,
    TEAM_MEMBER_ROLES,
    DEFAULT_INVITE_TOKEN_LIFETIME,
    AUDIT_ACTIONS
)
from ..exceptions import (
    TeamNotFoundError,
    UserNotFoundError,
    PermissionDenied,
    ValidationError
)


logger = logging.getLogger(__name__)


class TeamService:
    """团队管理服务"""

    def __init__(self):
        self.invite_token_lifetime = getattr(
            settings, 'MULTI_TENANT_AUTH_INVITE_TOKEN_LIFETIME',
            DEFAULT_INVITE_TOKEN_LIFETIME
        )

    def create_team(self, owner: User, name: str, slug: str, billing_tier: str = None, team_settings: Dict = None) -> Team:
        """
        创建团队

        Args:
            owner: 团队所有者
            name: 团队名称
            slug: 团队slug
            billing_tier: 计费等级
            team_settings: 团队设置

        Returns:
            Team: 创建的团队
        """
        # 验证参数
        self._validate_team_params(name, slug, team_settings or {})

        team = Team.objects.create(
            name=name,
            slug=slug,
            owner=owner,
            billing_tier=billing_tier,
            settings=team_settings or {}
        )

        # 记录审计日志
        from ..models.audit import AuditLog
        AuditLog.log_action(
            user=owner,
            action=AUDIT_ACTIONS['TEAM_CREATED'],
            resource_type='team',
            resource_id=team.id,
            metadata={
                'team_name': name,
                'team_slug': slug,
                'billing_tier': billing_tier
            }
        )

        logger.info(f"Team created: {team.id} by {owner.email}")
        return team

    def add_team_member(
        self,
        team: Team,
        user: User,
        role_name: str,
        added_by: User
    ) -> TeamMember:
        """
        添加团队成员

        Args:
            team: 团队对象
            user: 要添加的用户
            role_name: 角色名称
            added_by: 操作人

        Returns:
            TeamMember: 团队成员对象
        """
        # 验证角色
        if role_name not in TEAM_MEMBER_ROLES:
            raise ValidationError(f"Invalid role: {role_name}")

        # 检查是否已经是成员
        if TeamMember.objects.filter(team=team, user=user).exists():
            raise ValidationError(f"User {user.email} is already a team member")

        # 创建团队成员
        team_member = TeamMember.objects.create(
            team=team,
            user=user,
            role_name=role_name,
            is_active=True,
            added_by=added_by
        )

        # 为团队成员在所有团队工作空间设置权限
        from .permission_service import PermissionService
        permission_service = PermissionService()
        granted_count = permission_service.grant_team_member_permissions(
            granter_id=added_by.id,
            team_id=team.id,
            user_id=user.id,
            role_name=role_name
        )

        # 记录审计日志
        from ..models.audit import AuditLog
        AuditLog.log_action(
            user=user,
            action=AUDIT_ACTIONS['TEAM_MEMBER_ADDED'],
            resource_type='team',
            resource_id=team.id,
            metadata={
                'team_name': team.name,
                'role_name': role_name,
                'added_by': added_by.email,
                'workspaces_granted': granted_count
            }
        )

        logger.info(f"Team member added: {user.email} to {team.name} as {role_name}")
        return team_member

    def remove_team_member(
        self,
        team: Team,
        user: User,
        removed_by: User
    ) -> bool:
        """
        移除团队成员

        Args:
            team: 团队对象
            user: 要移除的用户
            removed_by: 操作人

        Returns:
            bool: 是否成功移除
        """
        try:
            team_member = TeamMember.objects.get(team=team, user=user)
        except TeamMember.DoesNotExist:
            raise ValidationError(f"User {user.email} is not a team member")

        # 不能移除团队所有者
        if team.owner == user:
            raise ValidationError("Cannot remove team owner from team")

        # 获取用户在团队工作空间的权限并撤销
        workspaces = Workspace.objects.filter(team=team)
        revoked_count = 0

        from .permission_service import PermissionService
        permission_service = PermissionService()

        for workspace in workspaces:
            try:
                permission_service.revoke_permissions(
                    user_id=user.id,
                    workspace_id=workspace.id,
                    revoked_by=removed_by.id
                )
                revoked_count += 1
            except Exception as e:
                logger.error(f"Failed to revoke workspace permission: {str(e)}")

        # 移除团队成员
        team_member.delete()

        # 记录审计日志
        from ..models.audit import AuditLog
        AuditLog.log_action(
            user=removed_by,
            action=AUDIT_ACTIONS['TEAM_MEMBER_REMOVED'],
            resource_type='team',
            resource_id=team.id,
            metadata={
                'team_name': team.name,
                'removed_user': user.email,
                'workspaces_revoked': revoked_count
            }
        )

        logger.info(f"Team member removed: {user.email} from {team.name}")
        return True

    def update_team_member_role(
        self,
        team: Team,
        user: User,
        new_role_name: str,
        updated_by: User
    ) -> TeamMember:
        """
        更新团队成员角色

        Args:
            team: 团队对象
            user: 用户对象
            new_role_name: 新角色名称
            updated_by: 操作人

        Returns:
            TeamMember: 更新后的团队成员对象
        """
        # 验证角色
        if new_role_name not in TEAM_MEMBER_ROLES:
            raise ValidationError(f"Invalid role: {new_role_name}")

        try:
            team_member = TeamMember.objects.get(team=team, user=user)
        except TeamMember.DoesNotExist:
            raise ValidationError(f"User {user.email} is not a team member")

        old_role = team_member.role_name
        team_member.role_name = new_role_name
        team_member.save(update_fields=['role_name'])

        # 更新用户在团队工作空间的权限
        from .permission_service import PermissionService
        permission_service = PermissionService()
        granted_count = permission_service.grant_team_member_permissions(
            granter_id=updated_by.id,
            team_id=team.id,
            user_id=user.id,
            role_name=new_role_name
        )

        # 记录审计日志
        from ..models.audit import AuditLog
        AuditLog.log_action(
            user=updated_by,
            action=AUDIT_ACTIONS['TEAM_MEMBER_UPDATED'],
            resource_type='team_member',
            resource_id=team_member.id,
            metadata={
                'team_name': team.name,
                'user_email': user.email,
                'old_role': old_role,
                'new_role': new_role_name,
                'workspaces_granted': granted_count
            }
        )

        logger.info(f"Team member role updated: {user.email} in {team.name} from {old_role} to {new_role_name}")
        return team_member

    def get_team_members(
        self,
        team: Team,
        include_inactive: bool = False,
        page: int = 1,
        limit: int = 20
    ) -> Dict:
        """
        获取团队成员列表

        Args:
            team: 团队对象
            include_inactive: 是否包含非激活成员
            page: 页码
            limit: 每页数量

        Returns:
            Dict: 包含成员列表和分页信息
        """
        queryset = TeamMember.objects.filter(team=team)

        if not include_inactive:
            queryset = queryset.filter(is_active=True)

        total = queryset.count()
        offset = (page - 1) * limit
        members = queryset.select_related('user').order_by('-joined_at')[offset:offset + limit]

        return {
            'members': members,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit
        }

    def get_user_teams(
        self,
        user: User,
        page: int = 1,
        limit: int = 20
    ) -> Dict:
        """
        获取用户的团队列表

        Args:
            user: 用户对象
            page: 页码
            limit: 每页数量

        Returns:
            Dict: 包含团队列表和分页信息
        """
        # 用户作为成员的团队
        member_teams = TeamMember.objects.filter(
            user=user,
            is_active=True
        ).select_related('team')

        # 用户拥有的团队
        owned_teams = Team.objects.filter(owner=user)

        # 合并并去重
        team_ids = set()
        teams = []

        # 添加拥有的团队
        for team in owned_teams:
            if team.id not in team_ids:
                team_ids.add(team.id)
                teams.append({
                    'team': team,
                    'role': 'owner',
                    'joined_at': team.created_at,
                    'is_owner': True
                })

        # 添加加入的团队
        for member in member_teams:
            if member.team.id not in team_ids:
                team_ids.add(member.team.id)
                teams.append({
                    'team': member.team,
                    'role': member.role_name,
                    'joined_at': member.joined_at,
                    'is_owner': False
                })

        # 按创建时间排序
        teams.sort(key=lambda x: x['joined_at'], reverse=True)

        # 分页
        total = len(teams)
        offset = (page - 1) * limit
        paginated_teams = teams[offset:offset + limit]

        return {
            'teams': paginated_teams,
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit
        }

    def _validate_team_params(self, name: str, slug: str, settings: Dict):
        """验证团队参数"""
        if not name or len(name.strip()) < 2:
            raise ValidationError("Team name must be at least 2 characters")

        if not slug or len(slug.strip()) < 2:
            raise ValidationError("Team slug must be at least 2 characters")

        if Team.objects.filter(slug=slug).exists():
            raise ValidationError("Team slug already exists")

        # 验证slug格式
        import re
        if not re.match(r'^[a-z0-9-]+$', slug):
            raise ValidationError("Team slug can only contain lowercase letters, numbers and hyphens")

    def get_team_statistics(self, team: Team) -> Dict:
        """获取团队统计信息"""
        return {
            'member_count': team.member_count,
            'workspace_count': team.workspaces.count(),
            'can_add_members': team.can_add_members,
            'max_members_limit': team.max_members_limit,
            'created_at': team.created_at.isoformat(),
            'billing_tier': team.billing_tier,
            'settings': team.settings
        }