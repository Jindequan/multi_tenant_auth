"""
极简权限服务 - 一个表解决所有权限问题
"""

import logging
from typing import List, Dict, Optional, Any

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

from ..models import User, UserWorkspaceActions, Workspace, TeamMember
from ..constants import (
    PERMISSION_CACHE_KEY_FORMAT,
    DEFAULT_CACHE_TIMEOUT,
    ROLE_PERMISSIONS,
    AVAILABLE_PERMISSIONS
)
from ..exceptions import PermissionDenied, WorkspaceNotFoundError, UserNotFoundError


logger = logging.getLogger(__name__)


class PermissionService:
    """极简权限服务"""

    def __init__(self):
        self.cache_timeout = getattr(settings, 'MULTI_TENANT_AUTH_CACHE_TIMEOUT', DEFAULT_CACHE_TIMEOUT)

    def get_cache_key(self, user_id: str, workspace_id: str) -> str:
        """获取权限缓存键"""
        return f"perm:{user_id}:{workspace_id}"

    def check_permission(self, user_id: str, workspace_id: str, action: str) -> bool:
        """
        极简权限检查 - 一次查询解决所有问题

        Args:
            user_id: 用户ID
            workspace_id: 工作空间ID
            action: 权限动作 ('view', 'edit', 'delete', 'share', 'comment')

        Returns:
            bool: 是否有权限
        """
        cache_key = self.get_cache_key(user_id, workspace_id)

        # 检查缓存
        permissions = cache.get(cache_key)
        if permissions is None:
            permissions = self._get_workspace_permissions_from_db(user_id, workspace_id)
            cache.set(cache_key, permissions, self.cache_timeout)

        return action in permissions

    def check_permissions(self, user_id: str, workspace_id: str, actions: List[str]) -> Dict[str, bool]:
        """
        批量权限检查 - 一次查询检查多个权限

        Args:
            user_id: 用户ID
            workspace_id: 工作空间ID
            actions: 权限动作列表

        Returns:
            Dict[str, bool]: 权限检查结果
        """
        permissions = self.get_workspace_permissions(user_id, workspace_id)
        return {action: (action in permissions) for action in actions}

    def get_workspace_permissions(self, user_id: str, workspace_id: str) -> List[str]:
        """
        获取用户在工作空间的所有权限

        Args:
            user_id: 用户ID
            workspace_id: 工作空间ID

        Returns:
            List[str]: 权限列表
        """
        cache_key = self.get_cache_key(user_id, workspace_id)

        permissions = cache.get(cache_key)
        if permissions is None:
            permissions = self._get_workspace_permissions_from_db(user_id, workspace_id)
            cache.set(cache_key, permissions, self.cache_timeout)

        return permissions

    def _get_workspace_permissions_from_db(self, user_id: str, workspace_id: str) -> List[str]:
        """从数据库获取用户在工作空间的权限"""
        try:
            permission_obj = UserWorkspaceActions.objects.get(
                user_id=user_id,
                workspace_id=workspace_id
            )

            # 检查权限是否过期
            if permission_obj.is_expired:
                return []

            return permission_obj.effective_actions

        except UserWorkspaceActions.DoesNotExist:
            return []

    def grant_permissions(
        self,
        granter_id: str,
        user_id: str,
        workspace_id: str,
        actions: List[str]
    ) -> UserWorkspaceActions:
        """
        设置权限 - 一次操作完成

        Args:
            granter_id: 授权人ID
            user_id: 被授权用户ID
            workspace_id: 工作空间ID
            actions: 权限列表

        Returns:
            UserWorkspaceActions: 权限对象
        """
        # 验证参数
        self._validate_grant_params(granter_id, user_id, workspace_id, actions)

        # 创建或更新权限
        permission_obj, created = UserWorkspaceActions.objects.update_or_create(
            user_id=user_id,
            workspace_id=workspace_id,
            defaults={
                'actions': actions,
                'granted_by_id': granter_id
            }
        )

        # 清除缓存
        cache.delete(self.get_cache_key(user_id, workspace_id))

        # 记录审计日志
        from ..models.audit import AuditLog
        AuditLog.log_action(
            user_id=granter_id,
            action='PERMISSION_GRANTED',
            resource_type='workspace',
            resource_id=workspace_id,
            metadata={
                'granted_to': user_id,
                'actions': actions,
                'created': created
            }
        )

        logger.info(f"Permissions granted: user={user_id}, workspace={workspace_id}, actions={actions}, created={created}")
        return permission_obj

    def revoke_permissions(self, user_id: str, workspace_id: str, revoked_by: str) -> bool:
        """
        撤销权限

        Args:
            user_id: 用户ID
            workspace_id: 工作空间ID
            revoked_by: 操作人ID

        Returns:
            bool: 是否成功撤销
        """
        try:
            permission_obj = UserWorkspaceActions.objects.get(
                user_id=user_id,
                workspace_id=workspace_id
            )

            # 记录审计日志
            from ..models.audit import AuditLog
            AuditLog.log_action(
                user_id=revoked_by,
                action='PERMISSION_REVOKED',
                resource_type='workspace',
                resource_id=workspace_id,
                metadata={
                    'revoked_from': user_id,
                    'previous_actions': permission_obj.actions
                }
            )

            permission_obj.delete()

            # 清除缓存
            cache.delete(self.get_cache_key(user_id, workspace_id))

            logger.info(f"Permissions revoked: user={user_id}, workspace={workspace_id}")
            return True

        except UserWorkspaceActions.DoesNotExist:
            logger.warning(f"Permission not found to revoke: user={user_id}, workspace={workspace_id}")
            return False

    def grant_role_permissions(
        self,
        granter_id: str,
        user_id: str,
        workspace_id: str,
        role_name: str
    ) -> UserWorkspaceActions:
        """
        基于角色授予权限

        Args:
            granter_id: 授权人ID
            user_id: 被授权用户ID
            workspace_id: 工作空间ID
            role_name: 角色名称

        Returns:
            UserWorkspaceActions: 权限对象
        """
        if role_name not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role_name}")

        role_actions = ROLE_PERMISSIONS[role_name]
        return self.grant_permissions(granter_id, user_id, workspace_id, role_actions)

    def get_user_workspaces(self, user_id: str, permissions: Optional[List[str]] = None) -> List[Workspace]:
        """
        获取用户有权限的工作空间

        Args:
            user_id: 用户ID
            permissions: 权限过滤列表 (可选)

        Returns:
            List[Workspace]: 工作空间列表
        """
        user_permissions = UserWorkspaceActions.objects.filter(
            user_id=user_id
        ).select_related('workspace')

        # 过滤有效权限
        valid_permissions = []
        for perm in user_permissions:
            if not perm.is_expired:
                valid_permissions.append(perm)

        # 按权限过滤
        if permissions:
            valid_permissions = [
                perm for perm in valid_permissions
                if any(action in perm.effective_actions for action in permissions)
            ]

        workspaces = [perm.workspace for perm in valid_permissions]
        return workspaces

    def grant_team_member_permissions(
        self,
        team_id: str,
        user_id: str,
        role_name: str,
        added_by: str
    ):
        """
        为团队成员在团队所有工作空间设置权限

        Args:
            team_id: 团队ID
            user_id: 用户ID
            role_name: 角色名称
            added_by: 添加人ID
        """
        try:
            from ..models import Team, Workspace
            team = Team.objects.get(id=team_id)
            workspaces = Workspace.objects.filter(team=team)

            role_actions = ROLE_PERMISSIONS.get(role_name, [])

            granted_count = 0
            for workspace in workspaces:
                try:
                    self.grant_permissions(added_by, user_id, workspace.id, role_actions)
                    granted_count += 1
                except Exception as e:
                    logger.error(f"Failed to grant workspace permissions: {str(e)}")

            logger.info(f"Team member permissions granted: team={team_id}, user={user_id}, role={role_name}, workspaces={granted_count}")
            return granted_count

        except Team.DoesNotExist:
            raise TeamNotFoundError(f"Team not found: {team_id}")

    def cleanup_expired_permissions(self) -> int:
        """
        清理过期的权限

        Returns:
            int: 清理的权限数量
        """
        now = timezone.now()
        expired_permissions = UserWorkspaceActions.objects.filter(
            expires_at__lt=now
        )

        count = expired_permissions.count()
        expired_permissions.delete()

        # 清除相关缓存
        for perm in expired_permissions:
            cache.delete(self.get_cache_key(str(perm.user_id), str(perm.workspace_id)))

        logger.info(f"Cleaned up {count} expired permissions")
        return count

    def _validate_grant_params(self, granter_id: str, user_id: str, workspace_id: str, actions: List[str]):
        """验证授权参数"""
        # 验证权限动作有效性
        for action in actions:
            if action not in AVAILABLE_PERMISSIONS:
                raise ValueError(f"Invalid permission action: {action}")

        # 验证用户存在
        try:
            User.objects.get(id=granter_id)
        except User.DoesNotExist:
            raise UserNotFoundError(f"Granter not found: {granter_id}")

        try:
            User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise UserNotFoundError(f"User not found: {user_id}")

        # 验证工作空间存在
        try:
            Workspace.objects.get(id=workspace_id)
        except Workspace.DoesNotExist:
            raise WorkspaceNotFoundError(f"Workspace not found: {workspace_id}")

    def refresh_cache(self, user_id: str, workspace_id: str) -> List[str]:
        """强制刷新权限缓存"""
        cache.delete(self.get_cache_key(user_id, workspace_id))
        return self.get_workspace_permissions(user_id, workspace_id)