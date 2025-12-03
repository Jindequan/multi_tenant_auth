"""
团队相关模型
"""

import uuid
from django.db import models
from django.conf import settings

from .base import AuthBaseModel
from ..constants import TEAM_MEMBER_ROLES


class Team(AuthBaseModel):
    """团队模型"""

    name = models.CharField(
        max_length=255,
        help_text="团队名称"
    )
    slug = models.SlugField(
        max_length=255,
        unique=True,
        help_text="团队slug，用于URL"
    )
    owner = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='owned_teams',
        help_text="团队所有者"
    )
    billing_tier = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="计费等级"
    )
    settings = models.JSONField(
        default=dict,
        help_text="团队设置 {allow_public_workspace: boolean, max_members: number}"
    )

    class Meta:
        db_table = '"multi_tenant_auth"."team"'
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['owner']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name} ({self.slug})"

    @property
    def member_count(self):
        """团队成员数量"""
        return self.members.filter(is_active=True).count()

    @property
    def max_members_limit(self):
        """最大成员数量限制"""
        return self.settings.get('max_members', None)

    @property
    def can_add_members(self):
        """是否可以添加成员"""
        max_members = self.max_members_limit
        if max_members is None:
            return True
        return self.member_count < max_members

    @property
    def allow_public_workspace(self):
        """是否允许公开工作空间"""
        return self.settings.get('allow_public_workspace', False)


class TeamMember(AuthBaseModel):
    """团队成员模型"""

    team = models.ForeignKey(
        Team,
        on_delete=models.CASCADE,
        related_name='members',
        help_text="所属团队"
    )
    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='team_memberships',
        help_text="成员用户"
    )
    role_name = models.CharField(
        max_length=50,
        choices=[(role, role) for role in TEAM_MEMBER_ROLES],
        help_text="成员角色"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="是否激活"
    )
    invited_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_invitations',
        help_text="邀请人"
    )
    invited_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="邀请时间"
    )
    joined_at = models.DateTimeField(
        auto_now_add=True,
        help_text="加入时间"
    )

    class Meta:
        db_table = '"multi_tenant_auth"."team_member"'
        unique_together = ['team', 'user']
        indexes = [
            models.Index(fields=['team', 'is_active']),
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['role_name']),
            models.Index(fields=['joined_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.team.name} ({self.role_name})"

    def get_role_permissions(self):
        """获取角色权限"""
        from ..constants import ROLE_PERMISSIONS
        return ROLE_PERMISSIONS.get(self.role_name, [])

    def has_permission(self, action):
        """检查是否具有特定权限"""
        return action in self.get_role_permissions()

    @property
    def is_owner(self):
        """是否是团队所有者"""
        return self.user == self.team.owner

    @property
    def is_admin(self):
        """是否是管理员"""
        return self.role_name in ['admin'] or self.is_owner

    @property
    def can_manage_members(self):
        """是否可以管理成员"""
        return 'manage_members' in self.get_role_permissions()