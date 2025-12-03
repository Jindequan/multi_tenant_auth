"""
工作空间相关模型
"""

import uuid
from django.db import models
from django.conf import settings

from .base import AuthBaseModel
from ..constants import WORKSPACE_TYPES, VISIBILITY_LEVELS


class Workspace(AuthBaseModel):
    """工作空间模型"""

    name = models.CharField(
        max_length=255,
        help_text="工作空间名称"
    )
    slug = models.SlugField(
        max_length=255,
        help_text="工作空间slug，用于URL"
    )
    description = models.TextField(
        blank=True,
        help_text="工作空间描述"
    )
    workspace_type = models.CharField(
        max_length=20,
        choices=[(v, k) for k, v in WORKSPACE_TYPES.items()],
        default=WORKSPACE_TYPES['TEAM'],
        help_text="工作空间类型: personal | team"
    )
    owner = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='owned_workspaces',
        help_text="工作空间所有者"
    )
    team = models.ForeignKey(
        Team,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='workspaces',
        help_text="所属团队 (仅团队工作空间)"
    )
    visibility = models.CharField(
        max_length=20,
        choices=[(v, k) for k, v in VISIBILITY_LEVELS.items()],
        default=VISIBILITY_LEVELS['PRIVATE'],
        help_text="可见性: private | team | public"
    )
    settings = models.JSONField(
        default=dict,
        help_text="工作空间设置"
    )

    class Meta:
        db_table = '"multi_tenant_auth"."workspace"'
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['owner']),
            models.Index(fields=['team']),
            models.Index(fields=['workspace_type']),
            models.Index(fields=['visibility']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name} ({self.workspace_type})"

    @property
    def is_personal(self):
        """是否是个人工作空间"""
        return self.workspace_type == WORKSPACE_TYPES['PERSONAL']

    @property
    def is_team(self):
        """是否是团队工作空间"""
        return self.workspace_type == WORKSPACE_TYPES['TEAM']

    @property
    def can_be_shared(self):
        """是否可以分享"""
        return self.visibility in [
            VISIBILITY_LEVELS['TEAM'],
            VISIBILITY_LEVELS['PUBLIC']
        ]

    def get_member_count(self):
        """获取工作空间成员数量"""
        return self.permissions.count()


class UserWorkspaceActions(AuthBaseModel):
    """用户工作空间权限表 - 核心权限表！"""

    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='workspace_permissions',
        help_text="用户"
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name='permissions',
        help_text="工作空间"
    )
    actions = models.JSONField(
        default=list,
        help_text="用户在工作空间的权限列表 ['view', 'edit', 'share', 'delete']"
    )
    granted_by = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='granted_permissions',
        help_text="授权人"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="权限过期时间 (临时权限)"
    )

    class Meta:
        db_table = '"multi_tenant_auth"."user_workspace_actions"'
        unique_together = ['user', 'workspace']
        indexes = [
            models.Index(fields=['user', 'workspace']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['granted_by']),
        ]

    def __str__(self):
        actions_str = ', '.join(self.actions) if self.actions else 'No permissions'
        return f"{self.user.email} - {self.workspace.name} ({actions_str})"

    def has_permission(self, action):
        """检查是否具有特定权限"""
        if not self.actions:
            return False
        return action in self.actions

    def add_permission(self, action):
        """添加权限"""
        if not self.actions:
            self.actions = []
        if action not in self.actions:
            self.actions.append(action)
            self.save(update_fields=['actions'])

    def remove_permission(self, action):
        """移除权限"""
        if self.actions and action in self.actions:
            self.actions.remove(action)
            self.save(update_fields=['actions'])

    def set_permissions(self, actions):
        """设置权限列表"""
        if isinstance(actions, str):
            actions = [actions]
        self.actions = list(set(actions))  # 去重
        self.save(update_fields=['actions'])

    @property
    def is_expired(self):
        """权限是否过期"""
        if self.expires_at is None:
            return False
        from django.utils import timezone
        return timezone.now() > self.expires_at

    @property
    def effective_actions(self):
        """有效权限列表"""
        if self.is_expired:
            return []
        return self.actions or []

    def clear_permissions(self):
        """清除所有权限"""
        self.actions = []
        self.save(update_fields=['actions'])