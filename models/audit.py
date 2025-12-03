"""
审计日志模型
"""

import uuid
from django.db import models

from .base import AuthBaseModel


class AuditLog(AuthBaseModel):
    """审计日志模型"""

    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='audit_logs',
        help_text="操作用户"
    )
    action = models.CharField(
        max_length=100,
        db_index=True,
        help_text="操作类型"
    )
    resource_type = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="资源类型"
    )
    resource_id = models.UUIDField(
        null=True,
        blank=True,
        help_text="资源ID"
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP地址"
    )
    user_agent = models.TextField(
        null=True,
        blank=True,
        help_text="User Agent"
    )
    metadata = models.JSONField(
        default=dict,
        help_text="附加元数据"
    )

    class Meta:
        db_table = '"multi_tenant_auth"."audit_log"'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['action']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.created_at}"

    @classmethod
    def log_action(
        cls,
        user,
        action,
        resource_type=None,
        resource_id=None,
        ip_address=None,
        user_agent=None,
        metadata=None
    ):
        """记录操作日志"""
        from django.utils import timezone

        return cls.objects.create(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            created_at=timezone.now()
        )

    @classmethod
    def log_user_action(cls, user, action, request=None, **kwargs):
        """记录用户操作"""
        ip_address = None
        user_agent = None

        if request:
            ip_address = cls._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')

        return cls.log_action(
            user=user,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )

    @staticmethod
    def _get_client_ip(request):
        """获取客户端IP地址"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    @classmethod
    def get_user_logs(cls, user, limit=50, action=None):
        """获取用户操作日志"""
        queryset = cls.objects.filter(user=user)

        if action:
            queryset = queryset.filter(action=action)

        return queryset.order_by('-created_at')[:limit]

    @classmethod
    def get_resource_logs(cls, resource_type, resource_id, limit=50):
        """获取资源操作日志"""
        return cls.objects.filter(
            resource_type=resource_type,
            resource_id=resource_id
        ).order_by('-created_at')[:limit]