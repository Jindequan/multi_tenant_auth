"""
基础模型类
"""

import uuid
from django.db import models
from django.conf import settings


class BaseModel(models.Model):
    """基础模型类"""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    updated_at = models.DateTimeField(
        auto_now=True
    )

    class Meta:
        abstract = True
        ordering = ['-created_at']


class AuthBaseModel(BaseModel):
    """认证库基础模型类，指定schema"""

    class Meta:
        abstract = True
        db_table_prefix = '"multi_tenant_auth".'


def get_schema_table_name(table_name: str) -> str:
    """获取带schema的完整表名"""
    schema_name = settings.MULTI_TENANT_AUTH_DB_SCHEMA if hasattr(settings, 'MULTI_TENANT_AUTH_DB_SCHEMA') else 'multi_tenant_auth'
    return f'"{schema_name}"."{table_name}"'