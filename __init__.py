"""
Multi-Tenant Auth Library

一个极简、高效的多租户认证权限管理库。

核心设计原则：
- 一个权限表解决所有问题: user_workspace_actions
- 一次查询检查权限: user_id + workspace_id
- 极简设计: 移除所有不必要的复杂度
- 高性能: 优先缓存和查询优化
"""

__version__ = "1.0.0"
__author__ = "Multi-Tenant Auth Team"
__description__ = "极简多租户认证权限管理库"

default_app_config = 'multi_tenant_auth.apps.MultiTenantAuthConfig'