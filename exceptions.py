"""
Multi-Tenant Auth 自定义异常
"""

from typing import Optional


class MultiTenantAuthError(Exception):
    """Multi-Tenant Auth 基础异常"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthenticationError(MultiTenantAuthError):
    """认证错误基类"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """无效凭据错误"""
    pass


class TokenExpiredError(AuthenticationError):
    """Token过期错误"""
    pass


class TokenInvalidError(AuthenticationError):
    """Token无效错误"""
    pass


class UserNotFoundError(AuthenticationError):
    """用户不存在错误"""
    pass


class UserInactiveError(AuthenticationError):
    """用户未激活错误"""
    pass


class EmailAlreadyExistsError(MultiTenantAuthError):
    """邮箱已存在错误"""
    pass


class PermissionError(MultiTenantAuthError):
    """权限错误基类"""
    pass


class PermissionDenied(PermissionError):
    """权限被拒绝错误"""
    pass


class WorkspaceNotFoundError(PermissionError):
    """工作空间不存在错误"""
    pass


class TeamNotFoundError(PermissionError):
    """团队不存在错误"""
    pass


class ValidationError(MultiTenantAuthError):
    """验证错误"""
    pass


class ConfigurationError(MultiTenantAuthError):
    """配置错误"""
    pass


class DatabaseError(MultiTenantAuthError):
    """数据库错误"""
    pass


class RateLimitError(MultiTenantAuthError):
    """频率限制错误"""
    pass