"""
Multi-Tenant Auth 常量定义

所有枚举值在代码层面约束，不在数据库层面约束
"""

from typing import List, Dict, Any

# 角色权限定义 (代码层面，不存储在数据库)
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    'owner': [
        'view', 'edit', 'delete', 'share',
        'manage_members', 'manage_settings'
    ],
    'admin': [
        'view', 'edit', 'delete', 'share',
        'manage_members'
    ],
    'editor': [
        'view', 'edit', 'share', 'comment'
    ],
    'viewer': [
        'view'
    ],
    'commenter': [
        'view', 'comment'
    ]
}

# 所有可用的权限类型
AVAILABLE_PERMISSIONS: List[str] = [
    'view', 'edit', 'delete', 'share',
    'comment', 'manage_members', 'manage_settings'
]

# 工作空间类型
WORKSPACE_TYPES = {
    'PERSONAL': 'personal',
    'TEAM': 'team'
}

# 工作空间可见性
VISIBILITY_LEVELS = {
    'PRIVATE': 'private',
    'TEAM': 'team',
    'PUBLIC': 'public'
}

# 团队成员角色
TEAM_MEMBER_ROLES = [
    'admin', 'editor', 'viewer', 'commenter'
]

# 缓存键前缀
CACHE_KEY_PREFIX = 'multi_tenant_auth'

# 权限缓存键格式
PERMISSION_CACHE_KEY_FORMAT = f'{CACHE_KEY_PREFIX}:perm:{{user_id}}:{{workspace_id}}'

# JWT Token 类型
TOKEN_TYPE_ACCESS = 'access'
TOKEN_TYPE_REFRESH = 'refresh'

# 默认设置
DEFAULT_CACHE_TIMEOUT = 300  # 5分钟
DEFAULT_INVITE_TOKEN_LIFETIME = 86400  # 24小时
DEFAULT_MAX_LOGIN_ATTEMPTS = 5
DEFAULT_LOGIN_ATTEMPT_TIMEOUT = 900  # 15分钟

# 审计动作类型
AUDIT_ACTIONS = {
    'USER_REGISTERED': 'user_registered',
    'USER_LOGIN': 'user_login',
    'USER_LOGOUT': 'user_logout',
    'TEAM_CREATED': 'team_created',
    'TEAM_MEMBER_ADDED': 'team_member_added',
    'TEAM_MEMBER_REMOVED': 'team_member_removed',
    'WORKSPACE_CREATED': 'workspace_created',
    'WORKSPACE_SHARED': 'workspace_shared',
    'PERMISSION_GRANTED': 'permission_granted',
    'PERMISSION_REVOKED': 'permission_revoked',
}

# HTTP 状态码
class HttpStatus:
    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    INTERNAL_SERVER_ERROR = 500

# 错误代码
class ErrorCode:
    # 认证错误
    INVALID_CREDENTIALS = 'invalid_credentials'
    TOKEN_EXPIRED = 'token_expired'
    TOKEN_INVALID = 'token_invalid'
    USER_NOT_FOUND = 'user_not_found'
    USER_INACTIVE = 'user_inactive'

    # 权限错误
    PERMISSION_DENIED = 'permission_denied'
    WORKSPACE_NOT_FOUND = 'workspace_not_found'
    TEAM_NOT_FOUND = 'team_not_found'

    # 验证错误
    VALIDATION_ERROR = 'validation_error'
    EMAIL_ALREADY_EXISTS = 'email_already_exists'
    INVITE_TOKEN_INVALID = 'invite_token_invalid'
    INVITE_TOKEN_EXPIRED = 'invite_token_expired'

    # 速率限制错误
    RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded'
    LOGIN_ATTEMPTS_EXCEEDED = 'login_attempts_exceeded'