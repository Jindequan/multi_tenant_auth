"""
Multi-Tenant Auth Library - 极简配置
只需要配置数据库，其他都有默认值
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import os


class MultiTenantAuthSettings:
    """
    极简配置类 - 大部分配置都有智能默认值
    """

    DEFAULTS = {
        # 数据库配置 - 这是唯一必需的配置
        'DB_NAME': getattr(settings, 'DATABASES', {}).get('default', {}).get('NAME', ''),
        'DB_USER': getattr(settings, 'DATABASES', {}).get('default', {}).get('USER', ''),
        'DB_PASSWORD': getattr(settings, 'DATABASES', {}).get('default', {}).get('PASSWORD', ''),
        'DB_HOST': getattr(settings, 'DATABASES', {}).get('default', {}).get('HOST', 'localhost'),
        'DB_PORT': getattr(settings, 'DATABASES', {}).get('default', {}).get('PORT', '5432'),

        # 多租户配置 - 都有默认值
        'DB_SCHEMA': 'multi_tenant_auth',  # 独立schema，不污染主数据库
        'JWT_SECRET_KEY': getattr(settings, 'SECRET_KEY', ''),  # 默认使用Django的SECRET_KEY
        'JWT_ALGORITHM': 'HS256',
        'JWT_ACCESS_TOKEN_LIFETIME': 60 * 15,  # 15分钟
        'JWT_REFRESH_TOKEN_LIFETIME': 60 * 60 * 24 * 7,  # 7天

        # 缓存配置 - 智能默认值
        'CACHE_TIMEOUT': 300,  # 5分钟
        'CACHE_PREFIX': 'multi_tenant_auth',
        'MAX_LOGIN_ATTEMPTS': 5,
        'LOGIN_ATTEMPT_TIMEOUT': 900,  # 15分钟

        # 功能开关 - 默认开启
        'ENABLE_REGISTRATION': True,
        'ENABLE_EMAIL_VERIFICATION': False,  # 默认关闭，减少复杂度
        'ENABLE_PASSWORD_RESET': True,
        'ENABLE_AUDIT_LOG': True,
        'ENABLE_WORKSPACE_CREATION': True,
        'ENABLE_TEAM_MANAGEMENT': True,

        # 权限配置 - 预定义角色
        'DEFAULT_ROLES': {
            'owner': ['view', 'edit', 'delete', 'share', 'manage', 'admin'],
            'admin': ['view', 'edit', 'delete', 'share', 'manage'],
            'editor': ['view', 'edit', 'share'],
            'viewer': ['view'],
        },

        # API配置
        'API_VERSION': 'v1',
        'API_PREFIX': 'api/auth',
        'ENABLE_DOCS': True,  # 自动生成API文档
        'ENABLE_CORS': True,

        # 安全配置
        'PASSWORD_MIN_LENGTH': 8,
        'PASSWORD_REQUIRE_UPPERCASE': False,  # 默认关闭，减少复杂度
        'PASSWORD_REQUIRE_LOWERCASE': False,
        'PASSWORD_REQUIRE_NUMBERS': False,
        'PASSWORD_REQUIRE_SYMBOLS': False,

        # 限制配置
        'MAX_WORKSPACES_PER_USER': 100,
        'MAX_TEAMS_PER_WORKSPACE': 50,
        'MAX_MEMBERS_PER_TEAM': 1000,
        'MAX_PERMISSIONS_PER_USER': 1000,
    }

    def __init__(self):
        self.settings = getattr(settings, 'MULTI_TENANT_AUTH', {})
        self._validate_settings()

    def _validate_settings(self):
        """只验证必需的配置"""
        # 检查数据库配置
        if not self.DB_NAME:
            raise ImproperlyConfigured(
                "MULTI_TENANT_AUTH.DB_NAME is required. "
                "Configure it in settings.py or use DATABASES['default']['NAME']"
            )

        # 检查JWT密钥
        if not self.JWT_SECRET_KEY:
            raise ImproperlyConfigured(
                "JWT_SECRET_KEY is required. "
                "Configure MULTI_TENANT_AUTH.JWT_SECRET_KEY or set SECRET_KEY in settings.py"
            )

    def __getattr__(self, name):
        """智能配置获取"""
        # 1. 先检查用户是否显式配置
        if name in self.settings:
            return self.settings[name]

        # 2. 检查是否有默认值
        if name in self.DEFAULTS:
            default_value = self.DEFAULTS[name]

            # 特殊处理数据库配置，自动从Django的DATABASES获取
            if name.startswith('DB_') and not default_value:
                django_db_key = name[3:].lower()  # 去掉DB_前缀
                if hasattr(self, '_get_django_db_config'):
                    return self._get_django_db_config(django_db_key)

            return default_value

        # 3. 检查环境变量（可选，向后兼容）
        env_key = f'MULTI_TENANT_AUTH_{name}'
        env_value = os.getenv(env_key)
        if env_value is not None:
            return env_value

        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def _get_django_db_config(self, key):
        """从Django的DATABASES配置获取数据库信息"""
        db_config = getattr(settings, 'DATABASES', {}).get('default', {})
        return db_config.get(key, '')

    def get_database_url(self):
        """生成数据库连接URL"""
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    def get_cache_key(self, user_id, workspace_id=None):
        """生成缓存键"""
        if workspace_id:
            return f"{self.CACHE_PREFIX}:perm:{user_id}:{workspace_id}"
        return f"{self.CACHE_PREFIX}:user:{user_id}"

    def is_production(self):
        """检查是否为生产环境"""
        return getattr(settings, 'DEBUG', False) is False


# 全局配置实例
auth_settings = MultiTenantAuthSettings()


# 便捷函数
def get_auth_setting(name, default=None):
    """便捷函数：获取配置项"""
    try:
        return getattr(auth_settings, name)
    except AttributeError:
        return default


def is_feature_enabled(feature_name):
    """便捷函数：检查功能是否开启"""
    setting_name = f'ENABLE_{feature_name.upper()}'
    return get_auth_setting(setting_name, False)


def get_default_permissions(role):
    """便捷函数：获取角色的默认权限"""
    return auth_settings.DEFAULT_ROLES.get(role, [])


def get_cache_timeout():
    """便捷函数：获取缓存超时时间"""
    return auth_settings.CACHE_TIMEOUT