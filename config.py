"""
Multi-Tenant Auth 独立配置管理
"""

import os
import uuid
from pathlib import Path
from typing import Dict, Any, Optional
import psycopg2
from psycopg2.extensions import connection as PgConnection


class AuthConfig:
    """独立的认证库配置管理"""

    # 配置文件路径
    ENV_FILE = Path('.env')

    # 必需的环境变量
    REQUIRED_ENV_VARS = [
        'MULTI_TENANT_AUTH_DB_NAME',
        'MULTI_TENANT_AUTH_DB_USER',
        'MULTI_TENANT_AUTH_DB_PASSWORD',
        'MULTI_TENANT_AUTH_DB_HOST',
        'MULTI_TENANT_AUTH_DB_PORT',
        'MULTI_TENANT_AUTH_JWT_SECRET_KEY'
    ]

    # 可选环境变量及默认值
    OPTIONAL_ENV_VARS = {
        'MULTI_TENANT_AUTH_DB_SCHEMA': 'multi_tenant_auth',
        'MULTI_TENANT_AUTH_DB_SSLMODE': 'prefer',
        'MULTI_TENANT_AUTH_JWT_ACCESS_TOKEN_LIFETIME': 900,  # 15分钟
        'MULTI_TENANT_AUTH_JWT_REFRESH_TOKEN_LIFETIME': 604800,  # 7天
        'MULTI_TENANT_AUTH_INVITE_TOKEN_LIFETIME': 86400,  # 24小时
        'MULTI_TENANT_AUTH_CACHE_TIMEOUT': 300,  # 5分钟
        'MULTI_TENANT_AUTH_MAX_LOGIN_ATTEMPTS': 5,
        'MULTI_TENANT_AUTH_LOGIN_ATTEMPT_TIMEOUT': 900,  # 15分钟
    }

    _instance = None
    _config_cache = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._load_env()
            self._validate_config()
            self._initialized = True

    def _load_env(self):
        """加载.env文件"""
        if self.ENV_FILE.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv(self.ENV_FILE)
            except ImportError:
                # dotenv不是必需的，如果没有安装就跳过
                pass

    def _validate_config(self):
        """验证必需配置"""
        missing_vars = []

        for var in self.REQUIRED_ENV_VARS:
            if not os.getenv(var):
                missing_vars.append(var)

        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}\n"
                f"Please add these to your .env file"
            )

        # 验证JWT密钥长度
        jwt_key = self.get('MULTI_TENANT_AUTH_JWT_SECRET_KEY')
        if len(jwt_key) < 32:
            raise ValueError(
                "MULTI_TENANT_AUTH_JWT_SECRET_KEY must be at least 32 characters long"
            )

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        if key in self._config_cache:
            return self._config_cache[key]

        # 优先从环境变量获取
        env_value = os.getenv(key)
        if env_value is not None:
            # 类型转换
            if key.endswith('_LIFETIME') or key.endswith('_TIMEOUT') or key.endswith('_ATTEMPTS'):
                try:
                    self._config_cache[key] = int(env_value)
                except ValueError:
                    self._config_cache[key] = self.OPTIONAL_ENV_VARS.get(key, default)
            else:
                self._config_cache[key] = env_value
            return self._config_cache[key]

        # 使用默认值
        if key in self.OPTIONAL_ENV_VARS:
            default_value = self.OPTIONAL_ENV_VARS[key]
            if default_value is not None:
                self._config_cache[key] = default_value
            return default_value

        return default

    def validate_config(self):
        """验证配置，可在应用启动时调用"""
        # 检查数据库连接
        try:
            conn = self.get_database_connection()
            conn.close()
        except Exception as e:
            raise ValueError(f"Database connection failed: {str(e)}")

    @property
    def database_config(self) -> Dict[str, Any]:
        """数据库配置字典"""
        return {
            'dbname': self.get('MULTI_TENANT_AUTH_DB_NAME'),
            'user': self.get('MULTI_TENANT_AUTH_DB_USER'),
            'password': self.get('MULTI_TENANT_AUTH_DB_PASSWORD'),
            'host': self.get('MULTI_TENANT_AUTH_DB_HOST'),
            'port': self.get('MULTI_TENANT_AUTH_DB_PORT'),
            'sslmode': self.get('MULTI_TENANT_AUTH_DB_SSLMODE'),
            'options': f'-c search_path={self.get("MULTI_TENANT_AUTH_DB_SCHEMA")}',
        }

    def get_database_connection(self) -> PgConnection:
        """创建数据库连接"""
        return psycopg2.connect(**self.database_config)

    @property
    def jwt_settings(self) -> Dict[str, Any]:
        """JWT设置"""
        return {
            'access_token_lifetime': self.get('MULTI_TENANT_AUTH_JWT_ACCESS_TOKEN_LIFETIME'),
            'refresh_token_lifetime': self.get('MULTI_TENANT_AUTH_JWT_REFRESH_TOKEN_LIFETIME'),
            'secret_key': self.get('MULTI_TENANT_AUTH_JWT_SECRET_KEY'),
        }

    @property
    def security_settings(self) -> Dict[str, Any]:
        """安全设置"""
        return {
            'invite_token_lifetime': self.get('MULTI_TENANT_AUTH_INVITE_TOKEN_LIFETIME'),
            'max_login_attempts': self.get('MULTI_TENANT_AUTH_MAX_LOGIN_ATTEMPTS'),
            'login_attempt_timeout': self.get('MULTI_TENANT_AUTH_LOGIN_ATTEMPT_TIMEOUT'),
            'cache_timeout': self.get('MULTI_TENANT_AUTH_CACHE_TIMEOUT'),
        }


# 全局配置实例
auth_config = AuthConfig()