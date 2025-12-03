"""
认证服务
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

import jwt
from django.utils import timezone
from django.conf import settings

from ..models import User, AuditLog
from ..config import auth_config
from ..constants import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    HttpStatus,
    ErrorCode,
    AUDIT_ACTIONS
)
from ..exceptions import (
    AuthenticationError,
    UserNotFoundError,
    UserInactiveError,
    InvalidCredentialsError,
    TokenExpiredError,
    TokenInvalidError,
    EmailAlreadyExistsError
)


logger = logging.getLogger(__name__)


class AuthService:
    """认证服务"""

    def __init__(self):
        self.jwt_settings = auth_config.jwt_settings

    def generate_tokens(self, user: User) -> Dict[str, str]:
        """
        生成访问令牌和刷新令牌

        Args:
            user: 用户对象

        Returns:
            Dict[str, str]: 包含access_token和refresh_token的字典
        """
        now = timezone.now()

        access_token_payload = {
            'user_id': str(user.id),
            'email': user.email,
            'token_type': TOKEN_TYPE_ACCESS,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(seconds=self.jwt_settings['access_token_lifetime'])).timestamp()),
        }

        refresh_token_payload = {
            'user_id': str(user.id),
            'token_type': TOKEN_TYPE_REFRESH,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(seconds=self.jwt_settings['refresh_token_lifetime'])).timestamp()),
        }

        access_token = jwt.encode(
            access_token_payload,
            self.jwt_settings['secret_key'],
            algorithm='HS256'
        )

        refresh_token = jwt.encode(
            refresh_token_payload,
            self.jwt_settings['secret_key'],
            algorithm='HS256'
        )

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_id': str(user.id),
            'email': user.email,
            'display_name': user.display_name,
            'avatar_url': user.avatar_url,
            'language': user.language
        }

    def verify_token(self, token: str) -> Dict[str, any]:
        """
        验证JWT令牌

        Args:
            token: JWT令牌

        Returns:
            Dict[str, any]: 解码后的payload

        Raises:
            TokenExpiredError: 令牌过期
            TokenInvalidError: 令牌无效
        """
        try:
            payload = jwt.decode(
                token,
                self.jwt_settings['secret_key'],
                algorithms=['HS256']
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError:
            raise TokenInvalidError("Invalid token")

    def authenticate_user(self, email: str, password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, any]:
        """
        用户认证

        Args:
            email: 邮箱
            password: 密码
            ip_address: IP地址
            user_agent: User Agent

        Returns:
            Dict[str, any]: 认证结果

        Raises:
            AuthenticationError: 认证失败
        """
        try:
            # 查找用户
            user = User.objects.get(email=email.lower())
        except User.DoesNotExist:
            # 记录失败的登录尝试
            AuditLog.log_action(
                user=None,
                action=AUDIT_ACTIONS['USER_LOGIN'],
                resource_type='user',
                metadata={'email': email, 'success': False, 'reason': 'user_not_found'},
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise InvalidCredentialsError("Invalid credentials")

        # 检查用户是否激活
        if not user.is_active:
            AuditLog.log_action(
                user=user,
                action=AUDIT_ACTIONS['USER_LOGIN'],
                resource_type='user',
                metadata={'success': False, 'reason': 'user_inactive'},
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise UserInactiveError("User account is inactive")

        # 验证密码
        if not user.check_password(password):
            AuditLog.log_action(
                user=user,
                action=AUDIT_ACTIONS['USER_LOGIN'],
                resource_type='user',
                metadata={'success': False, 'reason': 'invalid_password'},
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise InvalidCredentialsError("Invalid credentials")

        # 更新最后登录时间
        user.last_login_at = timezone.now()
        user.save(update_fields=['last_login_at'])

        # 记录成功的登录
        AuditLog.log_action(
            user=user,
            action=AUDIT_ACTIONS['USER_LOGIN'],
            resource_type='user',
            metadata={'success': True},
            ip_address=ip_address,
            user_agent=user_agent
        )

        # 生成tokens
        tokens = self.generate_tokens(user)

        return {
            'success': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'display_name': user.display_name,
                'avatar_url': user.avatar_url,
                'language': user.language,
                'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None
            },
            **tokens
        }

    def register_user(self, email: str, password: str, personal_info: Optional[Dict] = None, ip_address: str = None, user_agent: str = None) -> Dict[str, any]:
        """
        用户注册

        Args:
            email: 邮箱
            password: 密码
            personal_info: 个人信息
            ip_address: IP地址
            user_agent: User Agent

        Returns:
            Dict[str, any]: 注册结果

        Raises:
            EmailAlreadyExistsError: 邮箱已存在
        """
        # 检查邮箱是否已存在
        if User.objects.filter(email=email.lower()).exists():
            raise EmailAlreadyExistsError("Email already exists")

        # 创建用户
        user = User.objects.create(
            email=email.lower(),
            password=password,  # 会自动调用set_password
            personal_info=personal_info or {},
            settings={
                'email_notifications': True,
                'language': 'en'
            }
        )

        # 记录注册
        AuditLog.log_action(
            user=user,
            action=AUDIT_ACTIONS['USER_REGISTERED'],
            resource_type='user',
            metadata={'email': email},
            ip_address=ip_address,
            user_agent=user_agent
        )

        # 生成tokens
        tokens = self.generate_tokens(user)

        return {
            'success': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'display_name': user.display_name,
                'avatar_url': user.avatar_url,
                'language': user.language,
                'created_at': user.created_at.isoformat()
            },
            **tokens
        }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, any]:
        """
        刷新访问令牌

        Args:
            refresh_token: 刷新令牌

        Returns:
            Dict[str, any]: 新的tokens

        Raises:
            TokenExpiredError: 刷新令牌过期
            TokenInvalidError: 刷新令牌无效
        """
        # 验证刷新令牌
        try:
            payload = self.verify_token(refresh_token)
        except AuthenticationError:
            raise

        # 检查token类型
        if payload.get('token_type') != TOKEN_TYPE_REFRESH:
            raise TokenInvalidError("Invalid token type")

        # 获取用户
        try:
            user = User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            raise TokenInvalidError("User not found")

        # 检查用户状态
        if not user.is_active:
            raise UserInactiveError("User account is inactive")

        # 生成新的tokens
        new_tokens = self.generate_tokens(user)

        return {
            'success': True,
            'access_token': new_tokens['access_token'],
            'refresh_token': new_tokens['refresh_token'],
            'user_id': new_tokens['user_id']
        }

    def logout_user(self, user_id: str, ip_address: str = None, user_agent: str = None) -> bool:
        """
        用户登出

        Args:
            user_id: 用户ID
            ip_address: IP地址
            user_agent: User Agent

        Returns:
            bool: 是否成功登出
        """
        try:
            user = User.objects.get(id=user_id)

            # 记录登出
            AuditLog.log_action(
                user=user,
                action=AUDIT_ACTIONS['USER_LOGOUT'],
                resource_type='user',
                ip_address=ip_address,
                user_agent=user_agent
            )

            # TODO: 如果使用token黑名单，这里可以添加token到黑名单
            # 或者依赖客户端删除token

            return True

        except User.DoesNotExist:
            logger.error(f"Logout failed: User not found: {user_id}")
            return False

    def get_user_from_token(self, token: str) -> Optional[User]:
        """
        从token获取用户

        Args:
            token: JWT令牌

        Returns:
            Optional[User]: 用户对象或None
        """
        try:
            payload = self.verify_token(token)

            # 检查token类型
            if payload.get('token_type') != TOKEN_TYPE_ACCESS:
                return None

            # 获取用户
            try:
                return User.objects.get(id=payload['user_id'])
            except User.DoesNotExist:
                return None

        except AuthenticationError:
            return None

    @staticmethod
    def hash_password(password: str) -> str:
        """
        密码哈希

        Args:
            password: 明文密码

        Returns:
            str: 哈希后的密码
        """
        from django.contrib.auth.hashers import make_password
        return make_password(password)

    @staticmethod
    def verify_password_hash(password: str, hashed: str) -> bool:
        """
        验证密码哈希

        Args:
            password: 明文密码
            hashed: 哈希密码

        Returns:
            bool: 是否匹配
        """
        from django.contrib.auth.hashers import check_password
        return check_password(password, hashed)