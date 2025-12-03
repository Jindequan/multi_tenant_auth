"""
测试认证服务
"""

import json
import uuid
from datetime import datetime, timedelta
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.conf import settings
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.test import APIClient

from ..models import User, AuditLog
from ..services import AuthService
from ..exceptions import InvalidCredentials, UserNotActive, EmailAlreadyExists


class AuthServiceTest(TestCase):
    """测试认证服务"""

    def setUp(self):
        self.auth_service = AuthService()
        self.test_email = "test@example.com"
        self.test_password = "SecurePassword123!"
        self.test_name = "Test User"

    def test_register_user_success(self):
        """测试用户注册成功"""
        result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password,
            personal_info={"name": self.test_name},
            settings={"language": "en", "theme": "dark"}
        )

        self.assertTrue(result['success'])
        self.assertIsNotNone(result['user'])
        self.assertEqual(result['user']['email'], self.test_email)
        self.assertEqual(result['user']['personal_info']['name'], self.test_name)
        self.assertIsNotNone(result['access_token'])
        self.assertIsNotNone(result['refresh_token'])

        # 验证用户已创建
        user = User.objects.get(email=self.test_email)
        self.assertEqual(user.personal_info['name'], self.test_name)
        self.assertTrue(user.check_password(self.test_password))

        # 验证审计日志
        audit_log = AuditLog.objects.filter(user=user, action="register").first()
        self.assertIsNotNone(audit_log)

    def test_register_user_duplicate_email(self):
        """测试重复邮箱注册"""
        # 第一次注册
        self.auth_service.register_user(email=self.test_email, password=self.test_password)

        # 第二次注册相同邮箱
        with self.assertRaises(EmailAlreadyExists):
            self.auth_service.register_user(email=self.test_email, password=self.test_password)

    def test_register_user_invalid_email(self):
        """测试无效邮箱"""
        with self.assertRaises(ValidationError):
            self.auth_service.register_user(
                email="invalid-email",
                password=self.test_password
            )

    def test_register_user_weak_password(self):
        """测试弱密码"""
        with self.assertRaises(ValidationError):
            self.auth_service.register_user(
                email=self.test_email,
                password="123"  # 太短
            )

    def test_authenticate_user_success(self):
        """测试用户认证成功"""
        # 先注册用户
        self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password,
            personal_info={"name": self.test_name}
        )

        # 测试登录
        result = self.auth_service.authenticate_user(self.test_email, self.test_password)

        self.assertTrue(result['success'])
        self.assertIsNotNone(result['user'])
        self.assertEqual(result['user']['email'], self.test_email)
        self.assertIsNotNone(result['access_token'])
        self.assertIsNotNone(result['refresh_token'])

        # 验证审计日志
        user = User.objects.get(email=self.test_email)
        audit_log = AuditLog.objects.filter(user=user, action="login").first()
        self.assertIsNotNone(audit_log)

    def test_authenticate_user_wrong_password(self):
        """测试错误密码"""
        self.auth_service.register_user(email=self.test_email, password=self.test_password)

        with self.assertRaises(InvalidCredentials):
            self.auth_service.authenticate_user(self.test_email, "wrongpassword")

    def test_authenticate_user_not_exists(self):
        """测试用户不存在"""
        with self.assertRaises(InvalidCredentials):
            self.auth_service.authenticate_user("nonexistent@example.com", self.test_password)

    def test_authenticate_user_inactive(self):
        """测试非活跃用户"""
        user = User.objects.create_user(
            email=self.test_email,
            password=self.test_password,
            is_active=False
        )

        with self.assertRaises(UserNotActive):
            self.auth_service.authenticate_user(self.test_email, self.test_password)

    def test_refresh_token_success(self):
        """测试刷新令牌成功"""
        # 先注册获取refresh_token
        register_result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )
        refresh_token = register_result['refresh_token']

        # 刷新令牌
        result = self.auth_service.refresh_token(refresh_token)

        self.assertTrue(result['success'])
        self.assertIsNotNone(result['access_token'])
        self.assertIsNotNone(result['refresh_token'])
        self.assertNotEqual(result['access_token'], register_result['access_token'])

    def test_refresh_token_invalid(self):
        """测试无效刷新令牌"""
        with self.assertRaises(InvalidCredentials):
            self.auth_service.refresh_token("invalid-refresh-token")

    def test_logout_success(self):
        """测试登出成功"""
        # 先注册获取refresh_token
        register_result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )
        refresh_token = register_result['refresh_token']

        # 登出
        result = self.auth_service.logout(refresh_token)

        self.assertTrue(result['success'])

        # 尝试使用已登出的refresh_token
        with self.assertRaises(InvalidCredentials):
            self.auth_service.refresh_token(refresh_token)

    def test_change_password_success(self):
        """测试修改密码成功"""
        # 先注册
        self.auth_service.register_user(email=self.test_email, password=self.test_password)
        user = User.objects.get(email=self.test_email)

        new_password = "NewSecurePassword456!"
        result = self.auth_service.change_password(user.id, self.test_password, new_password)

        self.assertTrue(result['success'])

        # 验证新密码可以登录
        login_result = self.auth_service.authenticate_user(self.test_email, new_password)
        self.assertTrue(login_result['success'])

        # 验证旧密码不能登录
        with self.assertRaises(InvalidCredentials):
            self.auth_service.authenticate_user(self.test_email, self.test_password)

    def test_change_password_wrong_current(self):
        """测试修改密码时当前密码错误"""
        self.auth_service.register_user(email=self.test_email, password=self.test_password)
        user = User.objects.get(email=self.test_email)

        with self.assertRaises(InvalidCredentials):
            self.auth_service.change_password(
                user.id,
                "wrong-current-password",
                "new-password"
            )

    def test_user_profile_update(self):
        """测试用户资料更新"""
        self.auth_service.register_user(email=self.test_email, password=self.test_password)
        user = User.objects.get(email=self.test_email)

        new_info = {
            "name": "Updated Name",
            "bio": "Updated bio",
            "avatar_url": "https://example.com/new-avatar.jpg"
        }

        result = self.auth_service.update_user_profile(user.id, new_info)

        self.assertTrue(result['success'])
        self.assertEqual(result['user']['personal_info']['name'], "Updated Name")
        self.assertEqual(result['user']['personal_info']['bio'], "Updated bio")

        # 验证数据库已更新
        user.refresh_from_db()
        self.assertEqual(user.personal_info['name'], "Updated Name")
        self.assertEqual(user.personal_info['bio'], "Updated bio")

    def test_get_user_profile(self):
        """测试获取用户资料"""
        personal_info = {"name": self.test_name, "bio": "Test bio"}
        self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password,
            personal_info=personal_info
        )
        user = User.objects.get(email=self.test_email)

        profile = self.auth_service.get_user_profile(user.id)

        self.assertEqual(profile['email'], self.test_email)
        self.assertEqual(profile['personal_info']['name'], self.test_name)
        self.assertEqual(profile['personal_info']['bio'], "Test bio")
        self.assertIsNotNone(profile['created_at'])
        self.assertIsNotNone(profile['last_login'])


class AuthAPITest(APITestCase):
    """测试认证API"""

    def setUp(self):
        self.client = APIClient()
        self.auth_service = AuthService()
        self.test_email = "test@example.com"
        self.test_password = "SecurePassword123!"

    def test_register_api_success(self):
        """测试注册API成功"""
        url = reverse('auth-register')  # 假设有这个URL
        data = {
            'email': self.test_email,
            'password': self.test_password,
            'personal_info': {
                'name': 'Test User',
                'avatar_url': 'https://example.com/avatar.jpg'
            },
            'settings': {
                'language': 'en',
                'theme': 'dark'
            }
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['user']['email'], self.test_email)
        self.assertIsNotNone(response.data['access_token'])
        self.assertIsNotNone(response.data['refresh_token'])

    def test_register_api_validation_error(self):
        """测试注册API验证错误"""
        url = reverse('auth-register')
        data = {
            'email': 'invalid-email',  # 无效邮箱
            'password': '123'  # 弱密码
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_login_api_success(self):
        """测试登录API成功"""
        # 先注册
        self.auth_service.register_user(email=self.test_email, password=self.test_password)

        # 登录
        url = reverse('auth-login')
        data = {
            'email': self.test_email,
            'password': self.test_password
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIsNotNone(response.data['access_token'])
        self.assertIsNotNone(response.data['refresh_token'])

    def test_login_api_invalid_credentials(self):
        """测试登录API无效凭据"""
        url = reverse('auth-login')
        data = {
            'email': self.test_email,
            'password': 'wrongpassword'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])

    def test_refresh_token_api_success(self):
        """测试刷新令牌API成功"""
        # 先注册获取refresh_token
        register_result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )
        refresh_token = register_result['refresh_token']

        # 刷新令牌
        url = reverse('auth-refresh')
        data = {'refresh_token': refresh_token}

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIsNotNone(response.data['access_token'])
        self.assertIsNotNone(response.data['refresh_token'])

    def test_protected_api_without_token(self):
        """测试无令牌访问受保护API"""
        url = reverse('auth-profile')  # 需要认证的API

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_protected_api_with_valid_token(self):
        """测试有效令牌访问受保护API"""
        # 先注册获取token
        register_result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )
        access_token = register_result['access_token']

        # 设置认证头
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        # 访问受保护的API
        url = reverse('auth-profile')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.test_email)

    def test_logout_api_success(self):
        """测试登出API成功"""
        # 先注册获取refresh_token
        register_result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )
        refresh_token = register_result['refresh_token']

        # 登出
        url = reverse('auth-logout')
        data = {'refresh_token': refresh_token}

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证refresh_token已失效
        refresh_url = reverse('auth-refresh')
        refresh_response = self.client.post(refresh_url, {'refresh_token': refresh_token}, format='json')

        self.assertEqual(refresh_response.status_code, status.HTTP_401_UNAUTHORIZED)


class AuthSecurityTest(TransactionTestCase):
    """测试认证安全性"""

    def setUp(self):
        self.auth_service = AuthService()
        self.test_email = "test@example.com"
        self.test_password = "SecurePassword123!"

    def test_password_hashing(self):
        """测试密码哈希"""
        user = User.objects.create_user(email=self.test_email, password=self.test_password)

        # 密码不应该以明文存储
        self.assertNotEqual(user.password_hash, self.test_password)
        self.assertNotEqual(user.password_hash, self.test_password.encode())

        # 应该能够验证密码
        self.assertTrue(user.check_password(self.test_password))
        self.assertFalse(user.check_password("wrongpassword"))

    def test_jwt_token_structure(self):
        """测试JWT令牌结构"""
        result = self.auth_service.register_user(
            email=self.test_email,
            password=self.test_password
        )

        access_token = result['access_token']
        refresh_token = result['refresh_token']

        # JWT令牌应该是三个部分用点分隔
        self.assertEqual(len(access_token.split('.')), 3)
        self.assertEqual(len(refresh_token.split('.')), 3)

    def test_token_expiration(self):
        """测试令牌过期"""
        # 创建一个已过期的令牌（手动创建）
        from ..middleware import JWTMiddleware
        import jwt

        expired_payload = {
            'user_id': str(uuid.uuid4()),
            'exp': datetime.now() - timedelta(minutes=1),  # 1分钟前过期
            'type': 'access'
        }

        expired_token = jwt.encode(
            expired_payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )

        # 过期令牌应该无法通过验证
        middleware = JWTMiddleware()
        with self.assertRaises(Exception):  # 应该抛出jwt.ExpiredSignatureError
            middleware.validate_token(expired_token)

    def test_login_attempt_tracking(self):
        """测试登录尝试跟踪"""
        # 创建一个用户
        self.auth_service.register_user(email=self.test_email, password=self.test_password)
        user = User.objects.get(email=self.test_email)

        # 多次尝试错误登录
        for i in range(5):
            try:
                self.auth_service.authenticate_user(self.test_email, f"wrongpassword{i}")
            except InvalidCredentials:
                pass

        # 检查登录尝试是否被记录
        audit_logs = AuditLog.objects.filter(
            user=user,
            action="login_failed"
        ).count()

        self.assertEqual(audit_logs, 5)

    def test_concurrent_sessions(self):
        """测试并发会话"""
        result1 = self.auth_service.register_user(
            email=f"user1@{uuid.uuid4().hex[:8]}.com",
            password=self.test_password
        )
        result2 = self.auth_service.register_user(
            email=f"user2@{uuid.uuid4().hex[:8]}.com",
            password=self.test_password
        )

        # 两个用户的令牌应该不同
        self.assertNotEqual(result1['access_token'], result2['access_token'])
        self.assertNotEqual(result1['refresh_token'], result2['refresh_token'])

        # 同一个用户多次登录应该有不同的令牌
        user_email = f"user3@{uuid.uuid4().hex[:8]}.com"
        result3 = self.auth_service.register_user(email=user_email, password=self.test_password)
        result4 = self.auth_service.authenticate_user(user_email, self.test_password)

        self.assertNotEqual(result3['access_token'], result4['access_token'])