"""
完整的认证场景测试 - 涵盖各种成功和失败的认证情况
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_jwt.settings import api_settings

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import AuthenticationError, PermissionDenied
from ..views import LoginView, RegisterView, LogoutView, RefreshTokenView, ChangePasswordView
from ..decorators import require_auth, require_permissions

User = get_user_model()


class BasicAuthenticationTest(APITestCase):
    """基础认证测试"""

    def setUp(self):
        self.auth_service = AuthService()
        self.test_user_data = {
            "email": "test@example.com",
            "password": "SecurePassword123!",
            "personal_info": {"name": "Test User"}
        }
        self.user = User.objects.create_user(**self.test_user_data)

    def test_successful_registration(self):
        """测试成功注册"""
        registration_data = {
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "personal_info": {"name": "New User"}
        }

        response = self.client.post('/api/auth/register/', registration_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['user']['email'], "newuser@example.com")
        self.assertIsNotNone(response.data.get('access_token'))
        self.assertIsNotNone(response.data.get('refresh_token'))

        # 验证用户已创建
        new_user = User.objects.get(email="newuser@example.com")
        self.assertEqual(new_user.personal_info["name"], "New User")
        self.assertTrue(new_user.is_active)

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=new_user,
            action="register"
        ).first()
        self.assertIsNotNone(audit_log)
        self.assertEqual(audit_log.resource_type, "auth")

    def test_registration_validation_errors(self):
        """测试注册验证错误"""
        # 无效邮箱
        response = self.client.post('/api/auth/register/', {
            "email": "invalid-email",
            "password": "Password123!"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

        # 弱密码
        response = self.client.post('/api/auth/register/', {
            "email": "weak@example.com",
            "password": "123"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

        # 重复邮箱
        response = self.client.post('/api/auth/register/', self.test_user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

        # 缺少必填字段
        response = self.client.post('/api/auth/register/', {
            "password": "Password123!"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_successful_login(self):
        """测试成功登录"""
        login_data = {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        }

        response = self.client.post('/api/auth/login/', login_data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['user']['email'], self.test_user_data["email"])
        self.assertIsNotNone(response.data.get('access_token'))
        self.assertIsNotNone(response.data.get('refresh_token'))

        # 验证用户最后登录时间已更新
        updated_user = User.objects.get(id=self.user.id)
        self.assertIsNotNone(updated_user.last_login_at)

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action="login"
        ).first()
        self.assertIsNotNone(audit_log)
        self.assertTrue(audit_log.details.get('success'))

    def test_login_authentication_failures(self):
        """测试登录认证失败"""
        # 错误密码
        response = self.client.post('/api/auth/login/', {
            "email": self.test_user_data["email"],
            "password": "WrongPassword123!"
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])
        self.assertIn('error', response.data)

        # 不存在的用户
        response = self.client.post('/api/auth/login/', {
            "email": "nonexistent@example.com",
            "password": "Password123!"
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 空字段
        response = self.client.post('/api/auth/login/', {
            "email": "",
            "password": "Password123!"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 不活跃用户
        self.user.is_active = False
        self.user.save()

        response = self.client.post('/api/auth/login/', {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout(self):
        """测试登出"""
        # 先登录获取token
        login_response = self.client.post('/api/auth/login/', {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        })
        access_token = login_response.data['access_token']

        # 使用token登出
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.post('/api/auth/logout/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action="logout"
        ).first()
        self.assertIsNotNone(audit_log)

    def test_logout_without_auth(self):
        """测试未认证的登出请求"""
        response = self.client.post('/api/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class JWTTokenTest(APITestCase):
    """JWT Token处理测试"""

    def setUp(self):
        self.test_user_data = {
            "email": "jwt@example.com",
            "password": "JWTPassword123!"
        }
        self.user = User.objects.create_user(**self.test_user_data)

    def test_token_generation(self):
        """测试Token生成"""
        # 使用AuthService生成token
        auth_service = AuthService()
        tokens = auth_service.generate_tokens(self.user)

        self.assertIsNotNone(tokens.get('access_token'))
        self.assertIsNotNone(tokens.get('refresh_token'))
        self.assertIsInstance(tokens.get('expires_in'), int)
        self.assertGreater(tokens.get('expires_in'), 0)

    def test_token_validation(self):
        """测试Token验证"""
        auth_service = AuthService()
        tokens = auth_service.generate_tokens(self.user)

        # 验证有效的access token
        validated_user = auth_service.validate_access_token(tokens['access_token'])
        self.assertEqual(validated_user.id, self.user.id)

        # 验证有效的refresh token
        new_tokens = auth_service.refresh_access_token(tokens['refresh_token'])
        self.assertIsNotNone(new_tokens.get('access_token'))

    def test_token_refresh(self):
        """测试Token刷新"""
        # 登录获取初始token
        login_response = self.client.post('/api/auth/login/', {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        })
        initial_access_token = login_response.data['access_token']
        refresh_token = login_response.data['refresh_token']

        # 使用refresh token获取新的access token
        response = self.client.post('/api/auth/refresh/', {
            "refresh": refresh_token
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        new_access_token = response.data['access_token']
        self.assertNotEqual(initial_access_token, new_access_token)

        # 验证新token有效
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_token_expiry(self):
        """测试Token过期"""
        # 创建已过期的token
        with patch('rest_framework_jwt.utils.utcnow') as mock_now:
            # 模拟过期时间
            mock_now.return_value = timezone.now() - timedelta(days=1)

            auth_service = AuthService()
            expired_token = auth_service.generate_tokens(self.user)['access_token']

        # 尝试使用过期token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_token}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_invalid_token(self):
        """测试无效Token"""
        # 使用伪造的token
        invalid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature"
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {invalid_token}')

        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_token_blacklist(self):
        """测试Token黑名单"""
        # 登录获取token
        login_response = self.client.post('/api/auth/login/', {
            "email": self.test_user_data["email"],
            "password": self.test_user_data["password"]
        })
        access_token = login_response.data['access_token']

        # 登出（token应被加入黑名单）
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.client.post('/api/auth/logout/')

        # 尝试再次使用已登出的token
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_concurrent_token_usage(self):
        """测试并发Token使用"""
        # 从多个设备登录
        tokens = []
        for i in range(3):
            login_response = self.client.post('/api/auth/login/', {
                "email": self.test_user_data["email"],
                "password": self.test_user_data["password"]
            })
            tokens.append(login_response.data['access_token'])

        # 所有token都应该有效
        for token in tokens:
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
            response = self.client.get('/api/auth/profile/')
            self.assertEqual(response.status_code, status.HTTP_200_OK)


class TwoFactorAuthenticationTest(APITestCase):
    """双因素认证测试"""

    def setUp(self):
        self.user_data = {
            "email": "2fa@example.com",
            "password": "TwoFactorPassword123!"
        }
        self.user = User.objects.create_user(**self.user_data)

    @patch('multi_tenant_auth.services.auth_service.generate_totp_secret')
    @patch('multi_tenant_auth.services.auth_service.generate_qr_code')
    def test_enable_2fa(self, mock_qr, mock_secret):
        """测试启用双因素认证"""
        mock_secret.return_value = "JBSWY3DPEHPK3PXP"
        mock_qr.return_value = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."

        # 启用2FA
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')
        response = self.client.post('/api/auth/enable-2fa/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIsNotNone(response.data.get('secret'))
        self.assertIsNotNone(response.data.get('qr_code'))

        # 验证用户已启用2FA（但未验证）
        updated_user = User.objects.get(id=self.user.id)
        self.assertTrue(updated_user.personal_info.get('two_factor_enabled'))
        self.assertIsNotNone(updated_user.personal_info.get('two_factor_secret'))

    @patch('multi_tenant_auth.services.auth_service.verify_totp_token')
    def test_verify_2fa(self, mock_verify):
        """测试验证双因素认证"""
        # 先启用2FA
        self._enable_2fa_for_user()

        # 验证TOTP token
        mock_verify.return_value = True
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')

        response = self.client.post('/api/auth/verify-2fa/', {
            "token": "123456"
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证用户2FA已验证
        updated_user = User.objects.get(id=self.user.id)
        self.assertTrue(updated_user.personal_info.get('two_factor_verified'))

    def test_verify_2fa_invalid_token(self):
        """测试验证无效的2FA token"""
        # 先启用2FA
        self._enable_2fa_for_user()

        # 尝试验证无效token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')

        with patch('multi_tenant_auth.services.auth_service.verify_totp_token', return_value=False):
            response = self.client.post('/api/auth/verify-2fa/', {
                "token": "000000"
            })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_disable_2fa(self):
        """测试禁用双因素认证"""
        # 先启用并验证2FA
        self._enable_and_verify_2fa()

        # 禁用2FA
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')
        response = self.client.post('/api/auth/disable-2fa/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证用户2FA已禁用
        updated_user = User.objects.get(id=self.user.id)
        self.assertFalse(updated_user.personal_info.get('two_factor_enabled'))
        self.assertFalse(updated_user.personal_info.get('two_factor_verified'))

    def test_login_with_2fa_required(self):
        """测试需要2FA的登录"""
        # 启用2FA
        self._enable_and_verify_2fa()

        # 登录应该要求2FA验证
        response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get('authenticated'))
        self.assertTrue(response.data.get('requires_2fa'))
        self.assertIsNotNone(response.data.get('temp_token'))

        # 使用临时token验证2FA
        with patch('multi_tenant_auth.services.auth_service.verify_totp_token', return_value=True):
            response = self.client.post('/api/auth/verify-2fa/', {
                "token": "123456",
                "temp_token": response.data['temp_token']
            })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get('authenticated'))
        self.assertIsNotNone(response.data.get('access_token'))

    def _get_access_token(self):
        """获取访问token"""
        login_response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })
        return login_response.data['access_token']

    def _enable_2fa_for_user(self):
        """为用户启用2FA"""
        with patch('multi_tenant_auth.services.auth_service.generate_totp_secret') as mock_secret:
            mock_secret.return_value = "JBSWY3DPEHPK3PXP"
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')
            self.client.post('/api/auth/enable-2fa/')

    def _enable_and_verify_2fa(self):
        """启用并验证2FA"""
        self._enable_2fa_for_user()

        with patch('multi_tenant_auth.services.auth_service.verify_totp_token', return_value=True):
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self._get_access_token()}')
            self.client.post('/api/auth/verify-2fa/', {"token": "123456"})


class PasswordManagementTest(APITestCase):
    """密码管理测试"""

    def setUp(self):
        self.user_data = {
            "email": "password@example.com",
            "password": "OriginalPassword123!"
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_change_password_success(self):
        """测试成功修改密码"""
        access_token = self._get_access_token()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.post('/api/auth/change-password/', {
            "old_password": self.user_data["password"],
            "new_password": "NewSecurePassword456!"
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证密码已更新
        updated_user = User.objects.get(id=self.user.id)
        self.assertTrue(updated_user.check_password("NewSecurePassword456!"))
        self.assertFalse(updated_user.check_password(self.user_data["password"]))

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action="change_password"
        ).first()
        self.assertIsNotNone(audit_log)

    def test_change_password_wrong_old_password(self):
        """测试修改密码时旧密码错误"""
        access_token = self._get_access_token()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.post('/api/auth/change-password/', {
            "old_password": "WrongPassword123!",
            "new_password": "NewSecurePassword456!"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

        # 验证密码未更改
        updated_user = User.objects.get(id=self.user.id)
        self.assertTrue(updated_user.check_password(self.user_data["password"]))

    def test_change_password_weak_new_password(self):
        """测试修改密码时新密码过弱"""
        access_token = self._get_access_token()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.post('/api/auth/change-password/', {
            "old_password": self.user_data["password"],
            "new_password": "123"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_change_password_without_auth(self):
        """测试未认证时修改密码"""
        response = self.client.post('/api/auth/change-password/', {
            "old_password": self.user_data["password"],
            "new_password": "NewSecurePassword456!"
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('multi_tenant_auth.services.auth_service.send_password_reset_email')
    def test_forgot_password(self, mock_send_email):
        """测试忘记密码"""
        response = self.client.post('/api/auth/forgot-password/', {
            "email": self.user_data["email"]
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertTrue(mock_send_email.called)

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action="forgot_password"
        ).first()
        self.assertIsNotNone(audit_log)

    def test_forgot_password_nonexistent_email(self):
        """测试忘记密码时邮箱不存在"""
        response = self.client.post('/api/auth/forgot-password/', {
            "email": "nonexistent@example.com"
        })

        # 为安全考虑，应该返回成功响应
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

    def test_reset_password(self):
        """测试重置密码"""
        # 生成重置token
        auth_service = AuthService()
        reset_token = auth_service.generate_password_reset_token(self.user)

        response = self.client.post('/api/auth/reset-password/', {
            "token": reset_token,
            "new_password": "ResetPassword123!"
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证密码已重置
        updated_user = User.objects.get(id=self.user.id)
        self.assertTrue(updated_user.check_password("ResetPassword123!"))

        # 验证审计日志
        audit_log = AuditLog.objects.filter(
            user=self.user,
            action="reset_password"
        ).first()
        self.assertIsNotNone(audit_log)

    def test_reset_password_invalid_token(self):
        """测试重置密码时token无效"""
        response = self.client.post('/api/auth/reset-password/', {
            "token": "invalid_token",
            "new_password": "ResetPassword123!"
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def _get_access_token(self):
        """获取访问token"""
        login_response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })
        return login_response.data['access_token']


class AccountSecurityTest(APITestCase):
    """账户安全测试"""

    def setUp(self):
        self.user_data = {
            "email": "security@example.com",
            "password": "SecurePassword123!"
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_account_lockout_after_failed_attempts(self):
        """测试多次失败登录后账户锁定"""
        # 尝试多次错误登录
        for i in range(5):  # 假设5次失败后锁定
            response = self.client.post('/api/auth/login/', {
                "email": self.user_data["email"],
                "password": f"WrongPassword{i}!"
            })
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 第6次尝试应该被锁定
        response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]  # 正确密码
        })

        # 根据实现，可能是401或403
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_concurrent_login_attempts(self):
        """测试并发登录尝试"""
        # 模拟从多个IP同时登录
        login_attempts = []
        for i in range(3):
            response = self.client.post('/api/auth/login/', {
                "email": self.user_data["email"],
                "password": self.user_data["password"]
            })
            login_attempts.append(response)

        # 所有尝试都应该成功
        for response in login_attempts:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])

    def test_session_management(self):
        """测试会话管理"""
        # 登录获取token
        login_response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })
        access_token = login_response.data['access_token']

        # 使用token访问受保护资源
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 登出
        self.client.post('/api/auth/logout/')

        # token应该失效
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_ip_based_security(self):
        """测试基于IP的安全"""
        # 登录
        login_response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })
        access_token = login_response.data['access_token']

        # 模拟从新IP访问（在实际应用中可能需要额外配置）
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.client.defaults['REMOTE_ADDR'] = '192.168.1.100'

        response = self.client.get('/api/auth/profile/')

        # 根据安全策略，可能需要额外验证
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN])

    def test_user_agent_security(self):
        """测试基于User-Agent的安全"""
        # 登录
        login_response = self.client.post('/api/auth/login/', {
            "email": self.user_data["email"],
            "password": self.user_data["password"]
        })
        access_token = login_response.data['access_token']

        # 模拟可疑User-Agent
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.client.defaults['HTTP_USER_AGENT'] = 'Bot/1.0'

        response = self.client.get('/api/auth/profile/')

        # 根据安全策略，可能需要额外验证
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN])


class AuthenticationPerformanceTest(TransactionTestCase):
    """认证性能测试"""

    def setUp(self):
        # 创建大量用户用于性能测试
        self.users = []
        for i in range(100):
            user = User.objects.create_user(
                email=f"perf{i}@example.com",
                password="Password123!"
            )
            self.users.append(user)

    def test_login_performance(self):
        """测试登录性能"""
        import time

        start_time = time.time()

        # 执行多次登录
        for i in range(10):
            response = self.client.post('/api/auth/login/', {
                "email": f"perf{i}@example.com",
                "password": "Password123!"
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        end_time = time.time()
        total_time = end_time - start_time

        # 平均每次登录应该在合理时间内（例如 < 500ms）
        avg_time = total_time / 10
        self.assertLess(avg_time, 0.5, f"平均登录时间过长: {avg_time:.3f}s")

    def test_token_validation_performance(self):
        """测试Token验证性能"""
        import time

        # 先获取token
        login_response = self.client.post('/api/auth/login/', {
            "email": "perf0@example.com",
            "password": "Password123!"
        })
        token = login_response.data['access_token']

        # 测试token验证性能
        start_time = time.time()

        for i in range(100):
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
            response = self.client.get('/api/auth/profile/')
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        end_time = time.time()
        total_time = end_time - start_time

        # 平均每次验证应该很快（例如 < 100ms）
        avg_time = total_time / 100
        self.assertLess(avg_time, 0.1, f"平均Token验证时间过长: {avg_time:.3f}s")

    def test_concurrent_authentication(self):
        """测试并发认证"""
        import threading
        import time

        results = []
        errors = []

        def login_user(user_index):
            try:
                response = self.client.post('/api/auth/login/', {
                    "email": f"perf{user_index}@example.com",
                    "password": "Password123!"
                })
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # 创建多个线程同时登录
        threads = []
        for i in range(20):
            thread = threading.Thread(target=login_user, args=(i,))
            threads.append(thread)

        start_time = time.time()

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        end_time = time.time()

        # 验证所有登录都成功
        self.assertEqual(len(results), 20)
        self.assertEqual(len([r for r in results if r == 200]), 20)
        self.assertEqual(len(errors), 0)

        # 验证并发性能
        total_time = end_time - start_time
        self.assertLess(total_time, 2.0, f"并发登录时间过长: {total_time:.3f}s")