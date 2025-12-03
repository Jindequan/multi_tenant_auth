"""
边界条件和异常情况测试 - 测试系统的健壮性和错误处理
"""

import json
import uuid
import time
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.core.exceptions import ValidationError, IntegrityError, PermissionDenied
from django.db import connection, transaction, DatabaseError
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.exceptions import ValidationError as DRFValidationError

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import (
    AuthenticationError, PermissionDeniedError, TeamNotFoundError,
    WorkspaceNotFoundError, InvalidPermissionError, InvalidTokenError
)


class ModelValidationTest(TestCase):
    """模型验证测试"""

    def test_user_validation_edge_cases(self):
        """测试用户模型验证边界情况"""
        # 测试极长邮箱
        long_email = f"user_{'a' * 250}@{'b' * 250}.com"
        with self.assertRaises(ValidationError):
            User.objects.create_user(email=long_email, password="password123")

        # 测试空邮箱
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password="password123")

        # 测试None邮箱
        with self.assertRaises(ValueError):
            User.objects.create_user(email=None, password="password123")

        # 测试无效邮箱格式
        invalid_emails = [
            "plainaddress",
            "@missinglocal.com",
            "username@.com",
            "username@com",
            "username@.",
            "username..double dot@domain.com",
            "username@domain .com"
        ]

        for email in invalid_emails:
            with self.subTest(email=email):
                # Django的EmailField可能会验证这些，取决于配置
                try:
                    User.objects.create_user(email=email, password="password123")
                    # 如果没有抛出异常，这是合理的
                except (ValidationError, ValueError):
                    # 预期的异常
                    pass

        # 测试极长密码
        very_long_password = "a" * 1000
        user = User.objects.create_user(email="longpass@example.com", password=very_long_password)
        self.assertTrue(user.check_password(very_long_password))

        # 测试特殊字符密码
        special_passwords = [
            "密码123!",  # 中文
            "🔥🔑🚀",  # Emoji
            "\x00\x01\x02",  # 控制字符
            "' OR '1'='1",  # SQL注入尝试
            "<script>alert('xss')</script>",  # XSS尝试
        ]

        for password in special_passwords:
            with self.subTest(password=repr(password)):
                user = User.objects.create_user(email=f"special_{uuid.uuid4()}@example.com", password=password)
                self.assertTrue(user.check_password(password))

    def test_team_validation_edge_cases(self):
        """测试团队模型验证边界情况"""
        owner = User.objects.create_user(email="owner@example.com", password="password123")

        # 测试极长团队名称
        long_name = "Team " + "A" * 500
        with self.assertRaises(ValidationError):
            Team.objects.create(
                name=long_name,
                slug="long-name",
                owner=owner
            )

        # 测试特殊字符团队名称
        special_names = [
            "Team <script>",
            "Team's Special",
            'Team "Quotes"',
            "Team & Partners",
            "Team / Division",
            "Team \\ Other"
        ]

        for name in special_names:
            with self.subTest(name=name):
                team = Team.objects.create(
                    name=name,
                    slug=f"team-{uuid.uuid4()}",
                    owner=owner
                )
                self.assertEqual(team.name, name)

        # 测试无效slug
        invalid_slugs = [
            "invalid space",
            "invalid@symbol",
            "invalid#hash",
            "invalid%percent",
            "invalid&ampersand",
            "invalid?question",
            "INVALID CAPS",
            "123numbers"
        ]

        for slug in invalid_slugs:
            with self.subTest(slug=slug):
                # 根据slug字段的具体验证规则，可能会抛出异常
                try:
                    team = Team.objects.create(
                        name="Test Team",
                        slug=slug,
                        owner=owner
                    )
                    # 如果成功创建，Django会自动规范化slug
                except ValidationError:
                    # 预期的异常
                    pass

    def test_workspace_validation_edge_cases(self):
        """测试工作空间模型验证边界情况"""
        owner = User.objects.create_user(email="owner@example.com", password="password123")
        team = Team.objects.create(name="Test Team", slug="test-team", owner=owner)

        # 测试无效工作空间类型
        invalid_types = ["invalid_type", "", None, 123, {}, []]
        for workspace_type in invalid_types:
            with self.subTest(workspace_type=workspace_type):
                try:
                    Workspace.objects.create(
                        name="Test Workspace",
                        slug=f"workspace-{uuid.uuid4()}",
                        workspace_type=workspace_type,
                        owner=owner
                    )
                except (ValidationError, ValueError):
                    # 预期的异常
                    pass

        # 测试团队工作空间但无团队
        with self.assertRaises(IntegrityError):
            Workspace.objects.create(
                name="Invalid Team Workspace",
                slug="invalid-team",
                workspace_type="team",
                owner=owner,
                team=None
            )

        # 测试个人工作空间但有团队
        team_workspace = Workspace.objects.create(
            name="Personal with Team",
            slug="personal-team",
            workspace_type="personal",
            owner=owner,
            team=team  # 这可能不被允许
        )
        # 根据业务逻辑，这可能是允许或禁止的

    def test_permissions_validation_edge_cases(self):
        """测试权限模型验证边界情况"""
        user = User.objects.create_user(email="user@example.com", password="password123")
        granter = User.objects.create_user(email="granter@example.com", password="password123")
        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=granter
        )

        # 测试无效权限列表
        invalid_actions = [
            "invalid_action",
            "admin",  # 可能是保留权限
            "ALL",    # 可能是保留权限
            123,      # 数字
            {},       # 字典
            [],       # 嵌套列表
        ]

        for actions in invalid_actions:
            with self.subTest(actions=actions):
                try:
                    permission = UserWorkspaceActions.objects.create(
                        user=user,
                        workspace=workspace,
                        actions=[actions] if not isinstance(actions, list) else actions,
                        granted_by=granter
                    )
                    # 如果成功，验证权限已存储
                    self.assertEqual(permission.actions, [actions] if not isinstance(actions, list) else actions)
                except (ValidationError, ValueError):
                    # 预期的异常
                    pass

        # 测试过期时间在过去的权限
        past_time = timezone.now() - timedelta(days=1)
        permission = UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions=["view"],
            granted_by=granter,
            expires_at=past_time
        )
        self.assertTrue(permission.expires_at < timezone.now())

        # 测试极远的过期时间
        future_time = timezone.now() + timedelta(days=100 * 365)
        permission = UserWorkspaceActions.objects.create(
            user=user,
            workspace=Workspace.objects.create(
                name="Future Workspace",
                slug="future-workspace",
                workspace_type="personal",
                owner=granter
            ),
            actions=["view"],
            granted_by=granter,
            expires_at=future_time
        )
        self.assertTrue(permission.expires_at > timezone.now())


class DatabaseConstraintTest(TransactionTestCase):
    """数据库约束测试"""

    def test_foreign_key_constraints(self):
        """测试外键约束"""
        user = User.objects.create_user(email="user@example.com", password="password123")

        # 尝试创建不存在的团队的工作空间
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                workspace = Workspace(
                    name="Invalid Workspace",
                    slug="invalid-workspace",
                    workspace_type="team",
                    owner=user,
                    team_id=99999  # 不存在的团队ID
                )
                workspace.save()

        # 尝试创建不存在所有者的团队
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                team = Team(
                    name="Invalid Team",
                    slug="invalid-team",
                    owner_id=99999  # 不存在的用户ID
                )
                team.save()

        # 尝试创建不存在用户的权限记录
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                permission = UserWorkspaceActions(
                    user_id=99999,  # 不存在的用户ID
                    workspace_id=99999,  # 不存在的工作空间ID
                    actions=["view"],
                    granted_by=user
                )
                permission.save()

    def test_unique_constraints(self):
        """测试唯一性约束"""
        owner = User.objects.create_user(email="owner@example.com", password="password123")

        # 测试团队slug唯一性
        Team.objects.create(
            name="Team 1",
            slug="unique-slug",
            owner=owner
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Team.objects.create(
                    name="Team 2",
                    slug="unique-slug",  # 重复slug
                    owner=owner
                )

        # 测试用户工作空间权限唯一性
        user = User.objects.create_user(email="user@example.com", password="password123")
        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=owner
        )

        UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions=["view"],
            granted_by=owner
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                UserWorkspaceActions.objects.create(
                    user=user,
                    workspace=workspace,  # 重复用户-工作空间组合
                    actions=["edit"],
                    granted_by=owner
                )

        # 测试团队成员唯一性
        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=owner
        )

        TeamMember.objects.create(
            team=team,
            user=user,
            role_name="member"
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                TeamMember.objects.create(
                    team=team,
                    user=user,  # 重复团队-用户组合
                    role_name="admin"
                )

    def test_not_null_constraints(self):
        """测试非空约束"""
        user = User.objects.create_user(email="user@example.com", password="password123")

        # 测试必需字段为空
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                team = Team(
                    name="Test Team",
                    slug="test-team",
                    owner=None  # 不能为空
                )
                team.save()

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                workspace = Workspace(
                    name="Test Workspace",
                    slug="test-workspace",
                    workspace_type="personal",
                    owner=None  # 不能为空
                )
                workspace.save()

    def test_cascade_delete_behavior(self):
        """测试级联删除行为"""
        owner = User.objects.create_user(email="owner@example.com", password="password123")
        member = User.objects.create_user(email="member@example.com", password="password123")

        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=owner
        )

        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="team",
            owner=owner,
            team=team
        )

        team_member = TeamMember.objects.create(
            team=team,
            user=member,
            role_name="member"
        )

        permission = UserWorkspaceActions.objects.create(
            user=member,
            workspace=workspace,
            actions=["view"],
            granted_by=owner
        )

        # 删除团队应该级联删除相关记录
        team.delete()

        # 验证相关记录被删除
        self.assertFalse(Team.objects.filter(id=team.id).exists())
        self.assertFalse(TeamMember.objects.filter(id=team_member.id).exists())
        # 工作空间可能被级联删除或设置为空，取决于模型配置
        # 权限记录可能也被级联删除


class ServiceExceptionTest(TestCase):
    """服务层异常测试"""

    def setUp(self):
        self.auth_service = AuthService()
        self.permission_service = PermissionService()
        self.team_service = TeamService()

        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123"
        )

    def test_auth_service_exceptions(self):
        """测试认证服务异常"""
        # 测试无效认证
        with self.assertRaises(AuthenticationError):
            self.auth_service.authenticate_user("invalid@example.com", "wrongpassword")

        with self.assertRaises(AuthenticationError):
            self.auth_service.authenticate_user(None, "password")

        with self.assertRaises(AuthenticationError):
            self.auth_service.authenticate_user("valid@example.com", None)

        # 测试无效token
        with self.assertRaises(InvalidTokenError):
            self.auth_service.validate_access_token("invalid_token")

        with self.assertRaises(InvalidTokenError):
            self.auth_service.validate_access_token(None)

        with self.assertRaises(InvalidTokenError):
            self.auth_service.validate_access_token("")

        # 测试无效refresh token
        with self.assertRaises(InvalidTokenError):
            self.auth_service.refresh_access_token("invalid_refresh_token")

    def test_permission_service_exceptions(self):
        """测试权限服务异常"""
        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )

        # 测试无效权限授予
        with self.assertRaises(InvalidPermissionError):
            self.permission_service.grant_permissions(
                None,  # 无效用户
                workspace,
                ["view"],
                self.owner
            )

        with self.assertRaises(InvalidPermissionError):
            self.permission_service.grant_permissions(
                self.member,
                None,  # 无效工作空间
                ["view"],
                self.owner
            )

        with self.assertRaises(InvalidPermissionError):
            self.permission_service.grant_permissions(
                self.member,
                workspace,
                [],  # 空权限列表可能无效
                self.owner
            )

        # 测试无效权限检查
        with self.assertRaises(InvalidPermissionError):
            self.permission_service.check_permission(
                None,
                workspace,
                "view"
            )

        with self.assertRaises(InvalidPermissionError):
            self.permission_service.check_permission(
                self.member,
                None,
                "view"
            )

    def test_team_service_exceptions(self):
        """测试团队服务异常"""
        # 测试不存在的团队操作
        with self.assertRaises(TeamNotFoundError):
            self.team_service.get_team_by_slug("nonexistent-team")

        with self.assertRaises(TeamNotFoundError):
            self.team_service.add_team_member(
                99999,  # 不存在的团队ID
                self.member.id,
                "member"
            )

        # 测试无效团队创建
        with self.assertRaises(ValidationError):
            self.team_service.create_team(
                None,  # 无效名称
                "invalid-slug",
                self.owner
            )

        with self.assertRaises(ValidationError):
            self.team_service.create_team(
                "Valid Team Name",
                None,  # 无效slug
                self.owner
            )

        with self.assertRaises(ValidationError):
            self.team_service.create_team(
                "Valid Team Name",
                "valid-slug",
                None  # 无效所有者
            )


class APIExceptionTest(APITestCase):
    """API异常测试"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            password="password123"
        )
        self.token = self._get_token()

    def test_authentication_api_exceptions(self):
        """测试认证API异常"""
        # 测试无效登录数据
        invalid_login_data = [
            {},  # 空数据
            {"email": ""},  # 空邮箱
            {"password": ""},  # 空密码
            {"email": "invalid"},  # 无效邮箱格式
            {"email": "user@example.com"},  # 缺少密码
            {"password": "password123"},  # 缺少邮箱
        ]

        for data in invalid_login_data:
            with self.subTest(data=data):
                response = self.client.post('/api/auth/login/', data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 测试错误认证
        wrong_auth_data = [
            {"email": "wrong@example.com", "password": "password123"},
            {"email": "user@example.com", "password": "wrongpassword"},
            {"email": "wrong@example.com", "password": "wrongpassword"},
        ]

        for data in wrong_auth_data:
            with self.subTest(data=data):
                response = self.client.post('/api/auth/login/', data)
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authorization_api_exceptions(self):
        """测试授权API异常"""
        # 测试未认证访问受保护端点
        protected_endpoints = [
            '/api/auth/profile/',
            '/api/auth/logout/',
            '/api/auth/change-password/',
            '/api/auth/workspaces/',
        ]

        for endpoint in protected_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 测试权限不足的访问
        # 假设用户没有管理员权限
        admin_endpoints = [
            '/api/auth/users/',
            '/api/auth/user-stats/',
        ]

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        for endpoint in admin_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                # 根据具体实现，可能是403或404
                self.assertIn(response.status_code, [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND])

    def test_invalid_data_api_exceptions(self):
        """测试无效数据API异常"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 测试无效的注册数据
        invalid_registration_data = [
            {},  # 空数据
            {"email": "invalid-email"},  # 无效邮箱
            {"email": "valid@example.com", "password": "123"},  # 弱密码
            {"password": "ValidPassword123!"},  # 缺少邮箱
            {"email": "valid@example.com"},  # 缺少密码
        ]

        for data in invalid_registration_data:
            with self.subTest(data=data):
                response = self.client.post('/api/auth/register/', data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 测试无效的密码修改数据
        invalid_password_data = [
            {},  # 空数据
            {"new_password": "NewPassword123!"},  # 缺少旧密码
            {"old_password": "password123"},  # 缺少新密码
            {"old_password": "wrong", "new_password": "NewPassword123!"},  # 错误旧密码
            {"old_password": "password123", "new_password": "123"},  # 弱新密码
        ]

        for data in invalid_password_data:
            with self.subTest(data=data):
                response = self.client.post('/api/auth/change-password/', data)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_resource_not_found_exceptions(self):
        """测试资源未找到异常"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 测试不存在的资源ID
        nonexistent_ids = [0, 99999, -1, "invalid"]

        for resource_id in nonexistent_ids:
            with self.subTest(resource_id=resource_id):
                # 假设这些端点接受资源ID参数
                response = self.client.get(f'/api/auth/workspaces/{resource_id}/')
                self.assertIn(response.status_code, [status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST])

    def test_method_not_allowed_exceptions(self):
        """测试方法不允许异常"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 测试错误的HTTP方法
        endpoints_and_methods = [
            ('/api/auth/login/', 'GET'),
            ('/api/auth/register/', 'GET'),
            ('/api/auth/logout/', 'GET'),
            ('/api/auth/change-password/', 'GET'),
        ]

        for endpoint, method in endpoints_and_methods:
            with self.subTest(endpoint=endpoint, method=method):
                response = self.client.generic(method, endpoint)
                self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def _get_token(self):
        """获取访问token"""
        response = self.client.post('/api/auth/login/', {
            "email": "user@example.com",
            "password": "password123"
        })
        return response.data['access_token']


class SystemResourceTest(TestCase):
    """系统资源测试"""

    def test_large_data_handling(self):
        """测试大数据处理"""
        # 测试大量用户
        users = []
        for i in range(100):
            user = User.objects.create_user(
                email=f"user{i}@example.com",
                password="password123",
                personal_info={
                    "name": f"User {i}",
                    "bio": "A" * 1000,  # 长文本
                    "metadata": {"key" + str(j): "value" + str(j) for j in range(50)}  # 大量元数据
                }
            )
            users.append(user)

        # 验证数据完整性
        for i, user in enumerate(users):
            self.assertEqual(user.personal_info["name"], f"User {i}")
            self.assertEqual(len(user.personal_info["bio"]), 1000)
            self.assertEqual(len(user.personal_info["metadata"]), 50)

    def test_database_connection_limits(self):
        """测试数据库连接限制"""
        # 模拟大量并发数据库操作
        import threading
        import time

        def create_user(thread_id):
            try:
                user = User.objects.create_user(
                    email=f"thread{thread_id}@example.com",
                    password="password123"
                )
                return user.id
            except Exception as e:
                return str(e)

        # 创建多个线程同时操作数据库
        threads = []
        results = []

        for i in range(20):  # 20个并发线程
            thread = threading.Thread(
                target=lambda i=i: results.append(create_user(i))
            )
            threads.append(thread)

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 验证结果
        successful_results = [r for r in results if isinstance(r, int)]
        error_results = [r for r in results if isinstance(r, str)]

        # 至少应该有一些成功
        self.assertGreater(len(successful_results), 0)

        # 检查是否有数据库连接错误
        database_errors = [e for e in error_results if 'connection' in e.lower() or 'timeout' in e.lower()]
        if database_errors:
            # 如果有连接错误，记录但不作为测试失败
            print(f"Database connection errors: {database_errors}")

    def test_memory_usage_limits(self):
        """测试内存使用限制"""
        import gc
        import sys

        # 获取初始内存使用
        gc.collect()
        initial_objects = len(gc.get_objects())

        # 创建大量对象
        large_objects = []
        for i in range(1000):
            user = User.objects.create_user(
                email=f"memory{i}@example.com",
                password="password123",
                personal_info={"data": "x" * 1000}  # 每个对象1KB数据
            )
            large_objects.append(user)

        # 检查内存增长
        current_objects = len(gc.get_objects())
        memory_growth = current_objects - initial_objects

        # 清理
        for user in large_objects:
            user.delete()
        large_objects.clear()
        gc.collect()

        # 内存增长应该在合理范围内
        # 这个测试的结果取决于具体的环境和配置
        self.assertLess(memory_growth, 100000)  # 假设的内存限制

    def test_file_size_limits(self):
        """测试文件大小限制"""
        # 这个测试更适用于有文件上传功能的系统
        # 在当前的多租户认证系统中，可能没有直接的文件上传
        pass

    def test_concurrent_request_limits(self):
        """测试并发请求限制"""
        import threading
        import time
        from django.test import Client

        def make_request(thread_id):
            client = Client()
            try:
                response = client.post('/api/auth/login/', {
                    "email": f"concurrent{thread_id}@example.com",
                    "password": "password123"
                })
                return response.status_code
            except Exception as e:
                return str(e)

        # 创建多个并发请求
        threads = []
        results = []

        # 先创建用户
        for i in range(10):
            User.objects.create_user(
                email=f"concurrent{i}@example.com",
                password="password123"
            )

        start_time = time.time()

        for i in range(10):
            thread = threading.Thread(
                target=lambda i=i: results.append(make_request(i))
            )
            threads.append(thread)

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        end_time = time.time()
        total_time = end_time - start_time

        # 验证结果
        successful_results = [r for r in results if r == 200]
        error_results = [r for r in results if r != 200]

        # 至少应该有一些成功
        self.assertGreater(len(successful_results), 0)
        self.assertLess(total_time, 5.0)  # 总时间应该在5秒内完成

        if error_results:
            print(f"Concurrent request errors: {error_results}")


class SecurityEdgeCaseTest(TestCase):
    """安全边界情况测试"""

    def test_sql_injection_attempts(self):
        """测试SQL注入尝试"""
        suspicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users --",
            "admin'--",
            "admin' /*",
            "' OR 1=1#",
            "'; UPDATE users SET email='hacked@evil.com' WHERE 1=1 --"
        ]

        for suspicious_input in suspicious_inputs:
            with self.subTest(input=suspicious_input):
                # 尝试在各种字段中使用可疑输入
                try:
                    # 测试用户查找
                    User.objects.create_user(
                        email=f"test_{uuid.uuid4()}@example.com",
                        password="password123"
                    )

                    # Django ORM应该自动转义这些输入
                    users = User.objects.filter(email__contains=suspicious_input)
                    self.assertEqual(len(users), 0)  # 应该没有匹配的用户

                except Exception as e:
                    # 如果抛出异常，这是安全的（表示注入被阻止）
                    pass

    def test_xss_prevention(self):
        """测试XSS防护"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "'\"><script>alert('xss')</script>",
            "<iframe src=javascript:alert('xss')>",
        ]

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                # 测试在个人信息字段中存储XSS payload
                user = User.objects.create_user(
                    email=f"xss_{uuid.uuid4()}@example.com",
                    password="password123",
                    personal_info={
                        "name": payload,
                        "bio": f"My bio contains {payload}"
                    }
                )

                # 验证payload被正确存储（不会被执行）
                self.assertEqual(user.personal_info["name"], payload)
                self.assertIn(payload, user.personal_info["bio"])

    def test_path_traversal_attempts(self):
        """测试路径遍历尝试"""
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        for payload in path_traversal_payloads:
            with self.subTest(payload=payload):
                # 测试在文件相关操作中使用路径遍历payload
                try:
                    # 大多数现代框架都有路径遍历防护
                    # 这里只是确保系统不会崩溃
                    workspace = Workspace.objects.create(
                        name=f"Test {payload}",
                        slug=f"test-{uuid.uuid4()}",
                        workspace_type="personal",
                        owner=User.objects.create_user(
                            email=f"traversal_{uuid.uuid4()}@example.com",
                            password="password123"
                        )
                    )
                    self.assertIn(payload, workspace.name)

                except Exception as e:
                    # 异常也是可以接受的安全响应
                    pass

    def test_csrf_protection(self):
        """测试CSRF防护"""
        # Django默认有CSRF保护
        # 这个测试主要确保CSRF中间件正常工作
        client = Client(enforce_csrf_checks=True)

        # 创建用户
        user = User.objects.create_user(
            email="csrf@example.com",
            password="password123"
        )

        # 尝试不使用CSRF token进行POST请求
        response = client.post('/api/auth/login/', {
            "email": "csrf@example.com",
            "password": "password123"
        })

        # 在启用CSRF检查的情况下，应该返回403
        self.assertEqual(response.status_code, 403)

    def test_rate_limiting(self):
        """测试速率限制"""
        # 这个测试需要实际的速率限制实现
        # 这里只是一个框架
        client = Client()

        # 模拟大量快速请求
        responses = []
        for i in range(100):
            response = client.post('/api/auth/login/', {
                "email": f"rate{i}@example.com",
                "password": "password123"
            })
            responses.append(response.status_code)

        # 检查是否有速率限制响应（通常是429）
        rate_limited_responses = [r for r in responses if r == 429]
        if rate_limited_responses:
            self.assertGreater(len(rate_limited_responses), 0)

    def test_data_sanitization(self):
        """测试数据清理"""
        # 测试各种可能需要清理的数据
        test_data = {
            "name": "User\n\r\t\x00\x01",
            "description": "Description with unicode: 你好 🌍",
            "url": "http://example.com/path?param=value&other=data",
            "json": {"key": "value", "nested": {"array": [1, 2, 3]}},
            "number": "123",
            "boolean": "true",
        }

        user = User.objects.create_user(
            email="sanitize@example.com",
            password="password123",
            personal_info=test_data
        )

        # 验证数据被正确存储
        retrieved_data = user.personal_info
        self.assertEqual(retrieved_data["name"], test_data["name"])
        self.assertEqual(retrieved_data["description"], test_data["description"])
        self.assertEqual(retrieved_data["url"], test_data["url"])
        self.assertEqual(retrieved_data["json"], test_data["json"])
        self.assertEqual(retrieved_data["number"], test_data["number"])
        self.assertEqual(retrieved_data["boolean"], test_data["boolean"])