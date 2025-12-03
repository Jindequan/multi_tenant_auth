"""
测试边界情况和错误处理
"""

import uuid
from datetime import datetime, timedelta
from django.test import TestCase, TransactionTestCase
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, Mock

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import (
    PermissionDenied, UserNotFoundError, WorkspaceNotFoundError,
    TeamNotFoundError, InvalidCredentials, UserNotActive,
    EmailAlreadyExists, TeamMemberAlreadyExists, TeamMemberNotFound
)


class UserEdgeCasesTest(TestCase):
    """测试用户相关的边界情况"""

    def setUp(self):
        self.auth_service = AuthService()

    def test_create_user_with_minimal_data(self):
        """测试最少数据创建用户"""
        user = User.objects.create_user(
            email="minimal@example.com",
            password="Password123!"
        )

        self.assertEqual(user.email, "minimal@example.com")
        self.assertTrue(user.check_password("Password123!"))
        self.assertEqual(user.personal_info, {})  # 默认空字典
        self.assertEqual(user.settings, {})  # 默认空字典
        self.assertTrue(user.is_active)  # 默认激活
        self.assertIsNotNone(user.created_at)

    def test_create_user_with_maximal_data(self):
        """测试最大数据创建用户"""
        large_personal_info = {
            "name": "A" * 100,  # 最大长度
            "bio": "B" * 1000,  # 很长的bio
            "avatar_url": "https://example.com/" + "C" * 200
        }
        large_settings = {
            "theme": "dark",
            "language": "zh-CN",
            "notifications": {"email": True, "push": False},
            "preferences": {"key": "value" * 100}  # 大量设置数据
        }

        user = User.objects.create_user(
            email="maximal@example.com",
            password="Password123!",
            personal_info=large_personal_info,
            settings=large_settings
        )

        self.assertEqual(user.personal_info["name"], "A" * 100)
        self.assertEqual(user.settings["preferences"]["key"], "value" * 100)

    def test_user_email_validation(self):
        """测试邮箱验证的边界情况"""
        invalid_emails = [
            "",  # 空邮箱
            "invalid",  # 无@符号
            "@example.com",  # 缺少用户名
            "user@",  # 缺少域名
            "user..name@example.com",  # 连续点
            "user@.example.com",  # 域名以点开始
            "user@example..com",  # 域名连续点
            "a" * 250 + "@example.com",  # 超长邮箱
        ]

        for email in invalid_emails:
            with self.assertRaises(ValidationError):
                User.objects.create_user(email=email, password="Password123!")

    def test_user_password_validation(self):
        """测试密码验证的边界情况"""
        email = "test@example.com"

        invalid_passwords = [
            "",  # 空密码
            "123",  # 太短
            "password",  # 常见弱密码
            "12345678",  # 纯数字
            "abcdefgh",  # 纯字母
            "AAAAAAA1",  # 简单模式
        ]

        for password in invalid_passwords:
            with self.assertRaises(ValidationError):
                User.objects.create_user(email=email, password=password)

    def test_user_unique_email_edge_cases(self):
        """测试邮箱唯一性的边界情况"""
        email = "Test@Example.com"

        # 创建第一个用户
        User.objects.create_user(email=email, password="Password123!")

        # 测试大小写变化（应该仍然被视为重复）
        with self.assertRaises(IntegrityError):
            User.objects.create_user(email="test@example.com", password="Password123!")

        with self.assertRaises(IntegrityError):
            User.objects.create_user(email="TEST@EXAMPLE.COM", password="Password123!")

    def test_user_deletion_cascade(self):
        """测试用户删除的级联效果"""
        user = User.objects.create_user(email="delete@example.com", password="Password123!")

        # 创建相关数据
        workspace = Workspace.objects.create(
            name="User Workspace",
            slug="user-workspace",
            workspace_type="personal",
            owner=user
        )

        team = Team.objects.create(
            name="User Team",
            slug="user-team",
            owner=user
        )

        # 创建权限记录
        permission_service = PermissionService()
        permission_service.grant_permission(
            granter_id=user.id,
            user_id=user.id,
            workspace_id=workspace.id,
            actions=["view", "edit", "delete", "admin"]
        )

        # 创建审计日志
        AuditLog.objects.create(
            user=user,
            action="test_action",
            resource_type="test",
            details={"test": "data"}
        )

        # 删除用户
        user.delete()

        # 验证级联删除
        self.assertFalse(Workspace.objects.filter(id=workspace.id).exists())
        self.assertFalse(Team.objects.filter(id=team.id).exists())
        self.assertFalse(UserWorkspaceActions.objects.filter(user=user).exists())
        self.assertFalse(AuditLog.objects.filter(user=user).exists())

    def test_concurrent_user_creation(self):
        """测试并发用户创建"""
        import threading
        import time

        results = []
        errors = []

        def create_user(email_suffix):
            try:
                user = User.objects.create_user(
                    email=f"user{email_suffix}@example.com",
                    password="Password123!"
                )
                results.append(user.id)
            except Exception as e:
                errors.append(str(e))

        # 创建多个线程同时创建用户
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_user, args=(i,))
            threads.append(thread)

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 验证结果
        self.assertEqual(len(results), 10)  # 所有用户都应该创建成功
        self.assertEqual(len(errors), 0)  # 不应该有错误
        self.assertEqual(len(set(results)), 10)  # 所有ID都应该不同


class WorkspaceEdgeCasesTest(TestCase):
    """测试工作空间相关的边界情况"""

    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.com", password="Password123!")

    def test_workspace_slug_validation(self):
        """测试工作空间slug验证"""
        invalid_slugs = [
            "",  # 空slug
            "a" * 200,  # 超长slug
            "invalid slug!",  # 包含空格和特殊字符
            "slug-with-multiple--dashes",  # 连续破折号
            "-starting-dash",  # 以破折号开始
            "ending-dash-",  # 以破折号结束
        ]

        for slug in invalid_slugs:
            with self.assertRaises(ValidationError):
                Workspace.objects.create(
                    name="Test Workspace",
                    slug=slug,
                    workspace_type="personal",
                    owner=self.owner
                )

    def test_workspace_unique_slug_edge_cases(self):
        """测试工作空间slug唯一性边界情况"""
        slug = "test-workspace"

        # 创建第一个工作空间
        Workspace.objects.create(
            name="Test Workspace",
            slug=slug,
            workspace_type="personal",
            owner=self.owner
        )

        # 测试重复slug（应该失败）
        with self.assertRaises(IntegrityError):
            Workspace.objects.create(
                name="Another Workspace",
                slug=slug,
                workspace_type="personal",
                owner=self.owner
            )

    def test_workspace_team_relationship_edge_cases(self):
        """测试工作空间团队关系的边界情况"""
        # 创建团队工作空间
        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.owner
        )

        # 正常的团队工作空间
        team_workspace = Workspace.objects.create(
            name="Team Workspace",
            slug="team-workspace",
            workspace_type="team",
            owner=self.owner,
            team=team
        )

        self.assertEqual(team_workspace.team, team)

        # 个人工作空间不应该有team
        personal_workspace = Workspace.objects.create(
            name="Personal Workspace",
            slug="personal-workspace",
            workspace_type="personal",
            owner=self.owner
        )

        self.assertIsNone(personal_workspace.team)

    def test_workspace_permissions_edge_cases(self):
        """测试工作空间权限的边界情况"""
        permission_service = PermissionService()

        # 创建多个工作空间和用户
        user1 = User.objects.create_user(email="user1@example.com", password="Password123!")
        user2 = User.objects.create_user(email="user2@example.com", password="Password123!")

        workspace1 = Workspace.objects.create(
            name="Workspace 1",
            slug="workspace-1",
            workspace_type="personal",
            owner=self.owner
        )
        workspace2 = Workspace.objects.create(
            name="Workspace 2",
            slug="workspace-2",
            workspace_type="personal",
            owner=self.owner
        )

        # 测试复杂的权限场景
        scenarios = [
            (user1.id, workspace1.id, ["view", "edit"]),
            (user1.id, workspace2.id, ["view", "edit", "delete"]),
            (user2.id, workspace1.id, ["view"]),
            (user2.id, workspace2.id, ["view", "share", "admin"]),
        ]

        for user_id, workspace_id, actions in scenarios:
            permission_service.grant_permission(
                granter_id=self.owner.id,
                user_id=user_id,
                workspace_id=workspace_id,
                actions=actions
            )

        # 验证权限正确性
        for user_id, workspace_id, actions in scenarios:
            for action in ["view", "edit", "delete", "share", "admin"]:
                expected = action in actions
                actual = permission_service.check_permission(user_id, workspace_id, action)
                self.assertEqual(actual, expected,
                    f"User {user_id} workspace {workspace_id} action {action} expected {expected} got {actual}")


class PermissionEdgeCasesTest(TestCase):
    """测试权限相关的边界情况"""

    def setUp(self):
        self.permission_service = PermissionService()
        self.owner = User.objects.create_user(email="owner@example.com", password="Password123!")
        self.user = User.objects.create_user(email="user@example.com", password="Password123!")

        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )

    def test_permission_action_validation(self):
        """测试权限动作验证"""
        valid_actions = ["view", "edit", "delete", "share", "admin", "comment"]
        invalid_actions = ["invalid_action", "", "VIEW", "Edit", 123, None]

        # 测试有效动作
        for action in valid_actions:
            result = self.permission_service.grant_permission(
                granter_id=self.owner.id,
                user_id=self.user.id,
                workspace_id=self.workspace.id,
                actions=[action]
            )
            self.assertTrue(result['success'])

        # 测试无效动作
        for action in invalid_actions:
            with self.assertRaises((ValidationError, ValueError, TypeError)):
                self.permission_service.grant_permission(
                    granter_id=self.owner.id,
                    user_id=self.user.id,
                    workspace_id=self.workspace.id,
                    actions=[action]
                )

    def test_permission_expiration_edge_cases(self):
        """测试权限过期的边界情况"""
        now = datetime.now()

        # 测试不同过期时间
        test_cases = [
            (now - timedelta(seconds=1), False),  # 刚过期
            (now, False),  # 正在过期
            (now + timedelta(seconds=1), True),  # 即将过期
            (now + timedelta(hours=1), True),  # 1小时后过期
            (now + timedelta(days=1), True),  # 1天后过期
            (now + timedelta(days=365), True),  # 1年后过期
        ]

        for expires_at, should_be_valid in test_cases:
            with self.subTest(expires_at=expires_at, should_be_valid=should_be_valid):
                # 授予临时权限
                self.permission_service.grant_permission(
                    granter_id=self.owner.id,
                    user_id=self.user.id,
                    workspace_id=self.workspace.id,
                    actions=["view"],
                    expires_at=expires_at
                )

                # 检查权限
                has_permission = self.permission_service.check_permission(
                    self.user.id, self.workspace.id, "view"
                )

                self.assertEqual(has_permission, should_be_valid)

    def test_permission_caching_edge_cases(self):
        """测试权限缓存的边界情况"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        cache_key = f"multi_tenant_auth:perm:{self.user.id}:{self.workspace.id}"

        # 测试缓存不存在时的检查
        cache.delete(cache_key)
        has_permission = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertTrue(has_permission)

        # 验证缓存已设置
        cached_data = cache.get(cache_key)
        self.assertIsNotNone(cached_data)
        self.assertIn("view", cached_data)

        # 测试缓存损坏时的处理
        cache.set(cache_key, "corrupted_data")
        has_permission = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "edit"
        )
        self.assertTrue(has_permission)  # 应该回退到数据库

        # 验证缓存已修复
        cached_data = cache.get(cache_key)
        self.assertIsInstance(cached_data, list)
        self.assertIn("edit", cached_data)

    def test_permission_consistency_under_load(self):
        """测试高负载下的权限一致性"""
        import threading
        import time

        results = []
        errors = []

        def grant_and_check_permissions(thread_id):
            try:
                # 授予权限
                actions = ["view", "edit", "share"]
                if thread_id % 2 == 0:
                    actions.append("delete")

                result = self.permission_service.grant_permission(
                    granter_id=self.owner.id,
                    user_id=self.user.id,
                    workspace_id=self.workspace.id,
                    actions=actions
                )

                # 立即检查权限
                for action in ["view", "edit", "delete", "share"]:
                    has_permission = self.permission_service.check_permission(
                        self.user.id, self.workspace.id, action
                    )
                    expected = action in actions
                    if has_permission != expected:
                        errors.append(f"Thread {thread_id}: {action} expected {expected} got {has_permission}")

                results.append(result['success'])

            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")

        # 创建多个线程
        threads = []
        for i in range(20):
            thread = threading.Thread(target=grant_and_check_permissions, args=(i,))
            threads.append(thread)

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 验证结果
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 20)
        self.assertTrue(all(results))

    def test_permission_cleanup_edge_cases(self):
        """测试权限清理的边界情况"""
        # 创建大量权限记录
        users = []
        workspaces = []

        for i in range(10):
            user = User.objects.create_user(email=f"user{i}@example.com", password="Password123!")
            workspace = Workspace.objects.create(
                name=f"Workspace {i}",
                slug=f"workspace-{i}",
                workspace_type="personal",
                owner=self.owner
            )
            users.append(user)
            workspaces.append(workspace)

            # 授予权限
            self.permission_service.grant_permission(
                granter_id=self.owner.id,
                user_id=user.id,
                workspace_id=workspace.id,
                actions=["view", "edit"]
            )

        # 验证权限已创建
        self.assertEqual(UserWorkspaceActions.objects.count(), 10)

        # 清理所有权限
        deleted_count = UserWorkspaceActions.objects.all().delete()[0]
        self.assertEqual(deleted_count, 10)

        # 验证权限已清理
        self.assertEqual(UserWorkspaceActions.objects.count(), 0)

        # 验证权限检查返回False
        for user, workspace in zip(users, workspaces):
            has_permission = self.permission_service.check_permission(
                user.id, workspace.id, "view"
            )
            self.assertFalse(has_permission)


class APIEdgeCasesTest(APITestCase):
    """测试API相关的边界情况"""

    def setUp(self):
        from ..services import AuthService
        self.auth_service = AuthService()

        register_result = self.auth_service.register_user(
            email="test@example.com",
            password="Password123!"
        )
        self.token = register_result['access_token']
        self.user_id = register_result['user']['id']

    def test_api_with_malformed_token(self):
        """测试格式错误的token"""
        malformed_tokens = [
            "",  # 空token
            "invalid_token",  # 无效格式
            "Bearer",  # 只有Bearer前缀
            "Bearer ",  # 只有Bearer前缀和空格
            "Bearer invalid.jwt.token",  # 无效JWT
            "Bearer " + "A" * 1000,  # 超长token
        ]

        for token in malformed_tokens:
            with self.subTest(token=token):
                self.client.credentials(HTTP_AUTHORIZATION=token)

                response = self.client.get('/api/auth/profile/')
                self.assertIn(response.status_code, [401, 403])

    def test_api_with_large_payload(self):
        """测试大payload的API"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 创建大payload
        large_payload = {
            'personal_info': {
                'name': 'A' * 1000,
                'bio': 'B' * 5000,
                'data': {f'key_{i}': 'value' * 100 for i in range(100)}
            },
            'settings': {
                f'setting_{i}': f'value_{i}' * 10 for i in range(200)
            }
        }

        # 测试更新用户资料
        response = self.client.patch('/api/auth/profile/', large_payload, format='json')

        # 应该能够处理大payload（可能有限制但不应该崩溃）
        self.assertIn(response.status_code, [200, 400, 413])  # 413 = Payload Too Large

    def test_api_concurrent_requests(self):
        """测试并发API请求"""
        import threading
        import time

        results = []
        errors = []

        def make_request(request_id):
            try:
                self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')
                response = self.client.get('/api/auth/profile/')
                results.append((request_id, response.status_code))

                if response.status_code != 200:
                    errors.append(f"Request {request_id}: {response.status_code}")

            except Exception as e:
                errors.append(f"Request {request_id}: {str(e)}")

        # 创建多个并发请求
        threads = []
        for i in range(50):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)

        # 启动所有线程
        for thread in threads:
            thread.start()

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 验证结果
        self.assertEqual(len(results), 50)
        self.assertEqual(len(errors), 0)

        # 大部分请求应该成功
        success_count = sum(1 for _, status in results if status == 200)
        self.assertGreaterEqual(success_count, 45)  # 允许少量失败

    def test_api_with_various_content_types(self):
        """测试不同内容类型的API"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        content_types = [
            'application/json',
            'application/json; charset=utf-8',
            'text/plain',
            'application/xml',
            '',  # 无Content-Type
        ]

        for content_type in content_types:
            with self.subTest(content_type=content_type):
                # 设置Content-Type
                if content_type:
                    self.client.defaults['CONTENT_TYPE'] = content_type
                else:
                    self.client.defaults.pop('CONTENT_TYPE', None)

                # 尝试API请求
                response = self.client.get('/api/auth/profile/')

                # JSON格式应该成功，其他格式可能失败但不应该崩溃
                if 'json' in content_type:
                    self.assertEqual(response.status_code, 200)
                else:
                    self.assertIn(response.status_code, [200, 400, 415])  # 415 = Unsupported Media Type


class DatabaseEdgeCasesTest(TransactionTestCase):
    """测试数据库相关的边界情况"""

    def test_database_connection_failure_simulation(self):
        """测试数据库连接失败模拟"""
        # 这个测试需要模拟数据库连接失败
        with patch('django.db.connection.cursor') as mock_cursor:
            mock_cursor.side_effect = Exception("Database connection failed")

            permission_service = PermissionService()

            # 权限检查应该优雅地处理数据库错误
            with self.assertRaises(Exception):
                permission_service.check_permission(
                    uuid.uuid4(), uuid.uuid4(), "view"
                )

    def test_database_constraint_violations(self):
        """测试数据库约束违反"""
        user = User.objects.create_user(email="test@example.com", password="Password123!")
        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=user
        )

        # 第一次创建权限记录
        UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions=["view"],
            granted_by=user
        )

        # 尝试创建重复记录（应该失败）
        with self.assertRaises(IntegrityError):
            UserWorkspaceActions.objects.create(
                user=user,
                workspace=workspace,
                actions=["edit"],
                granted_by=user
            )

    def test_transaction_rollback_scenarios(self):
        """测试事务回滚场景"""
        user = User.objects.create_user(email="test@example.com", password="Password123!")

        initial_count = User.objects.count()

        try:
            with transaction.atomic():
                # 创建用户
                new_user = User.objects.create_user(email="new@example.com", password="Password123!")

                # 创建工作空间
                workspace = Workspace.objects.create(
                    name="Test Workspace",
                    slug="test-workspace",
                    workspace_type="personal",
                    owner=user
                )

                # 创建权限记录
                UserWorkspaceActions.objects.create(
                    user=new_user,
                    workspace=workspace,
                    actions=["view"],
                    granted_by=user
                )

                # 故意引发错误
                raise Exception("Intentional error")

        except Exception:
            pass  # 预期的错误

        # 验证事务已回滚
        final_count = User.objects.count()
        self.assertEqual(initial_count, final_count)

        # 验证相关记录不存在
        self.assertFalse(User.objects.filter(email="new@example.com").exists())
        self.assertFalse(Workspace.objects.filter(slug="test-workspace").exists())
        self.assertFalse(UserWorkspaceActions.objects.filter(user=new_user).exists())