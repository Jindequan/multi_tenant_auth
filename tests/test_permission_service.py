"""
测试权限服务
"""

import uuid
from datetime import datetime, timedelta
from django.test import TestCase, TransactionTestCase
from django.core.cache import cache
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.test import APIClient

from ..models import User, Workspace, Team, TeamMember, UserWorkspaceActions, AuditLog
from ..services import PermissionService, AuthService, TeamService
from ..constants import ROLE_PERMISSIONS
from ..exceptions import PermissionDenied, UserNotFoundError, WorkspaceNotFoundError


class PermissionServiceTest(TestCase):
    """测试权限服务核心功能"""

    def setUp(self):
        self.permission_service = PermissionService()
        self.auth_service = AuthService()

        # 创建测试用户
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )
        self.user = User.objects.create_user(
            email="user@example.com",
            password="password123"
        )
        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123"
        )

        # 创建测试工作空间
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )
        self.team_workspace = Workspace.objects.create(
            name="Team Workspace",
            slug="team-workspace",
            workspace_type="team",
            owner=self.owner
        )

        # 创建团队
        self.team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.owner
        )

    def test_grant_permission_success(self):
        """测试成功授予权限"""
        result = self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share"]
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['granted_actions'], ["view", "edit", "share"])

        # 验证数据库中的权限记录
        permission = UserWorkspaceActions.objects.get(
            user=self.user,
            workspace=self.workspace
        )
        self.assertEqual(set(permission.actions), {"view", "edit", "share"})
        self.assertEqual(permission.granted_by, self.owner)

    def test_check_permission_success(self):
        """测试权限检查成功"""
        # 先授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        # 检查权限
        can_view = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        can_edit = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "edit"
        )
        can_delete = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "delete"
        )

        self.assertTrue(can_view)
        self.assertTrue(can_edit)
        self.assertFalse(can_delete)

    def test_check_permission_no_record(self):
        """测试没有权限记录时的权限检查"""
        result = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertFalse(result)

    def test_check_permissions_batch(self):
        """测试批量权限检查"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share"]
        )

        # 批量检查
        permissions = self.permission_service.check_permissions(
            self.user.id,
            self.workspace.id,
            ["view", "edit", "delete", "share", "admin"]
        )

        expected = {
            "view": True,
            "edit": True,
            "delete": False,
            "share": True,
            "admin": False
        }
        self.assertEqual(permissions, expected)

    def test_update_permissions(self):
        """测试更新权限"""
        # 初始权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view"]
        )

        # 更新权限
        result = self.permission_service.update_permissions(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "delete", "share"]
        )

        self.assertTrue(result['success'])

        # 验证权限已更新
        permissions = self.permission_service.check_permissions(
            self.user.id,
            self.workspace.id,
            ["view", "edit", "delete", "share"]
        )

        self.assertTrue(all(permissions.values()))

    def test_revoke_permission(self):
        """测试撤销权限"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "delete"]
        )

        # 撤销权限
        result = self.permission_service.revoke_permission(
            user_id=self.user.id,
            workspace_id=self.workspace.id
        )

        self.assertTrue(result['success'])

        # 验证权限已撤销
        can_view = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertFalse(can_view)

        # 验证权限记录已删除
        with self.assertRaises(UserWorkspaceActions.DoesNotExist):
            UserWorkspaceActions.objects.get(user=self.user, workspace=self.workspace)

    def test_revoke_specific_permission(self):
        """测试撤销特定权限"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "delete", "share"]
        )

        # 撤销特定权限
        result = self.permission_service.revoke_permission(
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["delete", "share"]
        )

        self.assertTrue(result['success'])

        # 验证特定权限已撤销，其他权限保留
        permissions = self.permission_service.check_permissions(
            self.user.id,
            self.workspace.id,
            ["view", "edit", "delete", "share"]
        )

        self.assertEqual(permissions, {
            "view": True,
            "edit": True,
            "delete": False,
            "share": False
        })

    def test_temporary_permissions(self):
        """测试临时权限"""
        expires_at = datetime.now() + timedelta(hours=1)

        # 授予临时权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"],
            expires_at=expires_at
        )

        # 权限应该有效
        can_view = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertTrue(can_view)

        # 验证过期时间设置
        permission = UserWorkspaceActions.objects.get(
            user=self.user,
            workspace=self.workspace
        )
        self.assertIsNotNone(permission.expires_at)

    def test_expired_permissions(self):
        """测试过期权限"""
        expires_at = datetime.now() - timedelta(hours=1)  # 已过期

        # 授予已过期的权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"],
            expires_at=expires_at
        )

        # 权限应该无效
        can_view = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertFalse(can_view)

    def test_grant_role_permissions(self):
        """测试基于角色的权限授予"""
        # 授予编辑角色
        result = self.permission_service.grant_role_permissions(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            role="editor"
        )

        self.assertTrue(result['success'])

        # 验证获得了编辑角色的所有权限
        expected_actions = ROLE_PERMISSIONS['editor']
        permissions = self.permission_service.check_permissions(
            self.user.id,
            self.workspace.id,
            expected_actions
        )

        self.assertTrue(all(permissions.values()))

    def test_get_user_workspaces(self):
        """测试获取用户有权限的工作空间"""
        # 创建多个工作空间
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

        # 授予不同权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=workspace1.id,
            actions=["view"]
        )
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=workspace2.id,
            actions=["view", "edit", "delete"]
        )

        # 获取所有有权限的工作空间
        workspaces = self.permission_service.get_user_workspaces(self.user.id)

        self.assertEqual(len(workspaces), 3)  # 包括setUp中的workspace

        # 获取有编辑权限的工作空间
        edit_workspaces = self.permission_service.get_user_workspaces(
            self.user.id,
            permissions=["edit"]
        )
        self.assertEqual(len(edit_workspaces), 2)

    def test_batch_permission_operations(self):
        """测试批量权限操作"""
        workspaces = []
        for i in range(5):
            ws = Workspace.objects.create(
                name=f"Workspace {i}",
                slug=f"workspace-{i}",
                workspace_type="personal",
                owner=self.owner
            )
            workspaces.append(ws)

        # 批量授予权限
        grant_results = self.permission_service.batch_grant_permissions([
            {
                "user_id": self.user.id,
                "workspace_id": ws.id,
                "actions": ["view", "edit"]
            }
            for ws in workspaces
        ])

        self.assertEqual(len(grant_results), 5)
        self.assertTrue(all(result['success'] for result in grant_results))

        # 批量检查权限
        check_results = self.permission_service.batch_check_permissions([
            {
                "user_id": self.user.id,
                "workspace_id": ws.id,
                "action": "view"
            }
            for ws in workspaces
        ])

        self.assertEqual(len(check_results), 5)
        self.assertTrue(all(check_results.values()))

    def test_permission_caching(self):
        """测试权限缓存"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        # 第一次检查（从数据库）
        cache_key = f"multi_tenant_auth:perm:{self.user.id}:{self.workspace.id}"
        self.assertIsNone(cache.get(cache_key))

        can_view = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )
        self.assertTrue(can_view)

        # 验证缓存已设置
        cached_permissions = cache.get(cache_key)
        self.assertIsNotNone(cached_permissions)
        self.assertIn("view", cached_permissions)

        # 第二次检查（从缓存）
        can_edit = self.permission_service.check_permission(
            self.user.id, self.workspace.id, "edit"
        )
        self.assertTrue(can_edit)

    def test_clear_permission_cache(self):
        """测试清除权限缓存"""
        # 授予权限并建立缓存
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view"]
        )

        # 触发缓存
        self.permission_service.check_permission(
            self.user.id, self.workspace.id, "view"
        )

        # 清除缓存
        self.permission_service.clear_permission_cache(
            self.user.id, self.workspace.id
        )

        # 验证缓存已清除
        cache_key = f"multi_tenant_auth:perm:{self.user.id}:{self.workspace.id}"
        self.assertIsNone(cache.get(cache_key))


class PermissionAPITest(APITestCase):
    """测试权限API"""

    def setUp(self):
        self.client = APIClient()
        self.permission_service = PermissionService()
        self.auth_service = AuthService()

        # 创建用户并获取token
        register_result = self.auth_service.register_user(
            email="test@example.com",
            password="password123"
        )
        self.user_token = register_result['access_token']
        self.user_id = register_result['user']['id']

        admin_result = self.auth_service.register_user(
            email="admin@example.com",
            password="password123"
        )
        self.admin_token = admin_result['access_token']
        self.admin_id = admin_result['user']['id']

        # 创建工作空间
        self.user = User.objects.get(id=self.user_id)
        self.admin = User.objects.get(id=self.admin_id)

        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.admin
        )

    def test_check_permissions_api_success(self):
        """测试权限检查API成功"""
        # 先授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin_id,
            user_id=self.user_id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share"]
        )

        # 设置认证头
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')

        # 检查权限
        url = reverse('permission-check')
        data = {
            'user_id': str(self.user_id),
            'workspace_id': str(self.workspace.id),
            'action': 'edit'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['has_permission'])

    def test_check_permissions_api_batch(self):
        """测试批量权限检查API"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin_id,
            user_id=self.user_id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share"]
        )

        # 设置认证头
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')

        # 批量检查权限
        url = reverse('permission-check')
        data = {
            'user_id': str(self.user_id),
            'workspace_id': str(self.workspace.id),
            'actions': ['view', 'edit', 'delete', 'share']
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected = {
            'view': True,
            'edit': True,
            'delete': False,
            'share': True
        }
        self.assertEqual(response.data, expected)

    def test_grant_permission_api_success(self):
        """测试授予权限API成功"""
        # 使用admin token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')

        url = reverse('permission-grant')
        data = {
            'user_id': str(self.user_id),
            'workspace_id': str(self.workspace.id),
            'actions': ['view', 'edit', 'share']
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])

        # 验证权限已授予
        can_edit = self.permission_service.check_permission(
            self.user_id, self.workspace.id, 'edit'
        )
        self.assertTrue(can_edit)

    def test_grant_permission_api_unauthorized(self):
        """测试未授权用户尝试授予权限"""
        # 使用普通用户token（无权限）
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')

        url = reverse('permission-grant')
        data = {
            'user_id': str(self.user_id),
            'workspace_id': str(self.workspace.id),
            'actions': ['view', 'edit']
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_revoke_permission_api_success(self):
        """测试撤销权限API成功"""
        # 先授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin_id,
            user_id=self.user_id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        # 撤销权限
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        url = reverse('permission-revoke')
        data = {
            'user_id': str(self.user_id),
            'workspace_id': str(self.workspace.id)
        }

        response = self.client.delete(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证权限已撤销
        can_view = self.permission_service.check_permission(
            self.user_id, self.workspace.id, 'view'
        )
        self.assertFalse(can_view)

    def test_permission_api_validation_error(self):
        """测试权限API验证错误"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')

        url = reverse('permission-check')
        data = {
            'user_id': 'invalid-uuid',  # 无效的UUID
            'workspace_id': str(self.workspace.id),
            'action': 'edit'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_get_user_permissions_api(self):
        """测试获取用户权限API"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin_id,
            user_id=self.user_id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share", "admin"]
        )

        # 获取权限
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_token}')
        url = reverse('permission-user-permissions')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(str(self.workspace.id), response.data['workspaces'])
        workspace_permissions = response.data['workspaces'][str(self.workspace.id)]
        self.assertEqual(set(workspace_permissions), {"view", "edit", "share", "admin"})


class PermissionSecurityTest(TestCase):
    """测试权限安全性"""

    def setUp(self):
        self.permission_service = PermissionService()
        self.auth_service = AuthService()

        # 创建用户
        self.user1 = User.objects.create_user(email="user1@example.com", password="password123")
        self.user2 = User.objects.create_user(email="user2@example.com", password="password123")
        self.owner = User.objects.create_user(email="owner@example.com", password="password123")

        # 创建工作空间
        self.workspace = Workspace.objects.create(
            name="Secure Workspace",
            slug="secure-workspace",
            workspace_type="personal",
            owner=self.owner
        )

    def test_permission_isolation(self):
        """测试权限隔离"""
        # 给user1授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user1.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        # user2应该没有权限
        can_view_user1 = self.permission_service.check_permission(
            self.user1.id, self.workspace.id, "view"
        )
        can_view_user2 = self.permission_service.check_permission(
            self.user2.id, self.workspace.id, "view"
        )

        self.assertTrue(can_view_user1)
        self.assertFalse(can_view_user2)

    def test_permission_elevation_prevention(self):
        """测试防止权限提升"""
        # 给用户普通权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user1.id,
            workspace_id=self.workspace.id,
            actions=["view"]
        )

        # 用户尝试给自己授予权限（应该失败）
        with self.assertRaises(PermissionDenied):
            self.permission_service.grant_permission(
                granter_id=self.user1.id,  # 普通用户尝试授权
                user_id=self.user1.id,
                workspace_id=self.workspace.id,
                actions=["view", "edit", "delete", "admin"]
            )

    def test_audit_logging(self):
        """测试权限操作的审计日志"""
        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.owner.id,
            user_id=self.user1.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

        # 检查审计日志
        audit_log = AuditLog.objects.filter(
            action="permission_granted"
        ).first()

        self.assertIsNotNone(audit_log)
        self.assertEqual(audit_log.user, self.owner)
        self.assertIn(str(self.user1.id), audit_log.details['target_user'])
        self.assertIn(str(self.workspace.id), audit_log.details['workspace'])
        self.assertEqual(audit_log.details['granted_actions'], ["view", "edit"])

    def test_concurrent_permission_updates(self):
        """测试并发权限更新"""
        import threading
        import time

        results = []

        def grant_permission():
            try:
                result = self.permission_service.grant_permission(
                    granter_id=self.owner.id,
                    user_id=self.user1.id,
                    workspace_id=self.workspace.id,
                    actions=["view", "edit"]
                )
                results.append(result['success'])
            except Exception as e:
                results.append(False)

        def update_permission():
            time.sleep(0.1)  # 稍微延迟
            try:
                result = self.permission_service.update_permissions(
                    granter_id=self.owner.id,
                    user_id=self.user1.id,
                    workspace_id=self.workspace.id,
                    actions=["view", "edit", "delete"]
                )
                results.append(result['success'])
            except Exception as e:
                results.append(False)

        # 并发执行
        thread1 = threading.Thread(target=grant_permission)
        thread2 = threading.Thread(target=update_permission)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        # 至少一个操作应该成功
        self.assertTrue(any(results))

        # 最终权限应该是确定的
        final_permissions = self.permission_service.check_permissions(
            self.user1.id,
            self.workspace.id,
            ["view", "edit", "delete"]
        )
        self.assertTrue(final_permissions["view"])  # view应该始终存在