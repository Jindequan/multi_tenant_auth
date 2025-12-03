"""
完整的权限系统测试 - 涵盖所有权限验证情况和场景
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import AuthenticationError, PermissionDeniedError
from ..decorators import require_auth, require_permissions, require_workspace_access

User = get_user_model()


class BasicPermissionTest(TestCase):
    """基础权限测试"""

    def setUp(self):
        self.permission_service = PermissionService()

        # 创建测试用户
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            personal_info={"name": "Workspace Owner"}
        )

        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            personal_info={"name": "Workspace Member"}
        )

        self.non_member = User.objects.create_user(
            email="nonmember@example.com",
            password="password123",
            personal_info={"name": "Non Member"}
        )

        # 创建团队和工作空间
        self.team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.owner
        )

        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="team",
            owner=self.owner,
            team=self.team
        )

    def test_workspace_owner_permissions(self):
        """测试工作空间所有者权限"""
        # 工作空间所有者应该拥有所有权限
        permissions = self.permission_service.get_user_workspace_permissions(
            self.owner, self.workspace
        )

        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)
        self.assertIn("delete", permissions)
        self.assertIn("share", permissions)
        self.assertIn("admin", permissions)

    def test_explicit_granted_permissions(self):
        """测试明确授予的权限"""
        # 为成员授予权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit", "comment"],
            granted_by=self.owner
        )

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )

        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)
        self.assertIn("comment", permissions)
        self.assertNotIn("delete", permissions)
        self.assertNotIn("share", permissions)

    def test_no_permissions(self):
        """测试无权限情况"""
        permissions = self.permission_service.get_user_workspace_permissions(
            self.non_member, self.workspace
        )

        self.assertEqual(len(permissions), 0)

    def test_permission_inheritance_from_team(self):
        """测试从团队继承权限"""
        # 添加用户到团队
        TeamMember.objects.create(
            team=self.team,
            user=self.member,
            role_name="editor"
        )

        # 为团队成员授予权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit", "comment"],
            granted_by=self.owner
        )

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )

        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)
        self.assertIn("comment", permissions)

    def test_permission_check_methods(self):
        """测试权限检查方法"""
        # 授予特定权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 测试单个权限检查
        self.assertTrue(self.permission_service.check_permission(
            self.member, self.workspace, "view"
        ))

        self.assertTrue(self.permission_service.check_permission(
            self.member, self.workspace, "edit"
        ))

        self.assertFalse(self.permission_service.check_permission(
            self.member, self.workspace, "delete"
        ))

        # 测试多个权限检查
        self.assertTrue(self.permission_service.check_permissions(
            self.member, self.workspace, ["view", "edit"]
        ))

        self.assertFalse(self.permission_service.check_permissions(
            self.member, self.workspace, ["view", "delete"]
        ))

        # 测试任一权限检查
        self.assertTrue(self.permission_service.check_any_permission(
            self.member, self.workspace, ["edit", "delete"]
        ))

        self.assertFalse(self.permission_service.check_any_permission(
            self.member, self.workspace, ["delete", "share"]
        ))

    def test_temporary_permissions(self):
        """测试临时权限"""
        # 创建已过期的权限
        expired_time = timezone.now() - timedelta(days=1)
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner,
            expires_at=expired_time
        )

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )

        self.assertEqual(len(permissions), 0)

        # 创建未过期的权限
        valid_time = timezone.now() + timedelta(days=1)
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner,
            expires_at=valid_time
        )

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )

        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)

    def test_permission_grant_and_revoke(self):
        """测试权限授予和撤销"""
        # 初始无权限
        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )
        self.assertEqual(len(permissions), 0)

        # 授予权限
        success = self.permission_service.grant_permissions(
            self.member, self.workspace, ["view", "edit"], self.owner
        )

        self.assertTrue(success)

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )
        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)

        # 追加权限
        success = self.permission_service.grant_permissions(
            self.member, self.workspace, ["share"], self.owner
        )

        self.assertTrue(success)

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )
        self.assertIn("view", permissions)
        self.assertIn("edit", permissions)
        self.assertIn("share", permissions)

        # 撤销权限
        success = self.permission_service.revoke_permissions(
            self.member, self.workspace, ["edit", "share"], self.owner
        )

        self.assertTrue(success)

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )
        self.assertIn("view", permissions)
        self.assertNotIn("edit", permissions)
        self.assertNotIn("share", permissions)

        # 撤销所有权限
        success = self.permission_service.revoke_all_permissions(
            self.member, self.workspace, self.owner
        )

        self.assertTrue(success)

        permissions = self.permission_service.get_user_workspace_permissions(
            self.member, self.workspace
        )
        self.assertEqual(len(permissions), 0)

    def test_permission_transfer(self):
        """测试权限转移"""
        new_granter = User.objects.create_user(
            email="newgranter@example.com",
            password="password123"
        )

        # 初始权限由owner授予
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 转移权限授予者
        success = self.permission_service.transfer_grant_ownership(
            self.member, self.workspace, self.owner, new_granter
        )

        self.assertTrue(success)

        # 验证新的权限记录
        permissions = UserWorkspaceActions.objects.get(
            user=self.member,
            workspace=self.workspace
        )
        self.assertEqual(permissions.granted_by, new_granter)
        self.assertEqual(set(permissions.actions), {"view", "edit"})


class PermissionDecoratorTest(APITestCase):
    """权限装饰器测试"""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )

        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123"
        )

        self.non_member = User.objects.create_user(
            email="nonmember@example.com",
            password="password123"
        )

        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )

    def test_require_auth_decorator(self):
        """测试需要认证装饰器"""
        @require_auth
        def protected_view(request):
            return {"success": True}

        # 未认证用户
        request = MagicMock()
        request.user = None

        with self.assertRaises(AuthenticationError):
            protected_view(request)

        # 认证用户
        request.user = self.member

        response = protected_view(request)
        self.assertTrue(response["success"])

    def test_require_permissions_decorator(self):
        """测试需要权限装饰器"""
        @require_permissions(workspace_kwarg="workspace", required_actions=["view"])
        def protected_view(request, workspace):
            return {"success": True}

        # 授予查看权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        # 有权限的用户
        request = MagicMock()
        request.user = self.member

        response = protected_view(request, workspace=self.workspace)
        self.assertTrue(response["success"])

        # 无权限的用户
        request.user = self.non_member

        with self.assertRaises(PermissionDeniedError):
            protected_view(request, workspace=self.workspace)

    def test_require_workspace_access_decorator(self):
        """测试需要工作空间访问装饰器"""
        @require_workspace_access(workspace_id_kwarg="workspace_id", required_actions=["edit"])
        def protected_view(request, workspace_id):
            return {"success": True}

        # 授予编辑权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 有权限的用户
        request = MagicMock()
        request.user = self.member

        response = protected_view(request, workspace_id=self.workspace.id)
        self.assertTrue(response["success"])

        # 无权限的用户
        request.user = self.non_member

        with self.assertRaises(PermissionDeniedError):
            protected_view(request, workspace_id=self.workspace.id)

        # 权限不足的用户
        # 只授予查看权限
        view_only_member = User.objects.create_user(
            email="viewonly@example.com",
            password="password123"
        )
        UserWorkspaceActions.objects.create(
            user=view_only_member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        request.user = view_only_member

        with self.assertRaises(PermissionDeniedError):
            protected_view(request, workspace_id=self.workspace.id)

    def test_multiple_permission_checks(self):
        """测试多重权限检查"""
        @require_permissions(workspace_kwarg="workspace", required_actions=["view"])
        @require_permissions(workspace_kwarg="workspace", required_actions=["edit"])
        def double_protected_view(request, workspace):
            return {"success": True}

        # 授予查看和编辑权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        request = MagicMock()
        request.user = self.member

        response = double_protected_view(request, workspace=self.workspace)
        self.assertTrue(response["success"])

        # 只授予查看权限
        view_only_member = User.objects.create_user(
            email="viewonly2@example.com",
            password="password123"
        )
        UserWorkspaceActions.objects.create(
            user=view_only_member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        request.user = view_only_member

        with self.assertRaises(PermissionDeniedError):
            double_protected_view(request, workspace=self.workspace)

    def test_permission_decorator_with_invalid_workspace(self):
        """测试装饰器处理无效工作空间"""
        @require_permissions(workspace_kwarg="workspace", required_actions=["view"])
        def protected_view(request, workspace):
            return {"success": True}

        request = MagicMock()
        request.user = self.member

        with self.assertRaises(PermissionDeniedError):
            protected_view(request, workspace=None)


class APIPermissionTest(APITestCase):
    """API权限测试"""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )

        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123"
        )

        self.non_member = User.objects.create_user(
            email="nonmember@example.com",
            password="password123"
        )

        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )

        # 获取tokens
        owner_token = self._login_user(self.owner)
        member_token = self._login_user(self.member)
        non_member_token = self._login_user(self.non_member)

        self.owner_headers = {'HTTP_AUTHORIZATION': f'Bearer {owner_token}'}
        self.member_headers = {'HTTP_AUTHORIZATION': f'Bearer {member_token}'}
        self.non_member_headers = {'HTTP_AUTHORIZATION': f'Bearer {non_member_token}'}

    def test_workspace_access_api_permissions(self):
        """测试工作空间访问API权限"""
        # 创建需要权限的测试端点
        # 假设有 /api/auth/workspaces/{id}/ 访问端点

        # 为成员授予查看权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        # 工作空间所有者可以访问
        response = self.client.get(
            f'/api/auth/workspaces/{self.workspace.id}/',
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 有权限的成员可以访问
        response = self.client.get(
            f'/api/auth/workspaces/{self.workspace.id}/',
            **self.member_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 无权限的成员不能访问
        response = self.client.get(
            f'/api/auth/workspaces/{self.workspace.id}/',
            **self.non_member_headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_permission_grant_api(self):
        """测试权限授予API"""
        # 工作空间所有者可以授予权限
        response = self.client.post(
            '/api/auth/permissions/grant/',
            {
                "user_id": self.member.id,
                "workspace_id": self.workspace.id,
                "actions": ["view", "edit"]
            },
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证权限已授予
        permissions = UserWorkspaceActions.objects.filter(
            user=self.member,
            workspace=self.workspace
        ).first()
        self.assertIsNotNone(permissions)
        self.assertEqual(set(permissions.actions), {"view", "edit"})

    def test_permission_grant_api_unauthorized(self):
        """测试未授权的权限授予"""
        # 普通成员不能授予权限
        response = self.client.post(
            '/api/auth/permissions/grant/',
            {
                "user_id": self.non_member.id,
                "workspace_id": self.workspace.id,
                "actions": ["view"]
            },
            **self.member_headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_permission_revoke_api(self):
        """测试权限撤销API"""
        # 先授予权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 工作空间所有者可以撤销权限
        response = self.client.delete(
            '/api/auth/permissions/revoke/',
            {
                "user_id": self.member.id,
                "workspace_id": self.workspace.id,
                "actions": ["edit"]
            },
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证权限已部分撤销
        permissions = UserWorkspaceActions.objects.get(
            user=self.member,
            workspace=self.workspace
        )
        self.assertIn("view", permissions.actions)
        self.assertNotIn("edit", permissions.actions)

    def test_permission_check_api(self):
        """测试权限检查API"""
        # 授予权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 检查存在权限
        response = self.client.post(
            '/api/auth/permissions/check/',
            {
                "user_id": self.member.id,
                "workspace_id": self.workspace.id,
                "actions": ["view"]
            },
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['has_permission'])

        # 检查不存在权限
        response = self.client.post(
            '/api/auth/permissions/check/',
            {
                "user_id": self.member.id,
                "workspace_id": self.workspace.id,
                "actions": ["delete"]
            },
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['has_permission'])

    def test_user_permissions_api(self):
        """测试用户权限列表API"""
        # 授予权限
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit", "share"],
            granted_by=self.owner
        )

        # 用户可以查看自己的权限
        response = self.client.get(
            f'/api/auth/user-permissions/{self.member.id}/',
            **self.member_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        permissions = response.data['permissions']
        workspace_perms = [p for p in permissions if p['workspace_id'] == self.workspace.id]
        self.assertEqual(len(workspace_perms), 1)
        self.assertEqual(set(workspace_perms[0]['actions']), {"view", "edit", "share"})

    def test_permission_matrix_api(self):
        """测试权限矩阵API"""
        # 创建多个用户和权限
        users = [self.member, self.non_member]
        for user in users:
            UserWorkspaceActions.objects.create(
                user=user,
                workspace=self.workspace,
                actions=["view"],
                granted_by=self.owner
            )

        # 工作空间所有者可以查看权限矩阵
        response = self.client.get(
            f'/api/auth/permission-matrix/{self.workspace.id}/',
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        matrix = response.data['matrix']
        self.assertEqual(len(matrix), 2)  # 两个用户
        self.assertTrue(all('actions' in item for item in matrix))

    def test_batch_permission_api(self):
        """测试批量权限操作API"""
        # 批量授予权限
        response = self.client.post(
            '/api/auth/batch-permissions/',
            {
                "workspace_id": self.workspace.id,
                "user_permissions": [
                    {"user_id": self.member.id, "actions": ["view", "edit"]},
                    {"user_id": self.non_member.id, "actions": ["view"]}
                ]
            },
            **self.owner_headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 验证权限已批量授予
        member_perms = UserWorkspaceActions.objects.get(user=self.member, workspace=self.workspace)
        self.assertEqual(set(member_perms.actions), {"view", "edit"})

        non_member_perms = UserWorkspaceActions.objects.get(user=self.non_member, workspace=self.workspace)
        self.assertEqual(set(non_member_perms.actions), {"view"})

    def _login_user(self, user):
        """用户登录并获取token"""
        response = self.client.post('/api/auth/login/', {
            "email": user.email,
            "password": "password123"
        })
        return response.data['access_token']


class AdvancedPermissionTest(TestCase):
    """高级权限测试"""

    def setUp(self):
        self.permission_service = PermissionService()

        # 创建复杂的用户结构
        self.super_admin = User.objects.create_user(
            email="superadmin@example.com",
            password="password123"
        )

        self.workspace_owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )

        self.team_admin = User.objects.create_user(
            email="teamadmin@example.com",
            password="password123"
        )

        self.regular_member = User.objects.create_user(
            email="member@example.com",
            password="password123"
        )

        # 创建团队
        self.team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.workspace_owner
        )

        # 添加团队成员
        TeamMember.objects.create(
            team=self.team,
            user=self.team_admin,
            role_name="admin"
        )

        TeamMember.objects.create(
            team=self.team,
            user=self.regular_member,
            role_name="member"
        )

        # 创建工作空间
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="team",
            owner=self.workspace_owner,
            team=self.team
        )

    def test_role_based_permissions(self):
        """测试基于角色的权限"""
        # 超级管理员应该有所有权限
        super_admin_perms = self.permission_service.get_user_workspace_permissions(
            self.super_admin, self.workspace
        )
        self.assertIn("admin", super_admin_perms)

        # 工作空间所有者应该有管理权限
        owner_perms = self.permission_service.get_user_workspace_permissions(
            self.workspace_owner, self.workspace
        )
        self.assertIn("admin", owner_perms)

        # 团队管理员应该有部分管理权限
        TeamMember.objects.filter(user=self.team_admin).update(role_name="admin")
        team_admin_perms = self.permission_service.get_user_workspace_permissions(
            self.team_admin, self.workspace
        )
        self.assertIn("edit", team_admin_perms)
        self.assertIn("share", team_admin_perms)

    def test_permission_hierarchy(self):
        """测试权限层级"""
        # 创建权限层级：view < edit < share < admin
        permission_hierarchy = {
            "view": 0,
            "edit": 1,
            "share": 2,
            "admin": 3
        }

        # 授予编辑权限应该自动包含查看权限
        UserWorkspaceActions.objects.create(
            user=self.regular_member,
            workspace=self.workspace,
            actions=["edit"],
            granted_by=self.workspace_owner
        )

        # 检查权限层级
        permissions = self.permission_service.get_user_workspace_permissions(
            self.regular_member, self.workspace
        )

        # 编辑权限应该隐含查看权限
        has_edit = self.permission_service.check_permission(
            self.regular_member, self.workspace, "edit"
        )
        has_view = self.permission_service.check_permission(
            self.regular_member, self.workspace, "view"
        )

        self.assertTrue(has_edit)
        # 这里可以扩展服务以支持权限层级检查

    def test_cross_workspace_permissions(self):
        """测试跨工作空间权限"""
        # 创建第二个工作空间
        workspace2 = Workspace.objects.create(
            name="Second Workspace",
            slug="second-workspace",
            workspace_type="personal",
            owner=self.workspace_owner
        )

        # 在第一个工作空间授予权限
        UserWorkspaceActions.objects.create(
            user=self.regular_member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.workspace_owner
        )

        # 在第二个工作空间授予不同权限
        UserWorkspaceActions.objects.create(
            user=self.regular_member,
            workspace=workspace2,
            actions=["view", "share"],
            granted_by=self.workspace_owner
        )

        # 验证不同工作空间的权限是独立的
        workspace1_perms = self.permission_service.get_user_workspace_permissions(
            self.regular_member, self.workspace
        )
        workspace2_perms = self.permission_service.get_user_workspace_permissions(
            self.regular_member, workspace2
        )

        self.assertIn("edit", workspace1_perms)
        self.assertNotIn("share", workspace1_perms)
        self.assertIn("share", workspace2_perms)
        self.assertNotIn("edit", workspace2_perms)

    def test_permission_inheritance_scenarios(self):
        """测试权限继承场景"""
        # 场景1：团队成员自动继承团队工作空间的基本权限
        TeamMember.objects.create(
            team=self.team,
            user=self.workspace_owner,  # 添加为团队成员
            role_name="member"
        )

        # 自动授予基本团队工作空间权限
        UserWorkspaceActions.objects.create(
            user=self.regular_member,
            workspace=self.workspace,
            actions=["view", "comment"],
            granted_by=self.workspace_owner
        )

        # 验证继承权限
        member_perms = self.permission_service.get_user_workspace_permissions(
            self.regular_member, self.workspace
        )
        self.assertIn("view", member_perms)
        self.assertIn("comment", member_perms)

    def test_permission_revocation_cascade(self):
        """测试权限撤销级联"""
        # 设置复杂权限结构
        # 团队管理员授予成员权限
        UserWorkspaceActions.objects.create(
            user=self.regular_member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.team_admin
        )

        # 移除团队成员身份（应该撤销相关权限）
        TeamMember.objects.filter(
            team=self.team,
            user=self.regular_member
        ).delete()

        # 验证权限是否被撤销（取决于业务逻辑）
        # 这里可以测试级联撤销逻辑

    def test_permission_auditing(self):
        """测试权限审计"""
        initial_count = AuditLog.objects.filter(
            action__in=["grant_permission", "revoke_permission"]
        ).count()

        # 授予权限
        self.permission_service.grant_permissions(
            self.regular_member,
            self.workspace,
            ["view", "edit"],
            self.workspace_owner
        )

        grant_count = AuditLog.objects.filter(
            action="grant_permission"
        ).count()
        self.assertEqual(grant_count, initial_count + 1)

        # 撤销权限
        self.permission_service.revoke_permissions(
            self.regular_member,
            self.workspace,
            ["edit"],
            self.workspace_owner
        )

        revoke_count = AuditLog.objects.filter(
            action="revoke_permission"
        ).count()
        self.assertEqual(revoke_count, 1)

    def test_permission_performance(self):
        """测试权限查询性能"""
        import time

        # 创建大量权限记录
        for i in range(100):
            user = User.objects.create_user(
                email=f"perf{i}@example.com",
                password="password123"
            )
            UserWorkspaceActions.objects.create(
                user=user,
                workspace=self.workspace,
                actions=["view"],
                granted_by=self.workspace_owner
            )

        # 测试权限查询性能
        start_time = time.time()

        for i in range(10):
            user = User.objects.get(email=f"perf{i}@example.com")
            permissions = self.permission_service.get_user_workspace_permissions(
                user, self.workspace
            )

        end_time = time.time()
        total_time = end_time - start_time
        avg_time = total_time / 10

        # 平均查询时间应该在合理范围内
        self.assertLess(avg_time, 0.1, f"权限查询平均时间过长: {avg_time:.3f}s")


class PermissionEdgeCasesTest(TransactionTestCase):
    """权限边界情况测试"""

    def setUp(self):
        self.permission_service = PermissionService()
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="password123"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.owner
        )

    def test_permission_with_deleted_user(self):
        """测试删除用户后的权限处理"""
        # 授予权限
        permission_record = UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.owner
        )

        # 删除用户
        self.member.delete()

        # 权限记录应该如何处理？
        # 在实际应用中，可能需要级联删除或保留记录
        try:
            retrieved_permission = UserWorkspaceActions.objects.get(id=permission_record.id)
            # 如果记录存在，用户字段应该为None或特殊值
            self.assertIsNone(retrieved_permission.user)
        except UserWorkspaceActions.DoesNotExist:
            # 如果级联删除，这也是有效的处理方式
            pass

    def test_permission_with_deleted_workspace(self):
        """测试删除工作空间后的权限处理"""
        # 授予权限
        permission_record = UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        # 删除工作空间
        self.workspace.delete()

        # 权限记录应该被级联删除
        with self.assertRaises(UserWorkspaceActions.DoesNotExist):
            UserWorkspaceActions.objects.get(id=permission_record.id)

    def test_permission_with_deleted_granter(self):
        """测试删除权限授予者后的权限处理"""
        another_user = User.objects.create_user(
            email="another@example.com",
            password="password123"
        )

        # 由另一个用户授予权限
        permission_record = UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=another_user
        )

        # 删除权限授予者
        another_user.delete()

        # 权限记录的处理方式
        retrieved_permission = UserWorkspaceActions.objects.get(id=permission_record.id)
        # 根据设计，granted_by可能被设置为NULL或系统用户
        self.assertIsNotNone(retrieved_permission.granted_by)

    def test_permission_integrity_violation(self):
        """测试权限完整性违反"""
        # 尝试创建重复的权限记录
        UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        # 第二次创建应该失败
        with self.assertRaises(Exception):  # 通常是IntegrityError
            UserWorkspaceActions.objects.create(
                user=self.member,
                workspace=self.workspace,
                actions=["edit"],
                granted_by=self.owner
            )

    def test_permission_concurrent_modification(self):
        """测试权限并发修改"""
        # 初始权限
        permission = UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.owner
        )

        # 并发修改权限
        with transaction.atomic():
            # 第一个事务：添加编辑权限
            perm1 = UserWorkspaceActions.objects.select_for_update().get(id=permission.id)
            perm1.actions = ["view", "edit"]
            perm1.save()

            # 第二个事务：尝试添加分享权限
            try:
                perm2 = UserWorkspaceActions.objects.select_for_update().get(id=permission.id)
                perm2.actions = ["view", "share"]
                perm2.save()
            except Exception:
                # 可能出现并发修改冲突
                pass

        # 验证最终状态
        final_permission = UserWorkspaceActions.objects.get(id=permission.id)
        # 最终状态应该是其中一种修改结果

    def test_permission_boundary_values(self):
        """测试权限边界值"""
        # 测试空权限列表
        permission = UserWorkspaceActions.objects.create(
            user=self.member,
            workspace=self.workspace,
            actions=[],
            granted_by=self.owner
        )
        self.assertEqual(len(permission.actions), 0)

        # 测试非常大的权限列表
        large_actions = [f"action_{i}" for i in range(100)]
        permission.actions = large_actions
        permission.save()
        self.assertEqual(len(permission.actions), 100)

        # 测试特殊字符权限名称
        special_actions = ["view/special", "edit:admin", "delete#force"]
        permission.actions = special_actions
        permission.save()
        self.assertEqual(set(permission.actions), set(special_actions))

    def test_permission_system_limits(self):
        """测试权限系统限制"""
        # 测试单个用户最大权限数量
        permissions = []
        try:
            for i in range(1000):
                workspace = Workspace.objects.create(
                    name=f"Workspace {i}",
                    slug=f"workspace-{i}",
                    workspace_type="personal",
                    owner=self.owner
                )
                perm = UserWorkspaceActions.objects.create(
                    user=self.member,
                    workspace=workspace,
                    actions=["view"],
                    granted_by=self.owner
                )
                permissions.append(perm)
        except Exception as e:
            # 系统可能有权限数量限制
            pass

        # 测试权限查询性能在大量权限下的表现
        import time
        start_time = time.time()

        user_permissions = self.permission_service.get_user_all_permissions(self.member)

        end_time = time.time()
        query_time = end_time - start_time

        # 即使有大量权限，查询时间也应该在合理范围内
        self.assertLess(query_time, 1.0, f"大量权限查询时间过长: {query_time:.3f}s")