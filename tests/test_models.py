"""
测试模型和数据库操作
"""

import uuid
from datetime import datetime, timedelta
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import transaction

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService


class UserModelTest(TestCase):
    """测试用户模型"""

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_password = "SecurePassword123!"

    def test_create_user(self):
        """测试创建用户"""
        user = User.objects.create_user(
            email=self.test_email,
            password=self.test_password,
            personal_info={"name": "Test User", "avatar_url": "https://example.com/avatar.jpg"},
            settings={"language": "en", "theme": "dark"}
        )

        self.assertEqual(user.email, self.test_email)
        self.assertTrue(user.check_password(self.test_password))
        self.assertEqual(user.personal_info["name"], "Test User")
        self.assertTrue(user.is_active)
        self.assertIsNotNone(user.created_at)

    def test_user_email_unique(self):
        """测试邮箱唯一性"""
        User.objects.create_user(email=self.test_email, password=self.test_password)

        with self.assertRaises(Exception):  # 应该抛出IntegrityError
            User.objects.create_user(email=self.test_email, password=self.test_password)

    def test_user_str(self):
        """测试用户字符串表示"""
        user = User.objects.create_user(email=self.test_email, password=self.test_password)
        self.assertEqual(str(user), self.test_email)


class TeamTest(TestCase):
    """测试团队模型"""

    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.com", password="password123")
        self.member = User.objects.create_user(email="member@example.com", password="password123")

    def test_create_team(self):
        """测试创建团队"""
        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.owner,
            billing_tier="pro",
            settings={"max_members": 50}
        )

        self.assertEqual(team.name, "Test Team")
        self.assertEqual(team.slug, "test-team")
        self.assertEqual(team.owner, self.owner)
        self.assertEqual(team.billing_tier, "pro")
        self.assertEqual(str(team), "Test Team")

    def test_add_team_member(self):
        """测试添加团队成员"""
        team = Team.objects.create(name="Test Team", slug="test-team", owner=self.owner)

        member = TeamMember.objects.create(
            team=team,
            user=self.member,
            role_name="editor"
        )

        self.assertEqual(member.team, team)
        self.assertEqual(member.user, self.member)
        self.assertEqual(member.role_name, "editor")
        self.assertTrue(member.is_active)


class WorkspaceTest(TestCase):
    """测试工作空间模型"""

    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.com", password="password123")
        self.team = Team.objects.create(name="Test Team", slug="test-team", owner=self.owner)

    def test_create_personal_workspace(self):
        """测试创建个人工作空间"""
        workspace = Workspace.objects.create(
            name="Personal Project",
            slug="personal-project",
            workspace_type="personal",
            owner=self.owner
        )

        self.assertEqual(workspace.name, "Personal Project")
        self.assertEqual(workspace.workspace_type, "personal")
        self.assertEqual(workspace.owner, self.owner)
        self.assertIsNone(workspace.team)
        self.assertEqual(str(workspace), "Personal Project")

    def test_create_team_workspace(self):
        """测试创建团队工作空间"""
        workspace = Workspace.objects.create(
            name="Team Project",
            slug="team-project",
            workspace_type="team",
            owner=self.owner,
            team=self.team
        )

        self.assertEqual(workspace.workspace_type, "team")
        self.assertEqual(workspace.team, self.team)


class UserWorkspaceActionsTest(TestCase):
    """测试用户工作空间权限模型"""

    def setUp(self):
        self.user = User.objects.create_user(email="user@example.com", password="password123")
        self.granter = User.objects.create_user(email="granter@example.com", password="password123")
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.granter
        )

    def test_grant_permissions(self):
        """测试授予权限"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view", "edit", "share"],
            granted_by=self.granter
        )

        self.assertEqual(set(permissions.actions), {"view", "edit", "share"})
        self.assertEqual(permissions.user, self.user)
        self.assertEqual(permissions.workspace, self.workspace)
        self.assertEqual(permissions.granted_by, self.granter)

    def test_unique_user_workspace(self):
        """测试用户工作空间唯一性"""
        UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter
        )

        with self.assertRaises(Exception):  # 应该抛出IntegrityError
            UserWorkspaceActions.objects.create(
                user=self.user,
                workspace=self.workspace,
                actions=["edit"],
                granted_by=self.granter
            )

    def test_temporary_permissions(self):
        """测试临时权限"""
        expires_at = datetime.now() + timedelta(hours=1)

        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter,
            expires_at=expires_at
        )

        self.assertIsNotNone(permissions.expires_at)
        self.assertEqual(permissions.expires_at, expires_at)

    def test_permission_str(self):
        """测试权限字符串表示"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.granter
        )

        expected = f"{self.user.email} -> {self.workspace.name}: ['view', 'edit']"
        self.assertEqual(str(permissions), expected)


class AuditLogTest(TestCase):
    """测试审计日志模型"""

    def setUp(self):
        self.user = User.objects.create_user(email="user@example.com", password="password123")

    def test_create_audit_log(self):
        """测试创建审计日志"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            action="login",
            resource_type="auth",
            details={"ip_address": "127.0.0.1", "user_agent": "test-agent"}
        )

        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.action, "login")
        self.assertEqual(audit_log.resource_type, "auth")
        self.assertEqual(audit_log.details["ip_address"], "127.0.0.1")


class ModelIntegrationTest(TestCase):
    """测试模型集成"""

    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.com", password="password123")
        self.user = User.objects.create_user(email="user@example.com", password="password123")

        self.team = Team.objects.create(name="Test Team", slug="test-team", owner=self.owner)
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="team",
            owner=self.owner,
            team=self.team
        )

    def test_complete_user_workspace_permissions(self):
        """测试完整的用户工作空间权限流程"""
        # 授予权限
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view", "edit", "share"],
            granted_by=self.owner
        )

        # 验证权限
        self.assertEqual(set(permissions.actions), {"view", "edit", "share"})

        # 验证关联
        self.assertEqual(permissions.user.email, "user@example.com")
        self.assertEqual(permissions.workspace.name, "Test Workspace")
        self.assertEqual(permissions.granted_by.email, "owner@example.com")

    def test_team_member_workspace_permissions(self):
        """测试团队成员的工作空间权限"""
        # 添加团队成员
        member = TeamMember.objects.create(
            team=self.team,
            user=self.user,
            role_name="editor"
        )

        # 创建团队工作空间
        workspace = Workspace.objects.create(
            name="Team Project",
            slug="team-project",
            workspace_type="team",
            owner=self.owner,
            team=self.team
        )

        # 自动授予团队成员权限
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=workspace,
            actions=["view", "edit", "comment"],  # 编辑角色权限
            granted_by=self.owner
        )

        # 验证权限正确
        self.assertIn("edit", permissions.actions)
        self.assertIn("view", permissions.actions)
        self.assertIn("comment", permissions.actions)
        self.assertNotIn("delete", permissions.actions)  # 编辑者没有删除权限