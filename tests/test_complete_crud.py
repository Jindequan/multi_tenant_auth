"""
完整的CRUD测试 - 涵盖所有模型的增删改查操作
"""

import uuid
import json
from datetime import datetime, timedelta
from decimal import Decimal
from django.test import TestCase, TransactionTestCase
from django.core.exceptions import ValidationError, IntegrityError
from django.db import transaction, connection
from django.utils import timezone
from unittest.mock import patch, MagicMock

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import AuthenticationError, PermissionDenied, TeamNotFoundError, WorkspaceNotFoundError


class UserModelCRUDTest(TestCase):
    """用户模型完整CRUD测试"""

    def setUp(self):
        self.test_email = "test@example.com"
        self.test_password = "SecurePassword123!"
        self.user_data = {
            "email": self.test_email,
            "password": self.test_password,
            "personal_info": {
                "name": "Test User",
                "avatar_url": "https://example.com/avatar.jpg",
                "phone": "+1234567890"
            },
            "settings": {
                "language": "en",
                "theme": "dark",
                "email_notifications": True
            }
        }

    def test_create_user_complete(self):
        """测试完整创建用户"""
        user = User.objects.create_user(**self.user_data)

        # 验证基本信息
        self.assertEqual(user.email, self.test_email)
        self.assertTrue(user.check_password(self.test_password))
        self.assertTrue(user.is_active)

        # 验证个人信息
        self.assertEqual(user.personal_info["name"], "Test User")
        self.assertEqual(user.personal_info["avatar_url"], "https://example.com/avatar.jpg")
        self.assertEqual(user.personal_info["phone"], "+1234567890")

        # 验证设置
        self.assertEqual(user.settings["language"], "en")
        self.assertEqual(user.settings["theme"], "dark")
        self.assertTrue(user.settings["email_notifications"])

        # 验证时间戳
        self.assertIsNotNone(user.created_at)
        self.assertIsNotNone(user.updated_at)

    def test_read_user(self):
        """测试读取用户"""
        # 创建用户
        created_user = User.objects.create_user(**self.user_data)
        user_id = created_user.id

        # 通过主键读取
        user = User.objects.get(id=user_id)
        self.assertEqual(user.email, self.test_email)

        # 通过邮箱读取
        user = User.objects.get(email=self.test_email)
        self.assertEqual(user.id, user_id)

        # 测试属性访问
        self.assertEqual(user.display_name, "Test User")
        self.assertEqual(user.avatar_url, "https://example.com/avatar.jpg")
        self.assertEqual(user.language, "en")
        self.assertTrue(user.email_notifications_enabled)

    def test_update_user(self):
        """测试更新用户"""
        user = User.objects.create_user(**self.user_data)
        original_updated_at = user.updated_at

        # 更新个人信息
        user.personal_info.update({
            "name": "Updated Name",
            "avatar_url": "https://example.com/new-avatar.jpg"
        })
        user.save()

        updated_user = User.objects.get(id=user.id)
        self.assertEqual(updated_user.personal_info["name"], "Updated Name")
        self.assertEqual(updated_user.personal_info["avatar_url"], "https://example.com/new-avatar.jpg")
        self.assertGreater(updated_user.updated_at, original_updated_at)

        # 更新设置
        updated_user.settings.update({
            "language": "zh",
            "theme": "light"
        })
        updated_user.save()

        final_user = User.objects.get(id=user.id)
        self.assertEqual(final_user.settings["language"], "zh")
        self.assertEqual(final_user.settings["theme"], "light")

    def test_update_password(self):
        """测试更新密码"""
        user = User.objects.create_user(**self.user_data)
        new_password = "NewSecurePassword456!"

        # 使用set_password方法
        user.set_password(new_password)

        # 验证密码已更新
        self.assertTrue(user.check_password(new_password))
        self.assertFalse(user.check_password(self.test_password))

    def test_delete_user(self):
        """测试删除用户"""
        user = User.objects.create_user(**self.user_data)
        user_id = user.id

        # 软删除（设置is_active=False）
        user.is_active = False
        user.save()

        deactivated_user = User.objects.get(id=user_id)
        self.assertFalse(deactivated_user.is_active)

        # 硬删除
        user.delete()

        with self.assertRaises(User.DoesNotExist):
            User.objects.get(id=user_id)

    def test_user_constraints(self):
        """测试用户约束"""
        # 测试邮箱唯一性
        User.objects.create_user(email=self.test_email, password="password123")

        with self.assertRaises(IntegrityError):
            User.objects.create_user(email=self.test_email, password="password456")

        # 测试必填字段
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password="password123")

        with self.assertRaises(ValueError):
            User.objects.create_user(password="password123")

    def test_user_edge_cases(self):
        """测试用户边界情况"""
        # 测试空密码
        user = User.objects.create_user(email="no-password@example.com")
        self.assertIsNotNone(user.password_hash)

        # 测试极长邮箱
        long_email = f"user_{'a' * 100}@example.com"
        user = User.objects.create_user(email=long_email, password="password123")
        self.assertEqual(user.email, long_email)

        # 测试特殊字符邮箱
        special_email = "test+tag@example-domain.com"
        user = User.objects.create_user(email=special_email, password="password123")
        self.assertEqual(user.email, special_email)

    def test_user_bulk_operations(self):
        """测试用户批量操作"""
        # 批量创建
        users_data = [
            {"email": f"user{i}@example.com", "password": "password123"}
            for i in range(10)
        ]

        users = []
        for user_data in users_data:
            user = User.objects.create_user(**user_data)
            users.append(user)

        self.assertEqual(User.objects.count(), 10)

        # 批量更新
        User.objects.filter(id__in=[u.id for u in users[:5]]).update(is_active=False)

        active_count = User.objects.filter(is_active=True).count()
        inactive_count = User.objects.filter(is_active=False).count()
        self.assertEqual(active_count, 5)
        self.assertEqual(inactive_count, 5)

        # 批量删除
        User.objects.filter(id__in=[u.id for u in users[:5]]).delete()
        self.assertEqual(User.objects.count(), 5)


class TeamModelCRUDTest(TestCase):
    """团队模型完整CRUD测试"""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            personal_info={"name": "Team Owner"}
        )
        self.team_data = {
            "name": "Test Team",
            "slug": "test-team",
            "owner": self.owner,
            "billing_tier": "pro",
            "settings": {
                "max_members": 50,
                "allow_public_workspaces": True,
                "default_permissions": ["view", "comment"]
            }
        }

    def test_create_team_complete(self):
        """测试完整创建团队"""
        team = Team.objects.create(**self.team_data)

        # 验证基本信息
        self.assertEqual(team.name, "Test Team")
        self.assertEqual(team.slug, "test-team")
        self.assertEqual(team.owner, self.owner)
        self.assertEqual(team.billing_tier, "pro")

        # 验证设置
        self.assertEqual(team.settings["max_members"], 50)
        self.assertTrue(team.settings["allow_public_workspaces"])
        self.assertEqual(team.settings["default_permissions"], ["view", "comment"])

        # 验证时间戳
        self.assertIsNotNone(team.created_at)
        self.assertIsNotNone(team.updated_at)

    def test_read_team(self):
        """测试读取团队"""
        team = Team.objects.create(**self.team_data)

        # 通过主键读取
        read_team = Team.objects.get(id=team.id)
        self.assertEqual(read_team.name, "Test Team")

        # 通过slug读取
        read_team = Team.objects.get(slug="test-team")
        self.assertEqual(read_team.id, team.id)

        # 通过owner读取
        owner_teams = Team.objects.filter(owner=self.owner)
        self.assertEqual(owner_teams.count(), 1)
        self.assertEqual(owner_teams.first().id, team.id)

    def test_update_team(self):
        """测试更新团队"""
        team = Team.objects.create(**self.team_data)
        original_updated_at = team.updated_at

        # 更新基本信息
        team.name = "Updated Team Name"
        team.billing_tier = "enterprise"
        team.save()

        updated_team = Team.objects.get(id=team.id)
        self.assertEqual(updated_team.name, "Updated Team Name")
        self.assertEqual(updated_team.billing_tier, "enterprise")
        self.assertGreater(updated_team.updated_at, original_updated_at)

        # 更新设置
        updated_team.settings.update({
            "max_members": 100,
            "allow_public_workspaces": False
        })
        updated_team.save()

        final_team = Team.objects.get(id=team.id)
        self.assertEqual(final_team.settings["max_members"], 100)
        self.assertFalse(final_team.settings["allow_public_workspaces"])

    def test_delete_team(self):
        """测试删除团队"""
        team = Team.objects.create(**self.team_data)
        team_id = team.id

        # 硬删除
        team.delete()

        with self.assertRaises(Team.DoesNotExist):
            Team.objects.get(id=team_id)

    def test_team_member_crud(self):
        """测试团队成员CRUD操作"""
        team = Team.objects.create(**self.team_data)
        member = User.objects.create_user(
            email="member@example.com",
            password="password123",
            personal_info={"name": "Team Member"}
        )

        # 创建团队成员
        team_member = TeamMember.objects.create(
            team=team,
            user=member,
            role_name="editor",
            permissions=["view", "edit", "comment"]
        )

        self.assertEqual(team_member.team, team)
        self.assertEqual(team_member.user, member)
        self.assertEqual(team_member.role_name, "editor")
        self.assertEqual(set(team_member.permissions), {"view", "edit", "comment"})

        # 更新团队成员
        team_member.role_name = "admin"
        team_member.permissions = ["view", "edit", "delete", "share"]
        team_member.save()

        updated_member = TeamMember.objects.get(id=team_member.id)
        self.assertEqual(updated_member.role_name, "admin")
        self.assertEqual(set(updated_member.permissions), {"view", "edit", "delete", "share"})

        # 删除团队成员
        team_member.delete()

        with self.assertRaises(TeamMember.DoesNotExist):
            TeamMember.objects.get(id=team_member.id)

    def test_team_constraints(self):
        """测试团队约束"""
        # 测试团队slug唯一性
        Team.objects.create(
            name="Team 1",
            slug="unique-slug",
            owner=self.owner
        )

        with self.assertRaises(IntegrityError):
            Team.objects.create(
                name="Team 2",
                slug="unique-slug",
                owner=self.owner
            )

        # 测试团队成员唯一性
        team = Team.objects.create(name="Team", slug="team", owner=self.owner)
        member = User.objects.create_user(email="member@example.com", password="password123")

        TeamMember.objects.create(
            team=team,
            user=member,
            role_name="member"
        )

        with self.assertRaises(IntegrityError):
            TeamMember.objects.create(
                team=team,
                user=member,
                role_name="editor"
            )

    def test_team_edge_cases(self):
        """测试团队边界情况"""
        # 测试无owner的团队（应该失败）
        with self.assertRaises(IntegrityError):
            Team.objects.create(
                name="No Owner Team",
                slug="no-owner",
                owner=None
            )

        # 测试空权限列表
        team = Team.objects.create(**self.team_data)
        member = User.objects.create_user(email="member@example.com", password="password123")

        team_member = TeamMember.objects.create(
            team=team,
            user=member,
            role_name="viewer",
            permissions=[]
        )

        self.assertEqual(team_member.permissions, [])


class WorkspaceModelCRUDTest(TestCase):
    """工作空间模型完整CRUD测试"""

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123"
        )
        self.team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.owner
        )
        self.workspace_data = {
            "name": "Test Workspace",
            "slug": "test-workspace",
            "workspace_type": "personal",
            "owner": self.owner,
            "settings": {
                "is_public": False,
                "allow_comments": True,
                "max_file_size": 10485760
            }
        }

    def test_create_personal_workspace(self):
        """测试创建个人工作空间"""
        workspace = Workspace.objects.create(**self.workspace_data)

        self.assertEqual(workspace.name, "Test Workspace")
        self.assertEqual(workspace.workspace_type, "personal")
        self.assertEqual(workspace.owner, self.owner)
        self.assertIsNone(workspace.team)

    def test_create_team_workspace(self):
        """测试创建团队工作空间"""
        workspace_data = self.workspace_data.copy()
        workspace_data.update({
            "name": "Team Workspace",
            "slug": "team-workspace",
            "workspace_type": "team",
            "team": self.team
        })

        workspace = Workspace.objects.create(**workspace_data)

        self.assertEqual(workspace.workspace_type, "team")
        self.assertEqual(workspace.team, self.team)

    def test_read_workspace(self):
        """测试读取工作空间"""
        workspace = Workspace.objects.create(**self.workspace_data)

        # 通过主键读取
        read_workspace = Workspace.objects.get(id=workspace.id)
        self.assertEqual(read_workspace.name, "Test Workspace")

        # 通过slug读取
        read_workspace = Workspace.objects.get(slug="test-workspace")
        self.assertEqual(read_workspace.id, workspace.id)

        # 通过owner读取
        owner_workspaces = Workspace.objects.filter(owner=self.owner)
        self.assertEqual(owner_workspaces.count(), 1)

    def test_update_workspace(self):
        """测试更新工作空间"""
        workspace = Workspace.objects.create(**self.workspace_data)

        # 更新基本信息
        workspace.name = "Updated Workspace"
        workspace.workspace_type = "team"
        workspace.team = self.team
        workspace.save()

        updated_workspace = Workspace.objects.get(id=workspace.id)
        self.assertEqual(updated_workspace.name, "Updated Workspace")
        self.assertEqual(updated_workspace.workspace_type, "team")
        self.assertEqual(updated_workspace.team, self.team)

    def test_delete_workspace(self):
        """测试删除工作空间"""
        workspace = Workspace.objects.create(**self.workspace_data)
        workspace_id = workspace.id

        workspace.delete()

        with self.assertRaises(Workspace.DoesNotExist):
            Workspace.objects.get(id=workspace_id)

    def test_workspace_constraints(self):
        """测试工作空间约束"""
        # 测试slug唯一性
        Workspace.objects.create(**self.workspace_data)

        with self.assertRaises(IntegrityError):
            Workspace.objects.create(**self.workspace_data)


class UserWorkspaceActionsCRUDTest(TestCase):
    """用户工作空间权限模型完整CRUD测试"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            password="password123"
        )
        self.granter = User.objects.create_user(
            email="granter@example.com",
            password="password123"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="personal",
            owner=self.granter
        )

    def test_create_permissions_complete(self):
        """测试完整创建权限"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view", "edit", "share", "delete"],
            granted_by=self.granter,
            expires_at=timezone.now() + timedelta(days=30)
        )

        self.assertEqual(set(permissions.actions), {"view", "edit", "share", "delete"})
        self.assertEqual(permissions.user, self.user)
        self.assertEqual(permissions.workspace, self.workspace)
        self.assertEqual(permissions.granted_by, self.granter)
        self.assertIsNotNone(permissions.expires_at)

    def test_read_permissions(self):
        """测试读取权限"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view", "edit"],
            granted_by=self.granter
        )

        # 通过主键读取
        read_permissions = UserWorkspaceActions.objects.get(id=permissions.id)
        self.assertEqual(set(read_permissions.actions), {"view", "edit"})

        # 通过用户和工作空间读取
        specific_permissions = UserWorkspaceActions.objects.get(
            user=self.user,
            workspace=self.workspace
        )
        self.assertEqual(specific_permissions.id, permissions.id)

    def test_update_permissions(self):
        """测试更新权限"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter
        )

        # 更新权限列表
        permissions.actions = ["view", "edit", "share"]
        permissions.save()

        updated_permissions = UserWorkspaceActions.objects.get(id=permissions.id)
        self.assertEqual(set(updated_permissions.actions), {"view", "edit", "share"})

        # 更新过期时间
        new_expires_at = timezone.now() + timedelta(days=60)
        permissions.expires_at = new_expires_at
        permissions.save()

        final_permissions = UserWorkspaceActions.objects.get(id=permissions.id)
        self.assertEqual(final_permissions.expires_at, new_expires_at)

    def test_delete_permissions(self):
        """测试删除权限"""
        permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter
        )
        permissions_id = permissions.id

        permissions.delete()

        with self.assertRaises(UserWorkspaceActions.DoesNotExist):
            UserWorkspaceActions.objects.get(id=permissions_id)

    def test_permissions_constraints(self):
        """测试权限约束"""
        # 测试用户工作空间唯一性
        UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter
        )

        with self.assertRaises(IntegrityError):
            UserWorkspaceActions.objects.create(
                user=self.user,
                workspace=self.workspace,
                actions=["edit"],
                granted_by=self.granter
            )

    def test_temporary_permissions(self):
        """测试临时权限"""
        # 创建已过期的权限
        past_time = timezone.now() - timedelta(days=1)
        expired_permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.granter,
            expires_at=past_time
        )

        # 创建未过期的权限
        future_time = timezone.now() + timedelta(days=1)
        valid_permissions = UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions=["edit"],
            granted_by=self.granter,
            expires_at=future_time
        )

        # 查询有效权限
        valid_count = UserWorkspaceActions.objects.filter(
            expires_at__gt=timezone.now()
        ).count()
        self.assertEqual(valid_count, 1)


class AuditLogCRUDTest(TestCase):
    """审计日志模型完整CRUD测试"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            password="password123"
        )

    def test_create_audit_log_complete(self):
        """测试完整创建审计日志"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            action="login",
            resource_type="auth",
            resource_id=str(self.user.id),
            details={
                "ip_address": "127.0.0.1",
                "user_agent": "Mozilla/5.0...",
                "success": True,
                "timestamp": timezone.now().isoformat()
            }
        )

        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.action, "login")
        self.assertEqual(audit_log.resource_type, "auth")
        self.assertEqual(audit_log.resource_id, str(self.user.id))
        self.assertEqual(audit_log.details["ip_address"], "127.0.0.1")
        self.assertTrue(audit_log.details["success"])

    def test_read_audit_log(self):
        """测试读取审计日志"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            action="create_workspace",
            resource_type="workspace",
            details={"workspace_name": "Test Workspace"}
        )

        # 通过主键读取
        read_audit = AuditLog.objects.get(id=audit_log.id)
        self.assertEqual(read_audit.action, "create_workspace")

        # 通过用户过滤
        user_audits = AuditLog.objects.filter(user=self.user)
        self.assertEqual(user_audits.count(), 1)

        # 通过动作过滤
        login_audits = AuditLog.objects.filter(action="login")
        self.assertEqual(login_audits.count(), 0)

    def test_audit_log_ordering(self):
        """测试审计日志排序"""
        # 创建多个日志条目
        for i in range(5):
            AuditLog.objects.create(
                user=self.user,
                action=f"action_{i}",
                resource_type="test",
                details={"index": i}
            )

        # 按时间排序（最新的在前）
        latest_audit = AuditLog.objects.latest('created_at')
        self.assertEqual(latest_audit.action, "action_4")

        # 按时间排序（最旧的在前）
        oldest_audit = AuditLog.objects.earliest('created_at')
        self.assertEqual(oldest_audit.action, "action_0")

    def test_delete_audit_log(self):
        """测试删除审计日志（通常不应该删除，但测试数据库约束）"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            action="test_action",
            resource_type="test"
        )
        audit_log_id = audit_log.id

        # 在实际应用中，审计日志通常不应该被删除
        # 但这里测试数据库约束
        audit_log.delete()

        with self.assertRaises(AuditLog.DoesNotExist):
            AuditLog.objects.get(id=audit_log_id)


class ModelConstraintsAndEdgeCasesTest(TransactionTestCase):
    """模型约束和边界情况测试"""

    def setUp(self):
        self.users = []
        for i in range(3):
            user = User.objects.create_user(
                email=f"user{i}@example.com",
                password="password123"
            )
            self.users.append(user)

    def test_foreign_key_constraints(self):
        """测试外键约束"""
        # 创建团队
        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.users[0]
        )

        # 创建工作空间
        workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            workspace_type="team",
            owner=self.users[0],
            team=team
        )

        # 尝试删除被引用的团队（应该失败，因为有外键约束）
        with self.assertRaises(IntegrityError):
            team.delete()

        # 先删除工作空间，再删除团队
        workspace.delete()
        team.delete()  # 现在应该成功

    def test_cascade_delete_behavior(self):
        """测试级联删除行为"""
        team = Team.objects.create(
            name="Test Team",
            slug="test-team",
            owner=self.users[0]
        )

        # 添加团队成员
        member = TeamMember.objects.create(
            team=team,
            user=self.users[1],
            role_name="member"
        )

        # 删除团队应该级联删除团队成员
        team.delete()

        with self.assertRaises(TeamMember.DoesNotExist):
            TeamMember.objects.get(id=member.id)

    def test_database_transaction_rollback(self):
        """测试数据库事务回滚"""
        try:
            with transaction.atomic():
                # 创建用户
                user = User.objects.create_user(
                    email="transaction@example.com",
                    password="password123"
                )

                # 故意违反约束
                User.objects.create_user(
                    email="transaction@example.com",  # 重复邮箱
                    password="password456"
                )
        except IntegrityError:
            pass  # 预期的错误

        # 验证事务已回滚，用户没有被创建
        with self.assertRaises(User.DoesNotExist):
            User.objects.get(email="transaction@example.com")

    def test_concurrent_operations(self):
        """测试并发操作"""
        team = Team.objects.create(
            name="Concurrent Team",
            slug="concurrent-team",
            owner=self.users[0]
        )

        # 模拟并发添加同一个用户到团队
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                TeamMember.objects.create(
                    team=team,
                    user=self.users[1],
                    role_name="member"
                )

                # 尝试再次添加同一个用户
                TeamMember.objects.create(
                    team=team,
                    user=self.users[1],
                    role_name="editor"
                )

    def test_json_field_validation(self):
        """测试JSON字段验证"""
        # 测试无效JSON（应该失败）
        with self.assertRaises(ValueError):
            user = User.objects.create_user(
                email="json@example.com",
                password="password123"
            )
            # 直接操作数据库以绕过Django的JSON验证
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE "multi_tenant_auth"."user"
                    SET personal_info = 'invalid json'
                    WHERE id = %s
                """, [user.id])

    def test_large_data_handling(self):
        """测试大数据处理"""
        # 创建包含大量数据的用户
        large_data = {
            "name": "A" * 1000,
            "description": "B" * 5000,
            "metadata": {"key" + str(i): "value" + str(i) for i in range(100)}
        }

        user = User.objects.create_user(
            email="large-data@example.com",
            password="password123",
            personal_info=large_data
        )

        # 读取并验证大数据
        retrieved_user = User.objects.get(id=user.id)
        self.assertEqual(retrieved_user.personal_info["name"], "A" * 1000)
        self.assertEqual(len(retrieved_user.personal_info["metadata"]), 100)