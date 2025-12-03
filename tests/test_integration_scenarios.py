"""
集成测试 - 测试完整的业务流程和组件集成
"""

import uuid
import json
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..exceptions import AuthenticationError, PermissionDeniedError
from ..views import (
    RegisterView, LoginView, LogoutView, ProfileView,
    WorkspaceListView, WorkspaceDetailView, TeamListView,
    TeamDetailView, PermissionCheckView, UserListView
)

User = get_user_model()


class CompleteUserFlowTest(APITestCase):
    """完整用户流程测试"""

    def setUp(self):
        self.auth_service = AuthService()
        self.permission_service = PermissionService()
        self.team_service = TeamService()

    def test_new_user_complete_journey(self):
        """测试新用户完整旅程"""
        # 1. 用户注册
        registration_data = {
            "email": "journey@example.com",
            "password": "JourneyPassword123!",
            "personal_info": {
                "name": "Journey User",
                "avatar_url": "https://example.com/avatar.jpg"
            }
        }

        response = self.client.post('/api/auth/register/', registration_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        self.assertIsNotNone(response.data.get('access_token'))
        self.assertIsNotNone(response.data.get('refresh_token'))

        access_token = response.data['access_token']
        refresh_token = response.data['refresh_token']
        user_id = response.data['user']['id']

        # 2. 验证用户已创建
        user = User.objects.get(id=user_id)
        self.assertEqual(user.email, "journey@example.com")
        self.assertEqual(user.personal_info["name"], "Journey User")
        self.assertTrue(user.is_active)

        # 3. 使用token访问受保护的端点
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        # 获取用户信息
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], "journey@example.com")
        self.assertEqual(response.data['personal_info']['name'], "Journey User")

        # 4. 创建个人工作空间
        workspace_data = {
            "name": "My Personal Workspace",
            "slug": "my-personal-workspace",
            "workspace_type": "personal",
            "settings": {
                "is_public": False,
                "allow_comments": True
            }
        }

        response = self.client.post('/api/auth/workspaces/', workspace_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        workspace_id = response.data['workspace']['id']

        # 5. 验证工作空间创建
        workspace = Workspace.objects.get(id=workspace_id)
        self.assertEqual(workspace.name, "My Personal Workspace")
        self.assertEqual(workspace.owner, user)
        self.assertEqual(workspace.workspace_type, "personal")

        # 6. 获取工作空间列表
        response = self.client.get('/api/auth/workspaces/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['workspaces']), 1)
        self.assertEqual(response.data['workspaces'][0]['id'], workspace_id)

        # 7. 获取工作空间详情
        response = self.client.get(f'/api/auth/workspaces/{workspace_id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['workspace']['name'], "My Personal Workspace")

        # 8. 更新用户信息
        update_data = {
            "personal_info": {
                "name": "Updated Journey User",
                "bio": "This is my bio",
                "language": "zh"
            },
            "settings": {
                "email_notifications": False,
                "theme": "dark"
            }
        }

        response = self.client.patch('/api/auth/profile/', update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['personal_info']['name'], "Updated Journey User")
        self.assertEqual(response.data['personal_info']['language'], "zh")

        # 9. 修改密码
        password_data = {
            "old_password": "JourneyPassword123!",
            "new_password": "NewJourneyPassword456!"
        }

        response = self.client.post('/api/auth/change-password/', password_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 10. 验证密码已更改
        updated_user = User.objects.get(id=user_id)
        self.assertTrue(updated_user.check_password("NewJourneyPassword456!"))
        self.assertFalse(updated_user.check_password("JourneyPassword123!"))

        # 11. 刷新token
        response = self.client.post('/api/auth/refresh/', {
            "refresh": refresh_token
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        new_access_token = response.data['access_token']

        # 12. 验证新token有效
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 13. 登出
        response = self.client.post('/api/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 14. 验证token已失效
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_team_based_workflow(self):
        """测试基于团队的工作流程"""
        # 1. 创建团队所有者
        owner_data = {
            "email": "teamowner@example.com",
            "password": "TeamOwnerPassword123!",
            "personal_info": {"name": "Team Owner"}
        }

        response = self.client.post('/api/auth/register/', owner_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        owner_token = response.data['access_token']
        owner_id = response.data['user']['id']

        # 2. 创建团队成员
        member_data = {
            "email": "teammember@example.com",
            "password": "TeamMemberPassword123!",
            "personal_info": {"name": "Team Member"}
        }

        response = self.client.post('/api/auth/register/', member_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        member_id = response.data['user']['id']

        # 3. 所有者创建团队
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {owner_token}')
        team_data = {
            "name": "Development Team",
            "slug": "dev-team",
            "billing_tier": "pro",
            "settings": {
                "max_members": 10,
                "allow_public_workspaces": True
            }
        }

        response = self.client.post('/api/auth/teams/', team_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        team_id = response.data['team']['id']

        # 4. 所有者创建团队工作空间
        workspace_data = {
            "name": "Team Project",
            "slug": "team-project",
            "workspace_type": "team",
            "team_id": team_id,
            "settings": {
                "is_public": True,
                "allow_comments": True
            }
        }

        response = self.client.post('/api/auth/workspaces/', workspace_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        workspace_id = response.data['workspace']['id']

        # 5. 所有者邀请成员加入团队
        invite_data = {
            "user_id": member_id,
            "role_name": "developer"
        }

        response = self.client.post(f'/api/auth/teams/{team_id}/invite/', invite_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 6. 验证团队成员已添加
        team_member = TeamMember.objects.get(team_id=team_id, user_id=member_id)
        self.assertEqual(team_member.role_name, "developer")
        self.assertTrue(team_member.is_active)

        # 7. 所有者为成员授予工作空间权限
        permission_data = {
            "user_id": member_id,
            "workspace_id": workspace_id,
            "actions": ["view", "edit", "comment"]
        }

        response = self.client.post('/api/auth/permissions/grant/', permission_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 8. 成员登录并验证权限
        member_client = APIClient()
        response = member_client.post('/api/auth/login/', {
            "email": "teammember@example.com",
            "password": "TeamMemberPassword123!"
        })
        member_token = response.data['access_token']
        member_client.credentials(HTTP_AUTHORIZATION=f'Bearer {member_token}')

        # 9. 成员尝试访问团队工作空间
        response = member_client.get(f'/api/auth/workspaces/{workspace_id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['workspace']['name'], "Team Project")

        # 10. 成员检查自己的权限
        response = member_client.post('/api/auth/permissions/check/', {
            "workspace_id": workspace_id,
            "actions": ["view", "edit", "delete"]
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['has_permission']['view'])
        self.assertTrue(response.data['has_permission']['edit'])
        self.assertFalse(response.data['has_permission']['delete'])

        # 11. 成员查看所属团队
        response = member_client.get('/api/auth/teams/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['teams']), 1)
        self.assertEqual(response.data['teams'][0]['name'], "Development Team")

        # 12. 成员查看团队成员
        response = member_client.get(f'/api/auth/teams/{team_id}/members/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        members = response.data['members']
        self.assertEqual(len(members), 2)  # 所有者和成员

        # 13. 成员尝试创建自己的个人工作空间
        personal_workspace_data = {
            "name": "My Personal Project",
            "slug": "my-personal-project",
            "workspace_type": "personal"
        }

        response = member_client.post('/api/auth/workspaces/', personal_workspace_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        personal_workspace_id = response.data['workspace']['id']

        # 14. 验证工作空间所有权
        response = member_client.get('/api/auth/workspaces/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        workspaces = response.data['workspaces']
        self.assertEqual(len(workspaces), 2)  # 团队工作空间 + 个人工作空间


class PermissionWorkflowTest(APITestCase):
    """权限工作流测试"""

    def setUp(self):
        # 创建用户
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="password123",
            personal_info={"name": "Workspace Owner"}
        )

        self.admin = User.objects.create_user(
            email="admin@example.com",
            password="password123",
            personal_info={"name": "Workspace Admin"}
        )

        self.editor = User.objects.create_user(
            email="editor@example.com",
            password="password123",
            personal_info={"name": "Content Editor"}
        )

        self.viewer = User.objects.create_user(
            email="viewer@example.com",
            password="password123",
            personal_info={"name": "Content Viewer"}
        )

        # 创建工作空间
        self.workspace = Workspace.objects.create(
            name="Shared Workspace",
            slug="shared-workspace",
            workspace_type="personal",
            owner=self.owner
        )

        self.auth_service = AuthService()
        self.permission_service = PermissionService()

        # 获取tokens
        self.owner_token = self._get_user_token(self.owner)
        self.admin_token = self._get_user_token(self.admin)
        self.editor_token = self._get_user_token(self.editor)
        self.viewer_token = self._get_user_token(self.viewer)

    def _get_user_token(self, user):
        """获取用户token"""
        response = self.client.post('/api/auth/login/', {
            "email": user.email,
            "password": "password123"
        })
        return response.data['access_token']

    def test_comprehensive_permission_management(self):
        """测试全面的权限管理"""
        # 1. 所有者为管理员授予所有权限
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.owner_token}')
        admin_permissions = {
            "user_id": self.admin.id,
            "workspace_id": self.workspace.id,
            "actions": ["view", "edit", "share", "delete", "admin"]
        }

        response = self.client.post('/api/auth/permissions/grant/', admin_permissions)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 2. 管理员为编辑者授予编辑权限
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        editor_permissions = {
            "user_id": self.editor.id,
            "workspace_id": self.workspace.id,
            "actions": ["view", "edit", "comment"]
        }

        response = self.client.post('/api/auth/permissions/grant/', editor_permissions)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 3. 管理员为查看者授予查看权限
        viewer_permissions = {
            "user_id": self.viewer.id,
            "workspace_id": self.workspace.id,
            "actions": ["view"]
        }

        response = self.client.post('/api/auth/permissions/grant/', viewer_permissions)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

        # 4. 验证权限矩阵
        response = self.client.get(f'/api/auth/permission-matrix/{self.workspace.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        matrix = response.data['matrix']
        permissions_by_user = {p['user_id']: set(p['actions']) for p in matrix}

        # 验证各个用户的权限
        self.assertIn("admin", permissions_by_user.get(self.admin.id, set()))
        self.assertIn("edit", permissions_by_user.get(self.editor.id, set()))
        self.assertIn("view", permissions_by_user.get(self.viewer.id, set()))
        self.assertNotIn("delete", permissions_by_user.get(self.editor.id, set()))
        self.assertNotIn("edit", permissions_by_user.get(self.viewer.id, set()))

        # 5. 测试权限升级 - 编辑者升级为可以分享
        upgrade_permissions = {
            "user_id": self.editor.id,
            "workspace_id": self.workspace.id,
            "actions": ["share"]
        }

        response = self.client.post('/api/auth/permissions/grant/', upgrade_permissions)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 6. 验证权限升级
        response = self.client.get(f'/api/auth/user-permissions/{self.editor.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        editor_permissions = response.data['permissions'][0]  # 应该只有一个工作空间
        self.assertIn("view", editor_permissions['actions'])
        self.assertIn("edit", editor_permissions['actions'])
        self.assertIn("comment", editor_permissions['actions'])
        self.assertIn("share", editor_permissions['actions'])

        # 7. 测试权限降级 - 查看者撤销权限（临时测试）
        revoke_permissions = {
            "user_id": self.viewer.id,
            "workspace_id": self.workspace.id,
            "actions": ["view"]
        }

        response = self.client.delete('/api/auth/permissions/revoke/', revoke_permissions)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 8. 验证权限撤销
        response = self.client.post('/api/auth/permissions/check/', {
            "user_id": self.viewer.id,
            "workspace_id": self.workspace.id,
            "actions": ["view"]
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['has_permission']['view'])

        # 9. 测试临时权限 - 重新授予查看者临时权限
        from django.utils import timezone
        future_time = timezone.now() + timedelta(hours=1)

        # 需要直接使用服务或自定义API来设置过期时间
        self.permission_service.grant_permissions(
            user=self.viewer,
            workspace=self.workspace,
            actions=["view"],
            granted_by=self.admin,
            expires_at=future_time
        )

        # 10. 验证临时权限有效
        response = self.client.post('/api/auth/permissions/check/', {
            "user_id": self.viewer.id,
            "workspace_id": self.workspace.id,
            "actions": ["view"]
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['has_permission']['view'])

    def test_permission_inheritance_workflow(self):
        """测试权限继承工作流"""
        # 1. 创建团队
        team_data = {
            "name": "Inheritance Team",
            "slug": "inheritance-team",
            "billing_tier": "pro"
        }

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.owner_token}')
        response = self.client.post('/api/auth/teams/', team_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        team_id = response.data['team']['id']

        # 2. 创建团队工作空间
        team_workspace_data = {
            "name": "Team Inheritance Workspace",
            "slug": "team-inheritance-workspace",
            "workspace_type": "team",
            "team_id": team_id
        }

        response = self.client.post('/api/auth/workspaces/', team_workspace_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        team_workspace_id = response.data['workspace']['id']

        # 3. 添加用户到团队
        team_member_data = {
            "user_id": self.editor.id,
            "role_name": "developer"
        }

        response = self.client.post(f'/api/auth/teams/{team_id}/members/', team_member_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 4. 为团队成员授予团队工作空间权限
        response = self.client.post('/api/auth/permissions/grant/', {
            "user_id": self.editor.id,
            "workspace_id": team_workspace_id,
            "actions": ["view", "edit", "comment"]
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. 验证团队成员可以访问团队工作空间
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.editor_token}')
        response = self.client.get(f'/api/auth/workspaces/{team_workspace_id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 6. 验证团队成员信息包含团队角色
        response = self.client.get('/api/auth/teams/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        teams = response.data['teams']
        self.assertEqual(len(teams), 1)
        self.assertEqual(teams[0]['role'], "developer")


class SystemManagementTest(APITestCase):
    """系统管理测试"""

    def setUp(self):
        # 创建超级用户
        self.superuser = User.objects.create_user(
            email="superuser@example.com",
            password="superpassword123",
            personal_info={"name": "Super User", "is_superuser": True}
        )

        # 普通用户
        self.normal_user = User.objects.create_user(
            email="normal@example.com",
            password="normalpassword123",
            personal_info={"name": "Normal User"}
        )

        self.superuser_token = self._get_user_token(self.superuser)
        self.normal_user_token = self._get_user_token(self.normal_user)

    def _get_user_token(self, user):
        """获取用户token"""
        response = self.client.post('/api/auth/login/', {
            "email": user.email,
            "password": user.password if hasattr(user, 'password') else "password123"
        })
        return response.data['access_token']

    def test_system_administration(self):
        """测试系统管理功能"""
        # 1. 超级用户访问用户管理
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.superuser_token}')

        response = self.client.get('/api/auth/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        users = response.data['users']
        self.assertEqual(len(users), 2)  # 超级用户和普通用户

        # 2. 获取用户统计
        response = self.client.get('/api/auth/user-stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        stats = response.data['stats']
        self.assertIn('total_users', stats)
        self.assertIn('active_users', stats)
        self.assertIn('new_users_today', stats)

        # 3. 获取活动日志
        response = self.client.get('/api/auth/activity/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        activities = response.data['activities']
        self.assertIsInstance(activities, list)

        # 4. 获取系统配置
        response = self.client.get('/api/auth/config/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        config = response.data['config']
        self.assertIn('version', config)
        self.assertIn('features', config)

        # 5. 健康检查
        response = self.client.get('/api/auth/health/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        health = response.data['health']
        self.assertEqual(health['status'], 'healthy')

    def test_permission_denied_for_normal_user(self):
        """测试普通用户权限被拒绝"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.normal_user_token}')

        # 普通用户尝试访问管理端点
        admin_endpoints = [
            '/api/auth/users/',
            '/api/auth/user-stats/',
            '/api/auth/activity/',
            '/api/auth/config/'
        ]

        for endpoint in admin_endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                # 根据具体实现，可能是403或404
                self.assertIn(response.status_code, [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND])

    def test_system_monitoring(self):
        """测试系统监控"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.superuser_token}')

        # 模拟系统活动
        for i in range(10):
            AuditLog.objects.create(
                user=self.normal_user,
                action="test_action",
                resource_type="test",
                details={"index": i}
            )

        # 获取活动日志
        response = self.client.get('/api/auth/activity/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        activities = response.data['activities']
        self.assertGreaterEqual(len(activities), 10)

        # 测试分页
        response = self.client.get('/api/auth/activity/?limit=5')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        activities = response.data['activities']
        self.assertEqual(len(activities), 5)


class ErrorHandlingIntegrationTest(APITestCase):
    """错误处理集成测试"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            password="password123"
        )
        self.token = self._get_user_token(self.user)

    def _get_user_token(self, user):
        """获取用户token"""
        response = self.client.post('/api/auth/login/', {
            "email": user.email,
            "password": "password123"
        })
        return response.data['access_token']

    def test_comprehensive_error_scenarios(self):
        """测试全面的错误场景"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 1. 测试资源不存在
        response = self.client.get('/api/auth/workspaces/99999/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # 2. 测试无效数据
        response = self.client.post('/api/auth/workspaces/', {
            "name": "",  # 空名称
            "workspace_type": "invalid_type"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 3. 测试权限不足
        other_user = User.objects.create_user(
            email="other@example.com",
            password="password123"
        )
        other_workspace = Workspace.objects.create(
            name="Other Workspace",
            slug="other-workspace",
            workspace_type="personal",
            owner=other_user
        )

        response = self.client.get(f'/api/auth/workspaces/{other_workspace.id}/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # 4. 测试认证错误
        self.client.credentials()  # 清除认证
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 5. 测试方法不允许
        response = self.client.put('/api/auth/register/')
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # 6. 测试速率限制（如果实现）
        # 连续快速请求
        for i in range(10):
            response = self.client.post('/api/auth/login/', {
                "email": "user@example.com",
                "password": "wrongpassword"
            })
            if response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                break  # 速率限制触发

        # 7. 测试媒体类型不支持
        response = self.client.post(
            '/api/auth/register/',
            json.dumps({"email": "test@example.com", "password": "password123"}),
            content_type='text/plain'  # 错误的content-type
        )
        self.assertEqual(response.status_code, status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)


class WorkflowIntegrationTest(TransactionTestCase):
    """工作流集成测试"""

    def test_complete_multi_tenant_workflow(self):
        """测试完整的多租户工作流"""
        # 1. 租户管理员注册
        admin_client = APIClient()
        response = admin_client.post('/api/auth/register/', {
            "email": "tenant-admin@example.com",
            "password": "AdminPassword123!",
            "personal_info": {"name": "Tenant Admin"}
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        admin_token = response.data['access_token']

        # 2. 创建租户团队
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_token}')
        response = admin_client.post('/api/auth/teams/', {
            "name": "Acme Corp Team",
            "slug": "acme-corp",
            "billing_tier": "enterprise"
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        team_id = response.data['team']['id']

        # 3. 创建租户工作空间
        response = admin_client.post('/api/auth/workspaces/', {
            "name": "Acme Main Project",
            "slug": "acme-main",
            "workspace_type": "team",
            "team_id": team_id
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        workspace_id = response.data['workspace']['id']

        # 4. 批量创建团队成员
        member_clients = []
        member_tokens = []
        member_ids = []

        for i in range(5):
            member_email = f"member{i}@acme.com"
            response = admin_client.post('/api/auth/register/', {
                "email": member_email,
                "password": "MemberPassword123!",
                "personal_info": {"name": f"Acme Member {i}"}
            })
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            member_id = response.data['user']['id']
            member_ids.append(member_id)

            # 添加到团队
            response = admin_client.post(f'/api/auth/teams/{team_id}/members/', {
                "user_id": member_id,
                "role_name": "employee" if i < 3 else "manager"
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            # 成员登录
            member_client = APIClient()
            response = member_client.post('/api/auth/login/', {
                "email": member_email,
                "password": "MemberPassword123!"
            })
            member_tokens.append(response.data['access_token'])
            member_clients.append(member_client)

        # 5. 批量权限分配
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_token}')
        for i, member_id in enumerate(member_ids):
            role = "employee" if i < 3 else "manager"
            actions = ["view", "comment"] if role == "employee" else ["view", "edit", "share"]

            response = admin_client.post('/api/auth/permissions/grant/', {
                "user_id": member_id,
                "workspace_id": workspace_id,
                "actions": actions
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 6. 成员协作测试
        for i, (member_client, member_token) in enumerate(zip(member_clients, member_tokens)):
            member_client.credentials(HTTP_AUTHORIZATION=f'Bearer {member_token}')

            # 访问工作空间
            response = member_client.get(f'/api/auth/workspaces/{workspace_id}/')
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            # 检查权限
            expected_actions = ["view", "comment"] if i < 3 else ["view", "edit", "share"]
            response = member_client.post('/api/auth/permissions/check/', {
                "workspace_id": workspace_id,
                "actions": expected_actions
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            for action in expected_actions:
                self.assertTrue(response.data['has_permission'][action])

        # 7. 权限变更测试
        # 提升员工权限
        for i in range(3):  # 前3个是员工
            response = admin_client.post('/api/auth/permissions/grant/', {
                "user_id": member_ids[i],
                "workspace_id": workspace_id,
                "actions": ["edit"]  # 额外授予编辑权限
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 8. 验证权限变更生效
        employee_clients = member_clients[:3]
        for member_client in employee_clients:
            response = member_client.post('/api/auth/permissions/check/', {
                "workspace_id": workspace_id,
                "actions": ["edit"]
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['has_permission']['edit'])

        # 9. 审计日志验证
        response = admin_client.get('/api/auth/activity/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        activities = response.data['activities']

        # 验证包含关键操作
        activity_actions = [activity['action'] for activity in activities]
        self.assertIn('register', activity_actions)  # 注册操作
        self.assertIn('create_team', activity_actions)  # 创建团队
        self.assertIn('create_workspace', activity_actions)  # 创建工作空间
        self.assertIn('grant_permission', activity_actions)  # 授予权限

        # 10. 性能验证 - 所有操作应在合理时间内完成
        # 这个测试主要确保没有明显的性能问题
        self.assertLess(len(activities), 1000, "活动日志过多，可能存在性能问题")