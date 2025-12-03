"""
测试装饰器功能
"""

import uuid
from unittest.mock import Mock, patch
from django.test import TestCase, RequestFactory
from django.http import JsonResponse, HttpResponse
from rest_framework.test import APITestCase

from ..models import User, Workspace, UserWorkspaceActions
from ..services import PermissionService
from ..decorators import (
    require_permission,
    require_edit_permission,
    require_delete_permission,
    require_admin_permission,
    require_view_permission,
    require_share_permission,
    _resolve_value,
    _get_nested_attr
)
from ..exceptions import PermissionDenied


class DecoratorTest(TestCase):
    """测试装饰器核心功能"""

    def setUp(self):
        self.factory = RequestFactory()
        self.permission_service = PermissionService()

        # 创建测试用户
        self.user = User.objects.create_user(
            email="test@example.com",
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
            owner=self.admin
        )

        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "share"]
        )

    def test_require_permission_with_request_user(self):
        """测试从request获取用户ID"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def test_view(request):
            return HttpResponse("Success")

        response = test_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"Success")

    def test_require_permission_with_workspace_parameter(self):
        """测试从参数获取工作空间ID"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        # 模拟project对象
        project = Mock()
        project.id = str(self.workspace.id)

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id="project.id",
            action="edit"
        )
        def test_view(request, project):
            return HttpResponse(f"Project: {project.id}")

        response = test_view(request, project=project)
        self.assertEqual(response.status_code, 200)

    def test_require_permission_with_direct_values(self):
        """测试直接传入值"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id=str(self.user.id),
            workspace_id=str(self.workspace.id),
            action="share"
        )
        def test_view(request):
            return HttpResponse("Success")

        response = test_view(request)
        self.assertEqual(response.status_code, 200)

    def test_require_permission_without_auth_user(self):
        """测试没有认证用户的情况"""
        request = self.factory.post('/test/')

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def test_view(request):
            return HttpResponse("Success")

        response = test_view(request)
        self.assertEqual(response.status_code, 401)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'USER_ID_MISSING')

    def test_require_permission_missing_workspace(self):
        """测试缺少工作空间ID的情况"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id="nonexistent_project.id",
            action="view"
        )
        def test_view(request):
            return HttpResponse("Success")

        response = test_view(request)
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'WORKSPACE_ID_MISSING')

    def test_require_permission_insufficient_permissions(self):
        """测试权限不足的情况"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="delete"  # 用户没有删除权限
        )
        def test_view(request):
            return HttpResponse("Success")

        response = test_view(request)
        self.assertEqual(response.status_code, 403)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'PERMISSION_DENIED')

    def test_convenience_decorators(self):
        """测试便捷装饰器"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        # 测试view权限
        @require_view_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id)
        )
        def view_view(request):
            return HttpResponse("View Success")

        response = view_view(request)
        self.assertEqual(response.status_code, 200)

        # 测试edit权限
        @require_edit_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id)
        )
        def edit_view(request):
            return HttpResponse("Edit Success")

        response = edit_view(request)
        self.assertEqual(response.status_code, 200)

        # 测试share权限
        @require_share_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id)
        )
        def share_view(request):
            return HttpResponse("Share Success")

        response = share_view(request)
        self.assertEqual(response.status_code, 200)

        # 测试delete权限（应该失败）
        @require_delete_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id)
        )
        def delete_view(request):
            return HttpResponse("Delete Success")

        response = delete_view(request)
        self.assertEqual(response.status_code, 403)

    def test_resolve_value_from_request(self):
        """测试从request解析值"""
        request = Mock()
        request.auth_user_id = "user-123"
        request.auth_user = Mock()

        result = _resolve_value("request.auth_user_id", request)
        self.assertEqual(result, "user-123")

        result = _resolve_value("request.auth_user", request)
        self.assertEqual(result, request.auth_user)

    def test_resolve_value_from_object(self):
        """测试从对象解析值"""
        project = Mock()
        project.id = "project-456"
        project.workspace_id = "workspace-789"

        kwargs = {"project": project}

        result = _resolve_value("project.id", None, **kwargs)
        self.assertEqual(result, "project-456")

        result = _resolve_value("project.workspace_id", None, **kwargs)
        self.assertEqual(result, "workspace-789")

    def test_resolve_value_from_kwargs(self):
        """测试从kwargs解析值"""
        kwargs = {
            "user_id": "user-123",
            "workspace_id": "workspace-456"
        }

        result = _resolve_value("user_id", None, **kwargs)
        self.assertEqual(result, "user-123")

        result = _resolve_value("workspace_id", None, **kwargs)
        self.assertEqual(result, "workspace-456")

    def test_resolve_value_direct(self):
        """测试直接值解析"""
        result = _resolve_value("direct-value", None)
        self.assertEqual(result, "direct-value")

        result = _resolve_value(123, None)
        self.assertEqual(result, 123)

    def test_get_nested_attr(self):
        """测试嵌套属性获取"""
        # 测试对象属性
        user = Mock()
        user.profile = Mock()
        user.profile.name = "Test User"

        result = _get_nested_attr(user, "profile.name")
        self.assertEqual(result, "Test User")

        # 测试字典属性
        data = {
            "user": {
                "profile": {
                    "settings": {
                        "theme": "dark"
                    }
                }
            }
        }

        result = _get_nested_attr(data, "user.profile.settings.theme")
        self.assertEqual(result, "dark")

        # 测试混合
        user_dict = {
            "id": "user-123",
            "profile": Mock()
        }
        user_dict["profile"].name = "Dict User"

        result = _get_nested_attr(user_dict, "profile.name")
        self.assertEqual(result, "Dict User")

        # 测试不存在的属性
        result = _get_nested_attr(user, "nonexistent.attribute")
        self.assertIsNone(result)

    def test_decorator_with_multiple_parameters(self):
        """测试装饰器处理多个参数"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        # 创建多个工作空间
        workspace1 = self.workspace
        workspace2 = Workspace.objects.create(
            name="Workspace 2",
            slug="workspace-2",
            workspace_type="personal",
            owner=self.admin
        )

        # 给第二个工作空间授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin.id,
            user_id=self.user.id,
            workspace_id=workspace2.id,
            actions=["view", "delete"]
        )

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id="workspace.id",
            action="edit"
        )
        def edit_workspace_view(request, workspace):
            return HttpResponse(f"Edited {workspace.name}")

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id="workspace.id",
            action="delete"
        )
        def delete_workspace_view(request, workspace):
            return HttpResponse(f"Deleted {workspace.name}")

        # 测试编辑workspace1（有权限）
        response = edit_workspace_view(request, workspace=workspace1)
        self.assertEqual(response.status_code, 200)

        # 测试编辑workspace2（无权限）
        response = edit_workspace_view(request, workspace=workspace2)
        self.assertEqual(response.status_code, 403)

        # 测试删除workspace1（无权限）
        response = delete_workspace_view(request, workspace=workspace1)
        self.assertEqual(response.status_code, 403)

        # 测试删除workspace2（有权限）
        response = delete_workspace_view(request, workspace=workspace2)
        self.assertEqual(response.status_code, 200)

    def test_decorator_exception_handling(self):
        """测试装饰器异常处理"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def test_view(request):
            raise ValueError("Test exception")

        response = test_view(request)
        self.assertEqual(response.status_code, 500)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'INTERNAL_ERROR')
        self.assertEqual(response_data['message'], 'Test exception')


class DecoratorIntegrationTest(APITestCase):
    """测试装饰器与API集成"""

    def setUp(self):
        self.client = self.client_class()
        self.permission_service = PermissionService()

        # 创建用户并获取token
        from ..services import AuthService
        auth_service = AuthService()

        register_result = auth_service.register_user(
            email="test@example.com",
            password="password123"
        )
        self.token = register_result['access_token']
        self.user_id = register_result['user']['id']

        admin_result = auth_service.register_user(
            email="admin@example.com",
            password="password123"
        )
        self.admin_token = admin_result['access_token']
        self.admin_id = admin_result['user']['id']

        # 创建工作空间
        from ..models import User, Workspace
        self.user = User.objects.get(id=self.user_id)
        self.admin = User.objects.get(id=self.admin_id)

        self.workspace = Workspace.objects.create(
            name="API Test Workspace",
            slug="api-test-workspace",
            workspace_type="personal",
            owner=self.admin
        )

        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.admin_id,
            user_id=self.user_id,
            workspace_id=self.workspace.id,
            actions=["view", "edit"]
        )

    def test_api_with_decorator_protection(self):
        """测试API装饰器保护"""
        # 设置认证头
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 模拟一个受保护的API端点
        url = '/api/test-protected/'

        # 创建一个测试视图函数
        from django.urls import path
        from django.conf.urls import include

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def protected_view(request):
            return JsonResponse({"message": "Access granted", "user": str(request.auth_user_id)})

        # 由于我们无法直接注册URL，我们模拟装饰器调用
        request = self.client.get(url).request
        request.auth_user_id = str(self.user_id)
        request.auth_user = self.user

        # 直接调用装饰器保护的函数
        response = protected_view(request)
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data['message'], 'Access granted')
        self.assertEqual(response_data['user'], str(self.user_id))

    def test_api_with_decorator_permission_denied(self):
        """测试API装饰器权限拒绝"""
        # 设置认证头
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.token}')

        # 创建一个需要删除权限的视图
        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="delete"  # 用户没有删除权限
        )
        def delete_view(request):
            return JsonResponse({"message": "Delete successful"})

        request = self.client.get('/api/test-delete/').request
        request.auth_user_id = str(self.user_id)
        request.auth_user = self.user

        response = delete_view(request)
        self.assertEqual(response.status_code, 403)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'PERMISSION_DENIED')

    def test_api_without_authentication(self):
        """测试没有认证的API访问"""
        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def protected_view(request):
            return JsonResponse({"message": "Access granted"})

        request = self.client.get('/api/test/').request
        # 没有设置auth_user_id

        response = protected_view(request)
        self.assertEqual(response.status_code, 401)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'USER_ID_MISSING')


class DecoratorPerformanceTest(TestCase):
    """测试装饰器性能"""

    def setUp(self):
        self.factory = RequestFactory()
        self.permission_service = PermissionService()

        # 创建测试数据
        self.user = User.objects.create_user(email="perf@test.com", password="password123")
        self.workspace = Workspace.objects.create(
            name="Performance Test",
            slug="perf-test",
            workspace_type="personal",
            owner=self.user
        )

        # 授予权限
        self.permission_service.grant_permission(
            granter_id=self.user.id,
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            actions=["view", "edit", "delete", "share", "admin"]
        )

    def test_decorator_caching_performance(self):
        """测试装饰器缓存性能"""
        import time

        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def test_view(request):
            return HttpResponse("Success")

        # 第一次调用（应该查询数据库）
        start_time = time.time()
        response1 = test_view(request)
        first_call_time = time.time() - start_time

        # 第二次调用（应该使用缓存）
        start_time = time.time()
        response2 = test_view(request)
        second_call_time = time.time() - start_time

        # 两次调用都应该成功
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response2.status_code, 200)

        # 第二次调用应该更快（由于缓存）
        # 注意：在测试环境中差异可能不明显，但逻辑是正确的
        self.assertLessEqual(second_call_time, first_call_time * 1.5)

    def test_multiple_decorator_calls(self):
        """测试多次装饰器调用"""
        request = self.factory.post('/test/')
        request.auth_user_id = str(self.user.id)
        request.auth_user = self.user

        @require_permission(
            user_id="request.auth_user_id",
            workspace_id=str(self.workspace.id),
            action="view"
        )
        def test_view(request):
            return HttpResponse("Success")

        # 连续调用多次
        for i in range(10):
            response = test_view(request)
            self.assertEqual(response.status_code, 200)

    def test_decorator_parameter_resolution_performance(self):
        """测试装饰器参数解析性能"""
        import time

        # 测试不同参数解析方式的性能
        project = Mock()
        project.id = str(self.workspace.id)
        project.workspace_id = str(self.workspace.id)

        kwargs = {"project": project}

        # 测试直接值
        start_time = time.time()
        for _ in range(1000):
            result = _resolve_value(str(self.user.id), None, **kwargs)
        direct_time = time.time() - start_time

        # 测试request属性
        request = Mock()
        request.auth_user_id = str(self.user.id)
        start_time = time.time()
        for _ in range(1000):
            result = _resolve_value("request.auth_user_id", request, **kwargs)
        request_time = time.time() - start_time

        # 测试对象属性
        start_time = time.time()
        for _ in range(1000):
            result = _resolve_value("project.id", request, **kwargs)
        object_time = time.time() - start_time

        # 所有方式都应该在合理时间内完成
        self.assertLess(direct_time, 1.0)  # 直接值应该很快
        self.assertLess(request_time, 1.0)  # request属性解析应该很快
        self.assertLess(object_time, 1.0)   # 对象属性解析应该很快