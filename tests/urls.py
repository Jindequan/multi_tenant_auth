"""
测试URL配置 - 用于Multi-Tenant Auth Library测试
"""

from django.urls import path, include
from django.contrib import admin
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework import status
import json

# 导入多租户认证模块的URL
from multi_tenant_auth.api.urls as auth_urls
from multi_tenant_auth.decorators import require_permission
from multi_tenant_auth.models import User, Workspace


# 测试视图函数
def test_home(request):
    """测试主页"""
    return JsonResponse({
        'message': 'Multi-Tenant Auth Library Test Server',
        'status': 'running',
        'version': '1.0.0'
    })


@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def test_register(request):
    """测试用户注册API"""
    try:
        from multi_tenant_auth.services import AuthService
        auth_service = AuthService()

        result = auth_service.register_user(
            email=request.data.get('email'),
            password=request.data.get('password'),
            personal_info=request.data.get('personal_info', {}),
            settings=request.data.get('settings', {})
        )

        return Response(result, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def test_login(request):
    """测试用户登录API"""
    try:
        from multi_tenant_auth.services import AuthService
        auth_service = AuthService()

        result = auth_service.authenticate_user(
            email=request.data.get('email'),
            password=request.data.get('password')
        )

        return Response(result, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
def test_profile(request):
    """测试用户资料API"""
    if not hasattr(request, 'auth_user_id'):
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(id=request.auth_user_id)

        return Response({
            'success': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'personal_info': user.personal_info,
                'settings': user.settings,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat(),
                'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def test_permission_check(request):
    """测试权限检查API"""
    try:
        from multi_tenant_auth.services import PermissionService
        permission_service = PermissionService()

        user_id = request.data.get('user_id')
        workspace_id = request.data.get('workspace_id')

        if 'action' in request.data:
            # 检查单个权限
            action = request.data.get('action')
            has_permission = permission_service.check_permission(
                user_id, workspace_id, action
            )

            return Response({
                'has_permission': has_permission
            }, status=status.HTTP_200_OK)

        elif 'actions' in request.data:
            # 批量检查权限
            actions = request.data.get('actions', [])
            permissions = permission_service.check_permissions(
                user_id, workspace_id, actions
            )

            return Response(permissions, status=status.HTTP_200_OK)

        else:
            return Response({
                'success': False,
                'error': 'Action or actions parameter required'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
def test_permission_grant(request):
    """测试权限授予API"""
    if not hasattr(request, 'auth_user_id'):
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        from multi_tenant_auth.services import PermissionService
        permission_service = PermissionService()

        result = permission_service.grant_permission(
            granter_id=request.auth_user_id,
            user_id=request.data.get('user_id'),
            workspace_id=request.data.get('workspace_id'),
            actions=request.data.get('actions', []),
            expires_at=request.data.get('expires_at')
        )

        return Response(result, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def test_permission_revoke(request):
    """测试权限撤销API"""
    if not hasattr(request, 'auth_user_id'):
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        from multi_tenant_auth.services import PermissionService
        permission_service = PermissionService()

        result = permission_service.revoke_permission(
            user_id=request.data.get('user_id'),
            workspace_id=request.data.get('workspace_id'),
            actions=request.data.get('actions')
        )

        return Response(result, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def test_user_permissions(request):
    """测试获取用户所有权限API"""
    if not hasattr(request, 'auth_user_id'):
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        from multi_tenant_auth.services import PermissionService
        permission_service = PermissionService()

        permissions = permission_service.get_user_all_permissions(request.auth_user_id)

        return Response(permissions, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 测试装饰器的视图
def test_decorated_view(request, workspace_id):
    """测试装饰器保护的视图"""
    return JsonResponse({
        'message': 'Access granted',
        'user_id': getattr(request, 'auth_user_id', None),
        'workspace_id': workspace_id
    })


# 使用装饰器保护的测试视图
protected_view = require_permission(
    user_id="request.auth_user_id",
    workspace_id="workspace_id",
    action="view"
)(test_decorated_view)

edit_protected_view = require_permission(
    user_id="request.auth_user_id",
    workspace_id="workspace_id",
    action="edit"
)(test_decorated_view)

delete_protected_view = require_permission(
    user_id="request.auth_user_id",
    workspace_id="workspace_id",
    action="delete"
)(test_decorated_view)


# 健康检查视图
def health_check(request):
    """健康检查端点"""
    from django.db import connection
    from multi_tenant_auth.models import User, Workspace

    try:
        # 检查数据库连接
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # 检查基础模型
    try:
        user_count = User.objects.count()
        workspace_count = Workspace.objects.count()
        model_status = "healthy"
    except Exception as e:
        user_count = 0
        workspace_count = 0
        model_status = f"unhealthy: {str(e)}"

    return JsonResponse({
        'status': 'healthy' if db_status == 'healthy' and model_status == 'healthy' else 'unhealthy',
        'database': db_status,
        'models': model_status,
        'counts': {
            'users': user_count,
            'workspaces': workspace_count
        },
        'timestamp': '2024-01-01T00:00:00Z'  # 测试用固定时间
    })


# 性能测试视图
def performance_test(request):
    """性能测试端点"""
    import time
    from multi_tenant_auth.services import PermissionService

    start_time = time.time()

    # 创建测试用户和工作空间
    user = User.objects.create_user(
        email=f"perf_test_{int(time.time())}@example.com",
        password="password123"
    )

    workspace = Workspace.objects.create(
        name=f"Performance Test {int(time.time())}",
        slug=f"perf-test-{int(time.time())}",
        workspace_type="personal",
        owner=user
    )

    permission_service = PermissionService()

    # 测试权限授予性能
    grant_start = time.time()
    permission_service.grant_permission(
        granter_id=user.id,
        user_id=user.id,
        workspace_id=workspace.id,
        actions=["view", "edit", "delete", "share", "admin"]
    )
    grant_time = time.time() - grant_start

    # 测试权限检查性能
    check_start = time.time()
    for _ in range(100):
        permission_service.check_permission(user.id, workspace.id, "view")
    check_time = time.time() - check_start

    # 测试批量权限检查性能
    batch_start = time.time()
    for _ in range(100):
        permission_service.check_permissions(
            user.id, workspace.id,
            ["view", "edit", "delete", "share", "admin"]
        )
    batch_time = time.time() - batch_start

    total_time = time.time() - start_time

    return JsonResponse({
        'performance_metrics': {
            'total_time': total_time,
            'grant_time': grant_time,
            'check_time_100': check_time,
            'check_time_single': check_time / 100,
            'batch_time_100': batch_time,
            'batch_time_single': batch_time / 100,
        },
        'cache_info': {
            'message': 'Cache performance metrics would be shown here'
        }
    })


# URL配置
urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # 测试基础路由
    path('', test_home, name='test-home'),
    path('health/', health_check, name='health-check'),
    path('performance/', performance_test, name='performance-test'),

    # 认证相关测试
    path('api/test/register/', test_register, name='test-register'),
    path('api/test/login/', test_login, name='test-login'),
    path('api/test/profile/', test_profile, name='test-profile'),

    # 权限相关测试
    path('api/test/permissions/check/', test_permission_check, name='test-permission-check'),
    path('api/test/permissions/grant/', test_permission_grant, name='test-permission-grant'),
    path('api/test/permissions/revoke/', test_permission_revoke, name='test-permission-revoke'),
    path('api/test/permissions/user/', test_user_permissions, name='test-user-permissions'),

    # 装饰器测试
    path('api/test/protected/<uuid:workspace_id>/', protected_view, name='test-protected'),
    path('api/test/edit/<uuid:workspace_id>/', edit_protected_view, name='test-edit-protected'),
    path('api/test/delete/<uuid:workspace_id>/', delete_protected_view, name='test-delete-protected'),

    # Multi-Tenant Auth API路由
    path('api/auth/', include(auth_urls)),

    # 错误测试路由
    path('api/test/error/', lambda request: JsonResponse({'error': 'Test error'}, status=500), name='test-error'),
    path('api/test/unauthorized/', lambda request: JsonResponse({'error': 'Unauthorized'}, status=401), name='test-unauthorized'),
    path('api/test/forbidden/', lambda request: JsonResponse({'error': 'Forbidden'}, status=403), name='test-forbidden'),
    path('api/test/not-found/', lambda request: JsonResponse({'error': 'Not found'}, status=404), name='test-not-found'),
]


# 处理404错误
def custom_404(request, exception):
    return JsonResponse({
        'error': 'Endpoint not found',
        'path': request.path,
        'method': request.method,
    }, status=404)


# 处理500错误
def custom_500(request):
    return JsonResponse({
        'error': 'Internal server error',
        'path': request.path,
        'method': request.method,
    }, status=500)


# 错误处理器
handler404 = 'tests.urls.custom_404'
handler500 = 'tests.urls.custom_500'