"""
Multi-Tenant Auth Library - 完整的 REST API 接口
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token

from .views import (
    # 认证相关
    RegisterView,
    LoginView,
    LogoutView,
    RefreshTokenView,
    ProfileView,
    ChangePasswordView,
    ForgotPasswordView,
    ResetPasswordView,
    EnableTwoFactorView,
    VerifyTwoFactorView,
    DisableTwoFactorView,

    # 工作空间相关
    WorkspaceListView,
    WorkspaceDetailView,
    WorkspaceCreateView,
    WorkspaceUpdateView,
    WorkspaceDeleteView,
    WorkspaceStatsView,
    WorkspaceMembersView,

    # 团队相关
    TeamListView,
    TeamDetailView,
    TeamCreateView,
    TeamUpdateView,
    TeamDeleteView,
    TeamMembersView,
    TeamInviteView,

    # 权限相关
    PermissionCheckView,
    PermissionGrantView,
    PermissionRevokeView,
    UserPermissionsView,
    PermissionMatrixView,
    BatchPermissionView,

    # 用户相关
    UserListView,
    UserSearchView,
    UserStatsView,

    # 系统相关
    HealthCheckView,
    ConfigView,
    ActivityLogView,
    NotificationView,
)

# JWT认证端点
jwt_router = DefaultRouter()
jwt_router.register(r'login', obtain_jwt_token)  # POST /api/auth/login/
jwt_router.register(r'refresh', refresh_jwt_token)  # POST /api/auth/refresh/

# API路由器
api_router = DefaultRouter()

# 认证接口
api_router.register(r'register', RegisterView.as_view(), basename='auth-register')  # POST /api/auth/register/
api_router.register(r'login', LoginView.as_view(), basename='auth-login')  # POST /api/auth/login/
api_router.register(r'logout', LogoutView.as_view(), basename='auth-logout')  # POST /api/auth/logout/
api_router.register(r'refresh', RefreshTokenView.as_view(), basename='auth-refresh')  # POST /api/auth/refresh/
api_router.register(r'profile', ProfileView.as_view(), basename='auth-profile')  # GET/PATCH /api/auth/profile/
api_router.register(r'change-password', ChangePasswordView.as_view(), basename='auth-change-password')  # POST /api/auth/change-password/
api_router.register(r'forgot-password', ForgotPasswordView.as_view(), basename='auth-forgot-password')  # POST /api/auth/forgot-password/
api_router.register(r'reset-password', ResetPasswordView.as_view(), basename='auth-reset-password')  # POST /api/auth/reset-password/
api_router.register(r'enable-2fa', EnableTwoFactorView.as_view(), basename='auth-enable-2fa')  # POST /api/auth/enable-2fa/
api_router.register(r'verify-2fa', VerifyTwoFactorView.as_view(), basename='auth-verify-2fa')  # POST /api/auth/verify-2fa/
api_router.register(r'disable-2fa', DisableTwoFactorView.as_view(), basename='auth-disable-2fa')  # POST /api/auth/disable-2fa/

# 工作空间接口
api_router.register(r'workspaces', WorkspaceListView.as_view(), basename='workspaces')  # GET /api/auth/workspaces/
api_router.register(r'workspaces', WorkspaceDetailView.as_view(), basename='workspaces-detail')  # GET/PATCH/DELETE /api/auth/workspaces/{id}/
api_router.register(r'workspaces', WorkspaceCreateView.as_view(), basename='workspaces-create')  # POST /api/auth/workspaces/
api_router.register(r'workspace-stats', WorkspaceStatsView.as_view(), basename='workspace-stats')  # GET /api/auth/workspace-stats/
api_router.register(r'workspace-members', WorkspaceMembersView.as_view(), basename='workspace-members')  # GET /api/auth/workspace-members/

# 团队接口
api_router.register(r'teams', TeamListView.as_view(), basename='teams')  # GET /api/auth/teams/
api_router.register(r'teams', TeamDetailView.as_view(), basename='teams-detail')  # GET/PATCH/DELETE /api/auth/teams/{id}/
api_router.register(r'teams', TeamCreateView.as_view(), basename='teams-create')  # POST /api/auth/teams/
api_router.register(r'team-members', TeamMembersView.as_view(), basename='team-members')  # GET /api/auth/team-members/
api_router.register(r'team-invite', TeamInviteView.as_view(), basename='team-invite')  # POST /api/auth/team-invite/

# 权限接口
api_router.register(r'permissions-check', PermissionCheckView.as_view(), basename='permissions-check')  # POST /api/auth/permissions/check/
api_router.register(r'permissions-grant', PermissionGrantView.as_view(), basename='permissions-grant')  # POST /api/auth/permissions/grant/
api_router.register(r'permissions-revoke', PermissionRevokeView.as_view(), basename='permissions-revoke')  # DELETE /api/auth/permissions/revoke/
api_router.register(r'user-permissions', UserPermissionsView.as_view(), basename='user-permissions')  # GET /api/auth/user-permissions/
api_router.register(r'permission-matrix', PermissionMatrixView.as_view(), basename='permission-matrix')  # GET /api/auth/permission-matrix/
api_router.register(r'batch-permissions', BatchPermissionView.as_view(), basename='batch-permissions')  # POST /api/auth/batch-permissions/

# 用户接口
api_router.register(r'users', UserListView.as_view(), basename='users')  # GET /api/auth/users/
api_router.register(r'user-search', UserSearchView.as_view(), basename='user-search')  # GET /api/auth/user-search/
api_router.register(r'user-stats', UserStatsView.as_view(), basename='user-stats')  # GET /api/auth/user-stats/

# 系统接口
api_router.register(r'health', HealthCheckView.as_view(), basename='health')  # GET /api/auth/health/
api_router.register(r'config', ConfigView.as_view(), basename='config')  # GET /api/auth/config/
api_router.register(r'activity', ActivityLogView.as_view(), basename='activity')  # GET /api/auth/activity/
api_router.register(r'notifications', NotificationView.as_view(), basename='notifications')  # GET /api/auth/notifications/

# 特殊接口：路由
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])
def root_endpoint(request):
    """
    API根端点 - 返回可用端点列表
    """
    endpoints = {
        'authentication': {
            'login': f"{request.build_absolute_uri()}api/auth/login/",
            'register': f"{request.build_absolute_uri()}api/auth/register/",
            'logout': f"{request.build_absolute_uri()}api/auth/logout/",
            'refresh': f"{request.build_absolute_uri()}api/auth/refresh/",
            'forgot_password': f"{request.build_absolute_uri()}api/auth/forgot-password/",
            'reset_password': f"{request.build_absolute_uri()}api/auth/reset-password/",
            'enable_2fa': f"{request.build_absolute_uri()}api/auth/enable-2fa/",
            'verify_2fa': f"{request.build_absolute_uri()}api/auth/verify-2fa/",
            'disable_2fa': f"{request.build_absolute_uri()}api/auth/disable-2fa/",
            'change_password': f"{request.build_absolute_uri()}api/auth/change-password/",
            'profile': f"{request.build_absolute_uri()}api/auth/profile/",
        },
        'workspaces': {
            'list': f"{request.build_absolute_uri()}api/auth/workspaces/",
            'create': f"{request.build_absolute_uri()}api/auth/workspaces/",
            'detail': f"{request.build_absolute_uri()}api/auth/workspaces/{{id}}/",
            'members': f"{request.build_absolute_uri()}api/auth/workspace-members/",
            'stats': f"{request.build_absolute_uri()}api/auth/workspace-stats/",
        },
        'teams': {
            'list': f"{request.build_absolute_uri()}api/auth/teams/",
            'create': f"{request.build_absolute_uri()}api/auth/teams/",
            'detail': f"{request.build_absolute_uri()}api/auth/teams/{{id}}/",
            'members': f"{request.build_absolute_uri()}api/auth/team-members/",
            'invite': f"{request.build_absolute_uri()}api/auth/team-invite/",
        },
        'permissions': {
            'check': f"{request.build_absolute_uri()}api/auth/permissions/check/",
            'grant': f"{request.build_absolute_uri()}api/auth/permissions/grant/",
            'revoke': f"{request.build_absolute_uri()}api/auth/permissions/revoke/",
            'user_permissions': f"{request.build_absolute_uri()}api/auth/user-permissions/",
            'permission_matrix': f"{request.build_absolute_uri()}api/auth/permission-matrix/",
            'batch_permissions': f"{request.build_absolute_uri()}api/auth/batch-permissions/",
        },
        'users': {
            'list': f"{request.build_absolute_uri()}api/auth/users/",
            'search': f"{request.build_absolute_uri()}api/auth/user-search/",
            'stats': f"{request.build_absolute_uri()}api/auth/user-stats/",
        },
        'system': {
            'health': f"{request.build_absolute_uri()}api/auth/health/",
            'config': f"{request.build_absolute_uri()}api/auth/config/",
            'activity': f"{request.build_absolute_uri()}api/auth/activity/",
            'notifications': f"{request.build_absolute_uri()}api/auth/notifications/",
        },
        'docs': {
            'swagger': f"{request.build_absolute_uri()}api/auth/docs/",
            'redoc': f"{request.build_absolute_uri()}api/auth/redoc/",
        },
    }

    return Response({
        'success': True,
        'message': 'Multi-Tenant Auth API',
        'version': '1.0.0',
        'endpoints': endpoints,
        'documentation': {
            'swagger': f"{request.build_absolute_uri()}api/auth/docs/",
            'redoc': f"{request.build_absolute_uri()}api/auth/redoc/",
        },
        'examples': {
            'quick_start': f"{request.build_absolute_uri()}api/auth/examples/quick-start/",
            'react_integration': f"{request.build_absolute_uri()}api/auth/examples/react/",
            'curl_examples': f"{request.build_absolute_uri()}api/auth/examples/curl/",
        },
    }, status=status.HTTP_200_OK)

# API文档路由
urlpatterns = [
    # JWT认证
    path('token/', jwt_router.urls),

    # 主要API
    path('', api_router.urls),

    # 根端点
    path('', root_endpoint),

    # API文档
    path('docs/', include('rest_framework.urls')),  # DRF自带Swagger UI
    path('redoc/', include('rest_framework.urls')),  # ReDoc UI

    # 示例端点
    path('examples/', include([
        ('quick_start', 'multi_tenant_auth.api.examples'),
        ('react', 'multi_tenant_auth.api.examples'),
        ('curl', 'multi_tenant_auth.api.examples'),
    ])),
]

# URL配置
app_name = 'multi_tenant_auth'
urlpatterns = [
    path('auth/', include(urlpatterns)),
]