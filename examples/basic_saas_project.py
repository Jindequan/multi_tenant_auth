"""
Multi-Tenant Auth 基础 SaaS 项目示例
演示如何快速集成多租户认证系统
"""

import os
import django
from datetime import timedelta
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

# 配置 Django 设置
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='your-super-secret-key-change-in-production',

        # 基础配置
        INSTALLED_APPS=[
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'django.contrib.staticfiles',

            # 第三方应用
            'rest_framework',
            'rest_framework_simplejwt',
            'corsheaders',

            # Multi-Tenant Auth
            'multi_tenant_auth',
        ],

        # 数据库配置
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },

        # Multi-Tenant Auth 配置
        MULTI_TENANT_AUTH={
            'ENABLE_2FA': True,
            'PASSWORD_MIN_LENGTH': 8,
            'SESSION_TIMEOUT_MINUTES': 60,
            'MAX_LOGIN_ATTEMPTS': 5,
            'TOKEN_EXPIRY_MINUTES': 60,
            'REFRESH_TOKEN_EXPIRY_DAYS': 7,
            'REQUIRE_EMAIL_VERIFICATION': True,
            'DEFAULT_WORKSPACE_ROLES': ['owner', 'admin', 'member', 'viewer'],
            'CACHE_TIMEOUT': 300,
        },

        # REST Framework 配置
        REST_FRAMEWORK={
            'DEFAULT_AUTHENTICATION_CLASSES': [
                'rest_framework_simplejwt.authentication.JWTAuthentication',
            ],
            'DEFAULT_PERMISSION_CLASSES': [
                'rest_framework.permissions.IsAuthenticated',
            ],
            'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
            'PAGE_SIZE': 20,
        },

        # JWT 配置
        SIMPLE_JWT={
            'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
            'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
            'ROTATE_REFRESH_TOKENS': True,
            'ALGORITHM': 'HS256',
            'SIGNING_KEY': 'your-super-secret-key-change-in-production',
            'AUTH_HEADER_TYPES': ('Bearer',),
        },

        # CORS 配置
        CORS_ALLOWED_ORIGINS=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],

        # 静态文件
        STATIC_URL='/static/',
        STATIC_ROOT='staticfiles',

        # 国际化
        LANGUAGE_CODE='en-us',
        TIME_ZONE='UTC',
        USE_I18N=True,
        USE_TZ=True,

        # 安全配置
        SECURE_BROWSER_XSS_FILTER=True,
        X_FRAME_OPTIONS='DENY',
    )

# 初始化 Django
django.setup()

# 导入模型（在 Django 设置后）
from multi_tenant_auth.models import User, Workspace, UserWorkspaceActions
from multi_tenant_auth.decorators import require_workspace_permission
from multi_tenant_auth.services import PermissionService
from rest_framework_simplejwt.tokens import RefreshToken


# ================================
# 示例 API 视图
# ================================

@api_view(['POST'])
@permission_classes([])  # 允许未认证用户访问
def register_user(request):
    """用户注册示例"""
    try:
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')
        password_confirm = request.data.get('password_confirm')

        # 基础验证
        if not all([email, username, password]):
            return Response(
                {'error': '缺少必要字段'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if password != password_confirm:
            return Response(
                {'error': '密码不匹配'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 创建用户
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        # 创建默认工作空间
        workspace = Workspace.objects.create(
            name=f"{username}'s Workspace",
            description=f"默认工作空间 for {username}",
            created_by=user
        )

        # 设置用户为工作空间所有者
        UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions='*'  # 所有权限
        )

        return Response({
            'message': '注册成功',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            },
            'workspace': {
                'id': workspace.id,
                'name': workspace.name,
                'description': workspace.description,
            }
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([])
def login_user(request):
    """用户登录示例"""
    try:
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if not user:
            return Response(
                {'error': '用户名或密码错误'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # 生成 JWT 令牌
        refresh = RefreshToken.for_user(user)

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            }
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_workspaces(request):
    """获取用户工作空间列表"""
    try:
        user = request.user

        # 获取用户有权限的工作空间
        user_workspaces = UserWorkspaceActions.objects.filter(
            user=user
        ).select_related('workspace').order_by('-created_at')

        workspaces = []
        for uwa in user_workspaces:
            workspace = uwa.workspace
            workspaces.append({
                'id': workspace.id,
                'name': workspace.name,
                'description': workspace.description,
                'permissions': uwa.actions,
                'role': get_user_role(uwa.actions),
                'created_at': workspace.created_at,
            })

        return Response({
            'workspaces': workspaces,
            'count': len(workspaces),
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_workspace(request):
    """创建新工作空间"""
    try:
        user = request.user
        name = request.data.get('name')
        description = request.data.get('description', '')

        if not name:
            return Response(
                {'error': '工作空间名称不能为空'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 创建工作空间
        workspace = Workspace.objects.create(
            name=name,
            description=description,
            created_by=user
        )

        # 设置创建者为所有者
        UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions='*'
        )

        return Response({
            'message': '工作空间创建成功',
            'workspace': {
                'id': workspace.id,
                'name': workspace.name,
                'description': workspace.description,
                'permissions': '*',
                'role': 'owner',
            }
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@require_workspace_permission('view')
def get_workspace_details(request, workspace_id):
    """获取工作空间详情"""
    try:
        workspace = get_object_or_404(Workspace, id=workspace_id)

        # 获取工作空间成员
        members = UserWorkspaceActions.objects.filter(
            workspace=workspace
        ).select_related('user')

        member_list = []
        for member in members:
            member_list.append({
                'user_id': member.user.id,
                'username': member.user.username,
                'email': member.user.email,
                'permissions': member.actions,
                'role': get_user_role(member.actions),
                'joined_at': member.created_at,
            })

        return Response({
            'workspace': {
                'id': workspace.id,
                'name': workspace.name,
                'description': workspace.description,
                'created_at': workspace.created_at,
                'created_by': workspace.created_by.username,
            },
            'members': member_list,
            'member_count': len(member_list),
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@require_workspace_permission('admin')
def invite_member(request, workspace_id):
    """邀请成员到工作空间"""
    try:
        workspace = get_object_or_404(Workspace, id=workspace_id)
        email = request.data.get('email')
        role = request.data.get('role', 'member')

        if not email:
            return Response(
                {'error': '邮箱地址不能为空'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 检查用户是否存在
        try:
            new_member = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': '用户不存在'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 检查是否已经是成员
        if UserWorkspaceActions.objects.filter(
            user=new_member,
            workspace=workspace
        ).exists():
            return Response(
                {'error': '用户已经是工作空间成员'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 获取角色权限
        role_permissions = get_role_permissions(role)

        # 添加成员
        UserWorkspaceActions.objects.create(
            user=new_member,
            workspace=workspace,
            granted_by=request.user,
            actions=role_permissions
        )

        return Response({
            'message': f'成功邀请 {email} 加入工作空间',
            'member': {
                'user_id': new_member.id,
                'username': new_member.username,
                'email': new_member.email,
                'role': role,
                'permissions': role_permissions,
            }
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_permission_example(request):
    """权限检查示例"""
    try:
        user = request.user
        workspace_id = request.GET.get('workspace_id')
        action = request.GET.get('action', 'view')

        if not workspace_id:
            return Response(
                {'error': '需要提供 workspace_id'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 使用权限服务检查权限
        permission_service = PermissionService()
        has_permission = permission_service.check_permission(
            user_id=user.id,
            workspace_id=workspace_id,
            action=action
        )

        # 检查多个权限
        multiple_permissions = permission_service.check_permissions(
            user_id=user.id,
            workspace_id=workspace_id,
            actions=['view', 'edit', 'delete', 'admin']
        )

        return Response({
            'user_id': user.id,
            'workspace_id': workspace_id,
            'single_permission': {
                'action': action,
                'has_permission': has_permission,
            },
            'multiple_permissions': multiple_permissions,
            'role': get_user_role_from_permissions(multiple_permissions),
        })

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


# ================================
# 辅助函数
# ================================

def get_user_role(actions):
    """根据权限字符串获取用户角色"""
    if actions == '*':
        return 'owner'

    action_list = actions.split(',') if isinstance(actions, str) else actions

    if 'admin' in action_list:
        return 'admin'
    elif 'edit' in action_list:
        return 'editor'
    elif 'view' in action_list:
        return 'viewer'
    else:
        return 'none'


def get_user_role_from_permissions(permissions):
    """根据权限字典获取用户角色"""
    if permissions.get('admin', False):
        return 'admin'
    elif permissions.get('edit', False):
        return 'editor'
    elif permissions.get('view', False):
        return 'viewer'
    else:
        return 'none'


def get_role_permissions(role):
    """获取角色对应的权限"""
    role_permissions = {
        'owner': '*',
        'admin': 'view,edit,delete,invite,manage_members',
        'editor': 'view,edit,create',
        'member': 'view,create',
        'viewer': 'view',
    }

    return role_permissions.get(role, 'view')


# ================================
# 主函数 - 用于演示
# ================================

def main():
    """演示函数"""
    print("Multi-Tenant Auth 基础 SaaS 项目示例")
    print("=" * 50)
    print()
    print("这个示例展示了如何:")
    print("1. 配置 Django 项目使用 Multi-Tenant Auth")
    print("2. 实现用户注册和登录")
    print("3. 创建和管理工作空间")
    print("4. 权限检查和访问控制")
    print("5. 邀请和管理工作空间成员")
    print()
    print("API 端点:")
    print("- POST /api/register/ - 用户注册")
    print("- POST /api/login/ - 用户登录")
    print("- GET /api/workspaces/ - 获取工作空间列表")
    print("- POST /api/workspaces/ - 创建工作空间")
    print("- GET /api/workspaces/{id}/ - 获取工作空间详情")
    print("- POST /api/workspaces/{id}/invite/ - 邀请成员")
    print("- GET /api/check-permission/ - 权限检查示例")
    print()
    print("权限装饰器:")
    print("@require_workspace_permission('view')")
    print("@require_workspace_permission('edit')")
    print("@require_workspace_permission('admin')")
    print()
    print("配置要求:")
    print("1. pip install multi-tenant-auth")
    print("2. 在 settings.py 中配置 MULTI_TENANT_AUTH")
    print("3. 运行数据库迁移")
    print("4. 集成到您的 Django 项目中")
    print()
    print("更多信息请查看:")
    print("- https://github.com/your-org/multi-tenant-auth")
    print("- https://multi-tenant-auth.readthedocs.io/")


if __name__ == '__main__':
    main()