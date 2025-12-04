# Multi-Tenant Auth

[![PyPI version](https://badge.fury.io/py/multi-tenant-auth.svg)](https://badge.fury.io/py/multi-tenant-auth/)
[![Python versions](https://img.shields.io/pypi/pyversions/multi-tenant-auth.svg)](https://pypi.org/project/multi-tenant-auth/)
[![License](https://img.shields.io/pypi/l/multi-tenant-auth.svg)](https://pypi.org/project/multi-tenant-auth/)
[![Build Status](https://github.com/Jindequan/multi_tenant_auth/workflows/CI/badge.svg)](https://github.com/Jindequan/multi_tenant_auth/actions)
[![Coverage](https://codecov.io/gh/Jindequan/multi_tenant_auth/branch/main/graph/badge.svg)](https://codecov.io/gh/Jindequan/multi_tenant_auth/branch/main/graph/badge.svg)

> ⚠️ **开源免费，禁止商业化**
>
> 本项目完全开源免费，供个人学习、研究和非商业用途使用。
> **禁止二开收费** - 不得将本项目稍作修改后作为付费产品出售。
> **禁止商业化滥用** - 不得用于纯商业牟利目的。

一个极简、高效的多租户认证权限管理库，专为 Django SaaS 应用设计。
## 📦 安装

### 基础安装

```bash
pip install multi-tenant-auth
```

### 带开发依赖

```bash
pip install multi-tenant-auth[dev]
```

### 带完整依赖

```bash
pip install multi-tenant-auth[all]
```

## ⚙️ 快速开始

### 1. 配置 Django 设置

```python
# settings.py
INSTALLED_APPS = [
    # Django 默认应用
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
]

# Multi-Tenant Auth 配置
MULTI_TENANT_AUTH = {
    'ENABLE_2FA': True,
    'PASSWORD_MIN_LENGTH': 8,
    'SESSION_TIMEOUT_MINUTES': 60,
    'MAX_LOGIN_ATTEMPTS': 5,
    'TOKEN_EXPIRY_MINUTES': 60,
    'REFRESH_TOKEN_EXPIRY_DAYS': 7,
    'REQUIRE_EMAIL_VERIFICATION': True,
    'DEFAULT_WORKSPACE_ROLES': ['owner', 'admin', 'member', 'viewer'],
    'CACHE_TIMEOUT': 300,
}
```

### 2. 配置 URL

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    # 其他 URL
    path('api/auth/', include('multi_tenant_auth.api.urls')),
]
```

### 3. 运行迁移

```bash
python manage.py migrate
```

### 4. 创建超级用户

```bash
python manage.py createsuperuser
```

### 5. 使用 CLI 工具快速初始化

```bash
# 初始化项目
multi-tenant-auth init --project-name=my_project

# 创建工作空间
multi-tenant-auth create-workspace \
  --name="My Company" \
  --owner-username=admin \
  --description="Main company workspace"

# 启动开发服务器
multi-tenant-auth runserver
```

## 🏗️ 核心概念

### 用户 (User)
- 继承 Django 的 AbstractUser
- 支持双因素认证
- 邮箱验证
- 密码重置

### 工作空间 (Workspace)
- 租户的核心概念
- 每个用户可以有多个工作空间
- 支持工作空间的邀请和管理

### 团队 (Team)
- 工作空间内的团队组织
- 支持团队成员管理
- 基于团队的权限分配

### 权限 (UserWorkspaceActions)
- 核心权限表：`user_workspace_actions`
- 一个表解决所有权限问题
- 支持细粒度的操作权限

## 📚 API 使用示例

### 认证 API

```python
# 用户注册
POST /api/auth/register/
{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
}

# 用户登录
POST /api/auth/login/
{
    "username": "john_doe",
    "password": "SecurePass123!"
}

# 刷新令牌
POST /api/auth/refresh/
{
    "refresh": "your_refresh_token"
}
```

### 工作空间管理

```python
# 创建工作空间
POST /api/auth/workspaces/
{
    "name": "My Startup",
    "description": "Main workspace for my startup"
}

# 获取工作空间列表
GET /api/auth/workspaces/

# 邀请成员到工作空间
POST /api/auth/workspaces/{workspace_id}/members/
{
    "email": "member@example.com",
    "role": "member",
    "actions": ["view", "edit"]
}
```

### 团队管理

```python
# 创建团队
POST /api/auth/teams/
{
    "name": "Development Team",
    "description": "Main development team",
    "workspace_id": "workspace_uuid"
}

# 添加团队成员
POST /api/auth/teams/{team_id}/members/
{
    "user_id": "user_uuid",
    "role": "member"
}
```

## 🔒 权限系统

### 权限检查

```python
from multi_tenant_auth.decorators import require_workspace_permission
from multi_tenant_auth.services import PermissionService

# 装饰器方式
@require_workspace_permission('edit')
def my_view(request, workspace_id):
    # 只有具有编辑权限的用户才能访问
    pass

# 服务方式
permission_service = PermissionService()
has_permission = permission_service.check_permission(
    user_id=request.user.id,
    workspace_id=workspace_id,
    action='edit'
)
```

### 权限操作

```python
# 授予权限
from multi_tenant_auth.models import UserWorkspaceActions

UserWorkspaceActions.objects.update_or_create(
    user=user,
    workspace=workspace,
    defaults={'actions': 'view,edit,delete,admin'}
)

# 检查权限
user_actions = UserWorkspaceActions.objects.filter(
    user=user,
    workspace=workspace
).first()

if user_actions and 'edit' in user_actions.actions:
    # 用户有编辑权限
    pass
```

## 🎯 实际使用场景

### 1. SaaS 平台

```python
# 用户的仪表盘
@require_workspace_permission('view')
def dashboard(request, workspace_id):
    workspace = get_object_or_404(Workspace, id=workspace_id)
    # 显示工作空间信息
    return render(request, 'dashboard.html', {'workspace': workspace})

# 编辑工作空间设置
@require_workspace_permission('admin')
def workspace_settings(request, workspace_id):
    workspace = get_object_or_404(Workspace, id=workspace_id)
    # 只有管理员可以编辑设置
    pass
```

### 2. 多租户 API

```python
# API 视图示例
class ProjectViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        # 只返回用户有权限的工作空间中的项目
        workspace_id = self.request.GET.get('workspace_id')
        if workspace_id:
            # 检查权限
            if not permission_service.check_permission(
                user_id=self.request.user.id,
                workspace_id=workspace_id,
                action='view'
            ):
                return Project.objects.none()

            return Project.objects.filter(workspace_id=workspace_id)

        return Project.objects.none()

    def perform_create(self, serializer):
        # 创建项目时检查权限
        workspace_id = self.request.data.get('workspace_id')
        if permission_service.check_permission(
            user_id=self.request.user.id,
            workspace_id=workspace_id,
            action='create'
        ):
            serializer.save()
        else:
            raise PermissionDenied("无权限在此工作空间创建项目")
```

### 3. 中间件使用

```python
# 自动设置当前工作空间
class WorkspaceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        workspace_id = request.META.get('HTTP_X_WORKSPACE_ID')
        if workspace_id:
            try:
                workspace = Workspace.objects.get(id=workspace_id)
                # 检查权限
                if permission_service.check_permission(
                    user_id=request.user.id,
                    workspace_id=workspace_id,
                    action='view'
                ):
                    request.current_workspace = workspace
            except Workspace.DoesNotExist:
                pass

        return self.get_response(request)
```

## 🔧 高级配置

### 自定义权限操作

```python
# settings.py
MULTI_TENANT_AUTH = {
    'DEFAULT_WORKSPACE_ROLES': [
        'owner',      # 所有者权限
        'admin',      # 管理员权限
        'editor',     # 编辑权限
        'member',     # 成员权限
        'viewer',     # 查看权限
    ],
    'CUSTOM_PERMISSIONS': {
        'owner': ['*'],  # 所有权限
        'admin': ['view', 'edit', 'delete', 'manage_users'],
        'editor': ['view', 'edit', 'create'],
        'member': ['view', 'create'],
        'viewer': ['view'],
    }
}
```

### 缓存配置

```python
# Redis 缓存配置
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# 权限缓存
MULTI_TENANT_AUTH = {
    'CACHE_TIMEOUT': 300,  # 5分钟缓存
    'CACHE_KEY_PREFIX': 'mta_',
}
```

### JWT 配置

```python
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
```

## 🧪 测试

运行测试套件：

```bash
# 基础测试
python manage.py test multi_tenant_auth

# 使用 pytest
pytest multi_tenant_auth/tests/

# 生成覆盖率报告
pytest --cov=multi_tenant_auth --cov-report=html
```

### 测试权限

```python
from django.test import TestCase
from multi_tenant_auth.models import User, Workspace, UserWorkspaceActions

class PermissionTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.workspace = Workspace.objects.create(
            name='Test Workspace',
            created_by=self.user
        )
        UserWorkspaceActions.objects.create(
            user=self.user,
            workspace=self.workspace,
            actions='view,edit'
        )

    def test_has_permission(self):
        from multi_tenant_auth.services import PermissionService

        permission_service = PermissionService()
        has_view = permission_service.check_permission(
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            action='view'
        )
        has_delete = permission_service.check_permission(
            user_id=self.user.id,
            workspace_id=self.workspace.id,
            action='delete'
        )

        self.assertTrue(has_view)
        self.assertFalse(has_delete)
```

## 📈 性能优化

### 数据库索引

```python
# 自动创建的索引
# user_workspace_actions 表
# - (user_id, workspace_id) - 复合索引用于快速查找
# - workspace_id - 用于工作空间权限查询

# workspaces 表
# - created_by - 用于查找用户创建的工作空间
# - created_at - 用于时间排序
```

### 缓存策略

```python
# 权限检查缓存
@cache_page(timeout=300, key_prefix='permission_')
def check_permission_cached(user_id, workspace_id, action):
    # 权限检查逻辑
    pass

# 用户工作空间缓存
@cache_page(timeout=300, key_prefix='user_workspaces_')
def get_user_workspaces(user_id):
    # 获取用户工作空间列表
    pass
```

## 🚀 部署

### 环境变量

```bash
# 基础配置
DJANGO_SETTINGS_MODULE=my_project.settings
SECRET_KEY=your-super-secret-key

# 数据库
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Multi-Tenant Auth
MULTI_TENANT_AUTH_ENABLE_2FA=True
MULTI_TENANT_AUTH_SESSION_TIMEOUT_MINUTES=60
MULTI_TENANT_AUTH_TOKEN_EXPIRY_MINUTES=60
```

### Docker 支持

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "my_project.wsgi:application"]
```

## 🤝 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/your-org/multi-tenant-auth.git
cd multi-tenant-auth

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装开发依赖
pip install -e .[dev]

# 运行测试
pytest

# 代码格式化
black .
isort .

# 类型检查
mypy multi_tenant_auth
```

## 📄 许可证

本项目使用 MIT 许可证。查看 [LICENSE](LICENSE) 文件了解详细信息。

## 🆘 支持

- 📖 [文档](https://multi-tenant-auth.readthedocs.io/)
- 🐛 [问题反馈](https://github.com/your-org/multi-tenant-auth/issues)
- 💬 [讨论](https://github.com/your-org/multi-tenant-auth/discussions)
- 📧 [邮件支持](mailto:support@multi-tenant-auth.com)

## 🔗 相关项目

- [Multi-Tenant Auth Examples](https://github.com/your-org/multi-tenant-auth-examples) - 示例项目集合
- [Multi-Tenant Admin](https://github.com/your-org/multi-tenant-admin) - Django Admin 集成
- [Multi-Tenant Frontend](https://github.com/your-org/multi-tenant-frontend) - React 前端组件

---

⭐ 如果这个项目对你有帮助，请给它一个星标！

**让多租户认证变得简单！** 🚀