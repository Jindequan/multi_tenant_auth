"""
Multi-Tenant Auth CLI 工具
提供命令行接口用于快速初始化和管理
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path


def main():
    """CLI 主入口"""
    parser = argparse.ArgumentParser(
        description='Multi-Tenant Auth Library 管理工具',
        prog='multi-tenant-auth'
    )
    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # 初始化命令
    init_parser = subparsers.add_parser('init', help='初始化项目认证系统')
    init_parser.add_argument(
        '--project-name',
        default='my_project',
        help='项目名称'
    )
    init_parser.add_argument(
        '--skip-migrations',
        action='store_true',
        help='跳过数据库迁移'
    )

    # 创建超级用户命令
    createsuperuser_parser = subparsers.add_parser('createsuperuser', help='创建超级用户')
    createsuperuser_parser.add_argument('--username', help='用户名')
    createsuperuser_parser.add_argument('--email', help='邮箱')
    createsuperuser_parser.add_argument('--password', help='密码')

    # 迁移命令
    migrate_parser = subparsers.add_parser('migrate', help='运行数据库迁移')
    migrate_parser.add_argument('--app', default='multi_tenant_auth', help='指定应用')

    # 收集静态文件命令
    collectstatic_parser = subparsers.add_parser('collectstatic', help='收集静态文件')
    collectstatic_parser.add_argument('--noinput', action='store_true', help='无交互模式')

    # 创建工作空间命令
    create_workspace_parser = subparsers.add_parser('create-workspace', help='创建工作空间')
    create_workspace_parser.add_argument('--name', required=True, help='工作空间名称')
    create_workspace_parser.add_argument('--description', help='工作空间描述')
    create_workspace_parser.add_argument('--owner-username', required=True, help='所有者用户名')

    # 运行开发服务器命令
    runserver_parser = subparsers.add_parser('runserver', help='运行开发服务器')
    runserver_parser.add_argument('--port', type=int, default=8000, help='端口号')
    runserver_parser.add_argument('--host', default='127.0.0.1', help='主机地址')

    # 运行测试命令
    test_parser = subparsers.add_parser('test', help='运行测试')
    test_parser.add_argument('--coverage', action='store_true', help='生成覆盖率报告')
    test_parser.add_argument('--app', help='指定测试应用')

    # 生成配置文件命令
    generate_config_parser = subparsers.add_parser('generate-config', help='生成配置文件')
    generate_config_parser.add_argument('--format', choices=['yaml', 'json', 'env'], default='yaml', help='配置文件格式')

    # 检查权限命令
    check_permission_parser = subparsers.add_parser('check-permission', help='检查用户权限')
    check_permission_parser.add_argument('--user-id', required=True, help='用户ID')
    check_permission_parser.add_argument('--workspace-id', required=True, help='工作空间ID')
    check_permission_parser.add_argument('--action', required=True, help='操作类型')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # 执行对应命令
    try:
        if args.command == 'init':
            init_project(args)
        elif args.command == 'createsuperuser':
            create_superuser(args)
        elif args.command == 'migrate':
            run_migrations(args)
        elif args.command == 'collectstatic':
            collect_static(args)
        elif args.command == 'create-workspace':
            create_workspace(args)
        elif args.command == 'runserver':
            run_server(args)
        elif args.command == 'test':
            run_tests(args)
        elif args.command == 'generate-config':
            generate_config(args)
        elif args.command == 'check-permission':
            check_permission(args)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


def init_project(args):
    """初始化项目认证系统"""
    print(f"正在初始化 Multi-Tenant Auth 项目: {args.project_name}")

    # 检查是否在 Django 项目中
    if not os.path.exists('manage.py'):
        print("错误: 未找到 manage.py 文件。请确保在 Django 项目根目录中运行此命令。")
        sys.exit(1)

    # 检查 multi_tenant_auth 是否已安装
    try:
        import django
        from django.conf import settings
        from multi_tenant_auth.apps import MultiTenantAuthConfig
    except ImportError as e:
        print(f"错误: multi_tenant-auth 库未正确安装: {e}")
        print("请运行: pip install multi-tenant-auth")
        sys.exit(1)

    # 检查 settings.py 配置
    if 'multi_tenant_auth' not in settings.INSTALLED_APPS:
        print("⚠️  multi_tenant_auth 未在 INSTALLED_APPS 中配置")
        print("请添加 'multi_tenant_auth' 到您的 settings.py 中")

        # 尝试自动添加
        print("正在尝试自动添加...")
        auto_add_to_installed_apps()

    # 检查数据库配置
    check_database_config()

    # 运行迁移
    if not args.skip_migrations:
        print("正在运行数据库迁移...")
        subprocess.run(['python', 'manage.py', 'migrate', 'multi_tenant_auth'], check=True)

    # 创建超级用户（交互式）
    print("正在创建超级用户...")
    subprocess.run(['python', 'manage.py', 'createsuperuser'], check=False)

    # 收集静态文件
    print("正在收集静态文件...")
    subprocess.run(['python', 'manage.py', 'collectstatic', '--noinput'], check=True)

    print("✅ Multi-Tenant Auth 初始化完成！")
    print("🚀 现在可以运行 'python manage.py runserver' 启动开发服务器")
    print("📖 访问 http://localhost:8000/api/auth/docs/ 查看 API 文档")


def auto_add_to_installed_apps():
    """自动添加到 INSTALLED_APPS"""
    try:
        # 这里可以实现自动修改 settings.py 的逻辑
        print("⚠️  请手动在 settings.py 中添加 'multi_tenant_auth' 到 INSTALLED_APPS")
        return False
    except Exception:
        return False


def check_database_config():
    """检查数据库配置"""
    try:
        import django
        from django.conf import settings
        from django.db import connection

        # 尝试连接数据库
        connection.cursor()
        print("✅ 数据库连接正常")
        return True
    except Exception as e:
        print(f"❌ 数据库连接失败: {e}")
        print("请检查您的 DATABASES 配置")
        return False


def create_superuser(args):
    """创建超级用户"""
    cmd = ['python', 'manage.py', 'createsuperuser']

    if args.username:
        cmd.extend(['--username', args.username])
    if args.email:
        cmd.extend(['--email', args.email])
    if args.password:
        cmd.extend(['--noinput'])
        # 设置密码环境变量
        env = os.environ.copy()
        env['DJANGO_SUPERUSER_PASSWORD'] = args.password
        subprocess.run(cmd, env=env, check=True)
    else:
        subprocess.run(cmd, check=True)


def run_migrations(args):
    """运行数据库迁移"""
    cmd = ['python', 'manage.py', 'migrate', args.app]
    subprocess.run(cmd, check=True)


def collect_static(args):
    """收集静态文件"""
    cmd = ['python', 'manage.py', 'collectstatic']
    if args.noinput:
        cmd.append('--noinput')
    subprocess.run(cmd, check=True)


def create_workspace(args):
    """创建工作空间"""
    try:
        # 导入 Django 模型
        import django
        import os
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
        django.setup()

        from multi_tenant_auth.models import User, Workspace
        from django.contrib.auth import get_user_model

        # 获取用户
        try:
            user = User.objects.get(username=args.owner_username)
        except User.DoesNotExist:
            print(f"错误: 用户 '{args.owner_username}' 不存在")
            sys.exit(1)

        # 创建工作空间
        workspace = Workspace.objects.create(
            name=args.name,
            description=args.description or f"工作空间: {args.name}",
            created_by=user
        )

        # 添加用户为所有者
        from multi_tenant_auth.models import UserWorkspaceActions
        UserWorkspaceActions.objects.create(
            user=user,
            workspace=workspace,
            actions='*'  # 所有权限
        )

        print(f"✅ 工作空间 '{args.name}' 创建成功")
        print(f"📋 工作空间ID: {workspace.id}")
        print(f"👤 所有者: {args.owner_username}")

    except Exception as e:
        print(f"❌ 创建工作空间失败: {e}")
        sys.exit(1)


def run_server(args):
    """运行开发服务器"""
    cmd = ['python', 'manage.py', 'runserver', f'{args.host}:{args.port}']
    subprocess.run(cmd)


def run_tests(args):
    """运行测试"""
    if args.coverage:
        cmd = ['coverage', 'run', '--source=multi_tenant_auth', 'manage.py', 'test']
        if args.app:
            cmd.append(args.app)

        subprocess.run(cmd, check=True)

        # 生成覆盖率报告
        subprocess.run(['coverage', 'report'], check=True)
        subprocess.run(['coverage', 'html'], check=True)
        print("覆盖率报告已生成: htmlcov/index.html")
    else:
        cmd = ['python', 'manage.py', 'test']
        if args.app:
            cmd.append(args.app)
        subprocess.run(cmd, check=True)


def generate_config(args):
    """生成配置文件"""
    config_content = ""

    if args.format == 'yaml':
        config_content = f"""# Multi-Tenant Auth 配置文件
# 复制到您的 Django settings.py 或作为环境变量使用

# Django 基础配置
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
MULTI_TENANT_AUTH = {{
    'ENABLE_2FA': True,
    'PASSWORD_MIN_LENGTH': 8,
    'SESSION_TIMEOUT_MINUTES': 60,
    'MAX_LOGIN_ATTEMPTS': 5,
    'TOKEN_EXPIRY_MINUTES': 60,
    'REFRESH_TOKEN_EXPIRY_DAYS': 7,
    'REQUIRE_EMAIL_VERIFICATION': True,
    'DEFAULT_WORKSPACE_ROLES': ['owner', 'admin', 'member', 'viewer'],
    'CACHE_TIMEOUT': 300,
}}

# REST Framework 配置
REST_FRAMEWORK = {{
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}}

# JWT 配置
from datetime import timedelta
SIMPLE_JWT = {{
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}}

# CORS 配置
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://yourdomain.com",
]

# 数据库配置
DATABASES = {{
    'default': {{
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'your_db_name'),
        'USER': os.getenv('DB_USER', 'your_db_user'),
        'PASSWORD': os.getenv('DB_PASSWORD', 'your_db_password'),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }}
}}

# Redis 配置
CACHES = {{
    'default': {{
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f"redis://:{{os.getenv('REDIS_PASSWORD', '')}}@{{os.getenv('REDIS_HOST', 'localhost')}}:{{os.getenv('REDIS_PORT', '6379')}}/1",
        'OPTIONS': {{
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }}
    }}
}}

# 静态文件和媒体文件
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# 国际化
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True

# 安全配置
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
"""
    elif args.format == 'json':
        import json
        config = {
            "INSTALLED_APPS": [
                "django.contrib.admin",
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sessions",
                "django.contrib.messages",
                "django.contrib.staticfiles",
                "rest_framework",
                "rest_framework_simplejwt",
                "corsheaders",
                "multi_tenant_auth",
            ],
            "MULTI_TENANT_AUTH": {
                "ENABLE_2FA": True,
                "PASSWORD_MIN_LENGTH": 8,
                "SESSION_TIMEOUT_MINUTES": 60,
                "MAX_LOGIN_ATTEMPTS": 5,
                "TOKEN_EXPIRY_MINUTES": 60,
                "REFRESH_TOKEN_EXPIRY_DAYS": 7,
                "REQUIRE_EMAIL_VERIFICATION": True,
                "DEFAULT_WORKSPACE_ROLES": ["owner", "admin", "member", "viewer"],
                "CACHE_TIMEOUT": 300,
            },
            "REST_FRAMEWORK": {
                "DEFAULT_AUTHENTICATION_CLASSES": [
                    "rest_framework_simplejwt.authentication.JWTAuthentication",
                ],
                "DEFAULT_PERMISSION_CLASSES": [
                    "rest_framework.permissions.IsAuthenticated",
                ],
                "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
                "PAGE_SIZE": 20,
            },
        }
        config_content = json.dumps(config, indent=2, ensure_ascii=False)
    elif args.format == 'env':
        config_content = f"""# Multi-Tenant Auth 环境变量配置

# Django 配置
DJANGO_SETTINGS_MODULE=your_project.settings
SECRET_KEY=your-secret-key-here
DEBUG=True

# 数据库配置
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432

# Redis 配置
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Multi-Tenant Auth 配置
MULTI_TENANT_AUTH_ENABLE_2FA=True
MULTI_TENANT_AUTH_PASSWORD_MIN_LENGTH=8
MULTI_TENANT_AUTH_SESSION_TIMEOUT_MINUTES=60
MULTI_TENANT_AUTH_MAX_LOGIN_ATTEMPTS=5
MULTI_TENANT_AUTH_TOKEN_EXPIRY_MINUTES=60
MULTI_TENANT_AUTH_REFRESH_TOKEN_EXPIRY_DAYS=7
MULTI_TENANT_AUTH_REQUIRE_EMAIL_VERIFICATION=True

# JWT 配置
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_LIFETIME=60
JWT_REFRESH_TOKEN_LIFETIME=604800

# CORS 配置
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# 缓存配置
CACHE_TIMEOUT=300

# 邮件配置
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-email-password

# 安全配置
SECURE_SSL_REDIRECT=False
SECURE_HSTS_SECONDS=0
SECURE_HSTS_INCLUDE_SUBDOMAINS=False
SECURE_HSTS_PRELOAD=False
"""

    # 写入文件
    filename = f"multi_tenant_auth_config.{args.format}"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(config_content)

    print(f"配置文件已生成: {filename}")
    print("请根据您的项目需求修改配置内容。")


def check_permission(args):
    """检查用户权限"""
    try:
        import django
        import os
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
        django.setup()

        from multi_tenant_auth.services import PermissionService

        permission_service = PermissionService()

        # 检查权限
        has_permission = permission_service.check_permission(
            user_id=args.user_id,
            workspace_id=args.workspace_id,
            action=args.action
        )

        if has_permission:
            print(f"✅ 用户 {args.user_id} 在工作空间 {args.workspace_id} 中拥有 '{args.action}' 权限")
        else:
            print(f"❌ 用户 {args.user_id} 在工作空间 {args.workspace_id} 中没有 '{args.action}' 权限")

    except Exception as e:
        print(f"❌ 权限检查失败: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()