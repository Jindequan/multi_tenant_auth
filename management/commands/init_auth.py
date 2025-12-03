"""
初始化Multi-Tenant Auth库
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from ...db import db_manager
from ...migrations import migration_manager
from ...conf import auth_settings


class Command(BaseCommand):
    help = 'Initialize Multi-Tenant Auth library - 一键式初始化'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-initialization (WARNING: will reset migration history)'
        )
        parser.add_argument(
            '--create-schema',
            action='store_true',
            default=True,
            help='Create database schema'
        )

    def handle(self, *args, **options):
        """执行初始化"""
        try:
            # 1. 检查基本配置
            self.stdout.write("🔍 Checking configuration...")
            self._check_basic_config()
            self.stdout.write("✅ Configuration checked")

            # 2. 测试数据库连接
            self.stdout.write("🔗 Testing database connection...")
            if not db_manager.test_connection():
                raise CommandError("Database connection failed")

            self.stdout.write("✅ Database connection successful")

            # 3. 强制重置迁移历史
            if options['force']:
                self.stdout.write("⚠️  Force mode: resetting migration history...")
                migration_manager.reset_migrations()
                self.stdout.write("✅ Migration history reset")

            # 4. 创建schema
            if options['create_schema']:
                self.stdout.write("🏗️  Creating database schema...")
                db_manager.create_schema_if_not_exists()
                self.stdout.write("✅ Database schema created")

            # 5. 运行迁移
            self.stdout.write("🚀 Running migrations...")
            with transaction.atomic():
                success_count = migration_manager.migrate()

            if success_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Successfully ran {success_count} migrations')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS('✅ No pending migrations')
                )

            # 6. 验证安装
            self.stdout.write("🔍 Verifying installation...")
            self._verify_installation()
            self.stdout.write("✅ Installation verified")

            self.stdout.write(
                self.style.SUCCESS('\n🎉 Multi-Tenant Auth library initialized successfully!')
            )

            # 7. 显示使用指南
            self._show_usage_guide()

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Initialization failed: {str(e)}')
            )
            raise CommandError(f"Initialization failed: {str(e)}")

    def _verify_installation(self):
        """验证安装"""
        # 验证表是否创建成功
        expected_tables = [
            '"multi_tenant_auth"."user"',
            '"multi_tenant_auth"."team"',
            '"multi_tenant_auth"."team_member"',
            '"multi_tenant_auth"."workspace"',
            '"multi_tenant_auth"."user_workspace_actions"',
            '"multi_tenant_auth"."audit_log"'
        ]

        with db_manager.get_cursor() as cursor:
            for table in expected_tables:
                cursor.execute(f"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'multi_tenant_auth' AND table_name = {table.split('.')[1].replace('"', '')})")
                exists = cursor.fetchone()[0]
                if not exists:
                    raise CommandError(f"Table {table} does not exist")

    def _show_usage_guide(self):
        """显示使用指南"""
        self.stdout.write('\n' + '='*60)
        self.stdout.write('📖 USAGE GUIDE')
        self.stdout.write('='*60)
        self.stdout.write('\n1. Add to settings.py:')
        self.stdout.write('   INSTALLED_APPS = [')
        self.stdout.write('       # ... your apps')
        self.stdout.write('       "multi_tenant_auth",')
        self.stdout.write('   ]')
        self.stdout.write('\n2. Add to urls.py:')
        self.stdout.write('   from django.urls import path, include')
        self.stdout.write('   urlpatterns = [')
        self.stdout.write('       # ... your urls')
        self.stdout.write('       path("api/auth/", include("multi_tenant_auth.api.urls")),')
        self.stdout.write('   ]')
        self.stdout.write('\n3. Create superuser:')
        self.stdout.write('   python manage.py create_auth_admin')
        self.stdout.write('\n4. Check status:')
        self.stdout.write('   python manage.py check_auth_config')
        self.stdout.write('\n' + '='*60)

    def _check_basic_config(self):
        """检查基本配置"""
        from django.core.exceptions import ImproperlyConfigured

        try:
            # 检查数据库配置
            if not auth_settings.DB_NAME:
                raise ImproperlyConfigured(
                    "Database name is required. Configure DATABASES['default']['NAME'] in settings.py"
                )

            # 检查JWT密钥
            if not auth_settings.JWT_SECRET_KEY:
                raise ImproperlyConfigured(
                    "JWT secret key is required. Configure SECRET_KEY in settings.py"
                )

        except ImproperlyConfigured as e:
            raise CommandError(f"Configuration error: {str(e)}")
        except AttributeError as e:
            raise CommandError(f"Configuration missing: {str(e)}")