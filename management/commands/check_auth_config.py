"""
检查Multi-Tenant Auth配置
"""

from django.core.management.base import BaseCommand, CommandError

from ...config import auth_config
from ...db import db_manager


class Command(BaseCommand):
    help = 'Check Multi-Tenant Auth configuration'

    def handle(self, *args, **options):
        """执行配置检查"""
        self.stdout.write("🔍 Checking Multi-Tenant Auth configuration...")
        self.stdout.write("="*60)

        try:
            # 检查配置项
            self.stdout.write("\n📋 Configuration Variables:")
            self.stdout.write(f"  🗄️  Database: {auth_config.get('MULTI_TENANT_AUTH_DB_NAME')}")
            self.stdout.write(f"  👤 User: {auth_config.get('MULTI_TENANT_AUTH_DB_USER')}")
            self.stdout.write(f"  🌐 Host: {auth_config.get('MULTI_TENANT_AUTH_DB_HOST')}")
            self.stdout.write(f"  🔌 Port: {auth_config.get('MULTI_TENANT_AUTH_DB_PORT')}")
            self.stdout.write(f"  🗂️  Schema: {auth_config.get('MULTI_TENANT_AUTH_DB_SCHEMA')}")
            self.stdout.write(f"  🔐 JWT Secret: {'✅ Set' if auth_config.get('MULTI_TENANT_AUTH_JWT_SECRET_KEY') else '❌ Missing'}")

            # 检查可选配置
            self.stdout.write(f"\n⚙️  Optional Settings:")
            self.stdout.write(f"  🕐  Cache Timeout: {auth_config.get('MULTI_TENANT_AUTH_CACHE_TIMEOUT')}s")
            self.stdout.write(f"  📧  Invite Lifetime: {auth_config.get('MULTI_TENANT_AUTH_INVITE_TOKEN_LIFETIME')}s")
            self.stdout.write(f"  🚪  Max Login Attempts: {auth_config.get('MULTI_TENANT_AUTH_MAX_LOGIN_ATTEMPTS')}")
            self.stdout.write(f"  ⏰  Login Attempt Timeout: {auth_config.get('MULTI_TENANT_AUTH_LOGIN_ATTEMPT_TIMEOUT')}s")

            # 检查数据库连接
            self.stdout.write(f"\n🔗 Database Connection:")
            if db_manager.test_connection():
                self.stdout.write(f"  ✅ Connection successful")
            else:
                self.stdout.write(f"  ❌ Connection failed")
                raise CommandError("Database connection failed")

            # 检查连接池状态
            pool_status = db_manager.get_pool_status()
            if pool_status:
                self.stdout.write(f"\n🏊  Connection Pool:")
                self.stdout.write(f"  📊  Min Connections: {pool_status['minconn']}")
                self.stdout.write(f"  📊  Max Connections: {pool_status['maxconn']}")
                self.stdout.write(f"  🔒  Closed: {pool_status['closed']}")

            # 检查schema是否存在
            with db_manager.get_cursor() as cursor:
                schema_name = auth_config.get('MULTI_TENANT_AUTH_DB_SCHEMA')
                cursor.execute(f"SELECT schema_name FROM information_schema.schemata WHERE schema_name = '{schema_name}'")
                schema_exists = cursor.fetchone() is not None

                self.stdout.write(f"\n🗂️  Database Schema:")
                if schema_exists:
                    self.stdout.write(f"  ✅ Schema '{schema_name}' exists")

                    # 检查表是否存在
                    cursor.execute(f"""
                        SELECT table_name FROM information_schema.tables
                        WHERE table_schema = '{schema_name}'
                        ORDER BY table_name
                    """)
                    tables = [row[0] for row in cursor.fetchall()]

                    expected_tables = [
                        'user', 'team', 'team_member',
                        'workspace', 'user_workspace_actions', 'audit_log'
                    ]

                    self.stdout.write(f"  📊  Tables Found: {len(tables)}/{len(expected_tables)}")

                    for table in expected_tables:
                        status = "✅" if table in tables else "❌"
                        self.stdout.write(f"    {status} {table}")
                else:
                    self.stdout.write(f"  ❌ Schema '{schema_name}' does not exist")
                    self.stdout.write("  💡 Run 'python manage.py init_auth' to create the schema and tables")

            # 检查JWT密钥长度
            jwt_key = auth_config.get('MULTI_TENANT_AUTH_JWT_SECRET_KEY')
            if len(jwt_key) < 32:
                self.stdout.write(f"\n🔐 JWT Secret Key:")
                self.stdout.write(f"  ⚠️  Length: {len(jwt_key)} (recommended: 32+)")
                self.stdout.write(f"  💡  Consider using a longer secret key for better security")

            self.stdout.write(f"\n{'='*60}")
            self.stdout.write(self.style.SUCCESS('✅ Configuration check completed!'))

        except Exception as e:
            self.stdout.write(f"\n❌ Configuration check failed: {str(e)}")
            raise CommandError(f"Configuration check failed: {str(e)}")