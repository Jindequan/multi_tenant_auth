from django.apps import AppConfig
from django.conf import settings


class MultiTenantAuthConfig(AppConfig):
    """Multi-Tenant Auth 应用配置"""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'multi_tenant_auth'
    verbose_name = 'Multi-Tenant Auth'

    def ready(self):
        """应用初始化时的配置 - 极简版本"""
        # 只在开发模式下自动运行，生产环境需要手动初始化
        from django.conf import settings

        if getattr(settings, 'DEBUG', False):
            try:
                # 检查基本配置
                from .conf import auth_settings
                # 这会触发配置验证
                _ = auth_settings.DB_NAME
                _ = auth_settings.JWT_SECRET_KEY

                print("✅ Multi-Tenant Auth Library configuration validated")
                print("💡 Run 'python manage.py init_auth' to complete initialization")

            except Exception as e:
                print(f"⚠️ Multi-Tenant Auth Library configuration issue: {str(e)}")
                print("💡 Run 'python manage.py init_auth' to initialize")
        else:
            print("🎉 Multi-Tenant Auth Library loaded!")