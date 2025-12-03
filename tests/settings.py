"""
Django测试配置 - 用于Multi-Tenant Auth Library测试
"""

import os
import uuid

# 基础配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEBUG = True
SECRET_KEY = 'test-secret-key-for-testing-only-please-change-in-production'
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'testserver']

# 应用配置
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'rest_framework',
    'corsheaders',
    'multi_tenant_auth',
    'multi_tenant_auth.tests',  # 测试应用
]

# 中间件
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'multi_tenant_auth.middleware.JWTAuthMiddleware',
]

# URL配置
ROOT_URLCONF = 'tests.urls'

# 数据库配置 - 使用内存数据库
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # 内存数据库，测试速度最快
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# 国际化
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# 静态文件
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# 模板配置
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'tests', 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'debug': True,
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# 缓存配置 - 使用本地内存缓存
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'test-cache',
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
            'CULL_FREQUENCY': 3,
        }
    },
    'permissions': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'permissions-cache',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 5000,
            'CULL_FREQUENCY': 3,
        }
    }
}

# REST Framework配置
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'multi_tenant_auth.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'TEST_REQUEST_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
    ],
}

# CORS配置
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Multi-Tenant Auth配置
MULTI_TENANT_AUTH = {
    # JWT配置
    'JWT_SECRET_KEY': SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_ACCESS_TOKEN_LIFETIME': 60 * 15,  # 15分钟
    'JWT_REFRESH_TOKEN_LIFETIME': 60 * 60 * 24 * 7,  # 7天

    # 数据库配置
    'DB_SCHEMA': 'multi_tenant_auth',  # 测试时会自动创建
    'DB_SSLMODE': 'disable',  # 测试环境不需要SSL

    # 缓存配置
    'CACHE_TIMEOUT': 300,  # 5分钟
    'CACHE_PREFIX': 'multi_tenant_auth_test',
    'CACHE_BACKEND': 'permissions',  # 使用专门的permissions缓存

    # 功能开关
    'ENABLE_REGISTRATION': True,
    'ENABLE_EMAIL_VERIFICATION': False,  # 测试环境关闭
    'ENABLE_PASSWORD_RESET': True,
    'ENABLE_AUDIT_LOG': True,
    'ENABLE_WORKSPACE_CREATION': True,
    'ENABLE_TEAM_MANAGEMENT': True,

    # 安全配置（测试环境放宽）
    'MAX_LOGIN_ATTEMPTS': 10,  # 测试时可以更多尝试
    'LOGIN_ATTEMPT_TIMEOUT': 300,  # 5分钟
    'PASSWORD_MIN_LENGTH': 6,  # 测试环境降低要求
    'PASSWORD_REQUIRE_UPPERCASE': False,
    'PASSWORD_REQUIRE_LOWERCASE': False,
    'PASSWORD_REQUIRE_NUMBERS': False,
    'PASSWORD_REQUIRE_SYMBOLS': False,

    # 权限配置
    'DEFAULT_ROLES': {
        'owner': ['view', 'edit', 'delete', 'share', 'manage', 'admin'],
        'admin': ['view', 'edit', 'delete', 'share', 'manage'],
        'editor': ['view', 'edit', 'share', 'comment'],
        'viewer': ['view'],
        'commenter': ['view', 'comment'],
    },

    # 限制配置（测试环境放宽）
    'MAX_WORKSPACES_PER_USER': 1000,
    'MAX_TEAMS_PER_WORKSPACE': 100,
    'MAX_MEMBERS_PER_TEAM': 10000,
    'MAX_PERMISSIONS_PER_USER': 10000,

    # API配置
    'API_VERSION': 'v1',
    'API_PREFIX': 'api/auth',
    'ENABLE_DOCS': True,
    'ENABLE_CORS': True,

    # 测试特定配置
    'TESTING': True,
    'AUTO_CREATE_USER': True,
    'AUTO_GRANT_PERMISSIONS': True,
}

# 日志配置
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'test.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'multi_tenant_auth': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'tests': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# 测试配置
TESTING = True
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# 密码验证（测试环境使用简单验证）
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 6,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
]

# 文件上传配置（测试环境）
MEDIA_ROOT = os.path.join(BASE_DIR, 'test_media')
MEDIA_URL = '/test_media/'

# 文件存储配置
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB

# CSRF配置（测试环境可能需要）
CSRF_COOKIE_SECURE = False
CSRF_USE_SESSIONS = False
CSRF_COOKIE_HTTPONLY = False

# Session配置
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

# 测试特定的设置
SILENCED_SYSTEM_CHECKS = [
    'security.W001',  # HTTPS测试环境不需要
    'security.W002',  # HTTPS测试环境不需要
    'security.W004',  # HTTPS测试环境不需要
    'security.W008',  # SSL测试环境不需要
    'security.W009',  # HTTPS测试环境不需要
    'security.W012',  # Cookie secure测试环境不需要
]

# 邮件后端（测试环境不发送真实邮件）
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# 国际化配置
USE_THOUSAND_SEPARATOR = False
USE_X_FORWARDED_HOST = False
USE_X_FORWARDED_PORT = False

# 安全中间件配置
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SECURE_HSTS_SECONDS = 0
SECURE_REDIRECT_EXEMPT = []
SECURE_SSL_HOST = None
SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = None

# 自定义测试配置
CUSTOM_TEST_SETTINGS = {
    'SKIP_MIGRATIONS': True,  # 跳过迁移，使用SQL直接创建表
    'USE_TEST_FIXTURES': True,
    'FIXTURE_DIRS': [os.path.join(BASE_DIR, 'tests', 'fixtures')],
}

# 测试数据库优化
TEST_NON_SERIALIZED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
]

# 测试数据库配置
TEST_DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # 每次测试都使用新的内存数据库
        'OPTIONS': {
            'timeout': 30,
        }
    }
}

# 测试缓存配置
TEST_CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': f'test-cache-{uuid.uuid4()}',
    },
    'permissions': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': f'permissions-cache-{uuid.uuid4()}',
        'TIMEOUT': 300,
    }
}

# 测试时的性能监控
TEST_PERFORMANCE_MONITORING = True
TEST_PERFORMANCE_LOG_FILE = os.path.join(BASE_DIR, 'test_performance.log')

# 测试覆盖率配置
COVERAGE_ENABLED = True
COVERAGE_REPORT_HTML_DIR = os.path.join(BASE_DIR, 'htmlcov')
COVERAGE_REPORT_XML_FILE = os.path.join(BASE_DIR, 'coverage.xml')

# 测试数据生成配置
TEST_DATA_GENERATION = {
    'AUTO_CREATE_USERS': 5,
    'AUTO_CREATE_WORKSPACES': 10,
    'AUTO_CREATE_TEAMS': 3,
    'AUTO_GENERATE_PERMISSIONS': True,
}

# 模拟外部服务的配置
MOCK_EXTERNAL_SERVICES = True
MOCK_EMAIL_SERVICE = True
MOCK_PAYMENT_SERVICE = True
MOCK_NOTIFICATION_SERVICE = True

# API测试配置
API_TESTING = True
API_TEST_BASE_URL = 'http://testserver'
API_TEST_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}

# 并发测试配置
CONCURRENT_TESTING = True
CONCURRENT_TEST_THREADS = 10
CONCURRENT_TEST_REQUESTS = 100

# 集成测试配置
INTEGRATION_TESTING = True
INTEGRATION_TEST_SERVICES = [
    'database',
    'cache',
    'email',
    'storage',
]

# 安全测试配置
SECURITY_TESTING = True
SECURITY_TEST_SCENARIOS = [
    'sql_injection',
    'xss',
    'csrf',
    'authentication_bypass',
    'privilege_escalation',
]

# 压力测试配置
STRESS_TESTING = False  # 默认关闭，需要时手动开启
STRESS_TEST_USERS = 1000
STRESS_TEST_WORKSPACES = 5000
STRESS_TEST_DURATION = 3600  # 1小时

# 测试清理配置
TEST_CLEANUP = {
    'CLEANUP_AFTER_TEST': True,
    'CLEANUP_TEMP_FILES': True,
    'CLEANUP_CACHE': True,
    'CLEANUP_SESSIONS': True,
}

# 测试报告配置
TEST_REPORTING = True
TEST_REPORT_DIR = os.path.join(BASE_DIR, 'test_reports')
TEST_REPORT_FORMATS = ['html', 'xml', 'json']

# 调试配置
TEST_DEBUG = False  # 设置为True可以看到详细的调试信息

# 性能基准配置
PERFORMANCE_BENCHMARKS = {
    'permission_check_max_time': 0.01,  # 10ms
    'login_max_time': 0.05,  # 50ms
    'registration_max_time': 0.1,  # 100ms
    'permission_grant_max_time': 0.02,  # 20ms
}

# 测试环境特定的导入
try:
    from .local_test_settings import *  # 本地测试配置，如果存在
except ImportError:
    pass