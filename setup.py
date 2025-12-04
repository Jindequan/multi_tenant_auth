"""
Multi-Tenant Auth Library
极简、高效的多租户认证权限管理库
"""

from setuptools import setup, find_packages
import os

# 读取 README 文件
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Multi-Tenant Auth Library - 极简多租户认证权限管理库"

# 读取 requirements 文件
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="multi-tenant-auth",
    version="1.0.0",
    author="Jindequan",
    author_email="jindequan@example.com",
    description="极简多租户认证权限管理库 - 开源免费，禁止商业化",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Jindequan/multi_tenant_auth",
    project_urls={
        "Bug Reports": "https://github.com/Jindequan/multi_tenant_auth/issues",
        "Source": "https://github.com/Jindequan/multi_tenant_auth",
        "Documentation": "https://github.com/Jindequan/multi_tenant_auth/wiki",
        "Changelog": "https://github.com/Jindequan/multi_tenant_auth/blob/main/CHANGELOG.md",
        "Commercial License": "mailto:jindequan@example.com",
    },
    packages=find_packages(exclude=["tests*", "docs*", "examples*"]),
    include_package_data=True,
    package_data={
        "multi_tenant_auth": [
            "templates/**/*",
            "static/**/*",
            "locale/**/*",
            "fixtures/**/*",
            "management/**/*",
            "migrations/**/*",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.1",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.0",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
    ],
    keywords="django multi-tenant authentication authorization saas workspace team rbac",
    python_requires=">=3.8",
    install_requires=[
        "Django>=3.2,<5.1",
        "djangorestframework>=3.14.0",
        "djangorestframework-simplejwt>=5.2.0",
        "django-cors-headers>=4.0.0",
        "python-decouple>=3.8",
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0",
        "psycopg2-binary>=2.9.0",
        "redis>=4.5.0",
        "celery>=5.3.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-django>=4.5.0",
            "pytest-cov>=4.1.0",
            "black>=23.3.0",
            "flake8>=6.0.0",
            "isort>=5.12.0",
            "mypy>=1.4.0",
            "factory-boy>=3.2.0",
            "faker>=18.6.0",
        ],
        "docs": [
            "Sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinxcontrib-django>=2.0",
        ],
        "monitoring": [
            "sentry-sdk>=1.25.0",
            "prometheus-client>=0.16.0",
        ],
        "cache": [
            "django-redis>=5.2.0",
            "django-cacheops>=7.0.0",
        ],
        "aws": [
            "boto3>=1.26.0",
            "django-storages>=1.13.0",
        ],
        "all": [
            "pytest>=7.4.0",
            "pytest-django>=4.5.0",
            "pytest-cov>=4.1.0",
            "black>=23.3.0",
            "flake8>=6.0.0",
            "isort>=5.12.0",
            "mypy>=1.4.0",
            "factory-boy>=3.2.0",
            "faker>=18.6.0",
            "Sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinxcontrib-django>=2.0",
            "sentry-sdk>=1.25.0",
            "prometheus-client>=0.16.0",
            "django-redis>=5.2.0",
            "django-cacheops>=7.0.0",
            "boto3>=1.26.0",
            "django-storages>=1.13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "multi-tenant-auth=multi_tenant_auth.cli:main",
        ],
        "django.apps": [
            "multi_tenant_auth=multi_tenant_auth.apps.MultiTenantAuthConfig",
        ],
    },
    zip_safe=False,
    platforms=["any"],
    license="MIT",
    test_suite="tests",
)