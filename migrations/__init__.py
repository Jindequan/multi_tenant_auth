"""
Multi-Tenant Auth 迁移系统
"""

from .migrator import AuthMigrationManager

# 全局迁移管理器
migration_manager = AuthMigrationManager()