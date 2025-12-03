"""
Multi-Tenant Auth 独立迁移管理器
"""

import os
import psycopg2
from pathlib import Path
from typing import List, Optional

from ..db import db_manager
from ..config import auth_config


class AuthMigrationManager:
    """认证库专用迁移管理器"""

    def __init__(self):
        self.migrations_dir = Path(__file__).parent / 'sql'
        self.schema_name = auth_config.get('MULTI_TENANT_AUTH_DB_SCHEMA')

    def ensure_schema_exists(self):
        """确保schema存在"""
        with db_manager.get_cursor() as cursor:
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {self.schema_name}")
            cursor.execute(f"SET search_path TO {self.schema_name}, public")

    def ensure_migration_table(self):
        """确保迁移记录表存在"""
        with db_manager.get_cursor() as cursor:
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.schema_name}.migration_history (
                    id SERIAL PRIMARY KEY,
                    migration_name VARCHAR(255) UNIQUE NOT NULL,
                    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

    def get_executed_migrations(self) -> set:
        """获取已执行的迁移"""
        with db_manager.get_cursor() as cursor:
            cursor.execute(f"""
                SELECT migration_name FROM {self.schema_name}.migration_history
                ORDER BY migration_name;
            """)
            return {row[0] for row in cursor.fetchall()}

    def get_pending_migrations(self) -> List[str]:
        """获取待执行的迁移"""
        all_migrations = sorted([
            f.stem for f in self.migrations_dir.glob('*.sql')
        ])
        executed = self.get_executed_migrations()
        return [m for m in all_migrations if m not in executed]

    def execute_migration(self, migration_name: str) -> bool:
        """执行单个迁移"""
        migration_file = self.migrations_dir / f'{migration_name}.sql'

        if not migration_file.exists():
            raise FileNotFoundError(f"Migration file not found: {migration_file}")

        with open(migration_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()

        # 替换schema占位符
        sql_content = sql_content.replace('{{SCHEMA}}', self.schema_name)

        try:
            with db_manager.get_cursor() as cursor:
                # 分割SQL语句（按分号分割）
                statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]

                for statement in statements:
                    if statement:
                        cursor.execute(statement)

                # 记录迁移历史
                cursor.execute(f"""
                    INSERT INTO {self.schema_name}.migration_history (migration_name)
                    VALUES (%s);
                """, [migration_name])

            return True

        except Exception as e:
            print(f"Migration {migration_name} failed: {str(e)}")
            return False

    def migrate(self) -> int:
        """执行所有待执行的迁移"""
        print("Starting Multi-Tenant Auth migrations...")

        # 确保schema和迁移表存在
        self.ensure_schema_exists()
        self.ensure_migration_table()

        pending = self.get_pending_migrations()

        if not pending:
            print("No pending migrations.")
            return 0

        print(f"Running {len(pending)} migrations:")
        success_count = 0

        for migration_name in pending:
            print(f"  - {migration_name}", end=' ')
            if self.execute_migration(migration_name):
                print("✅")
                success_count += 1
            else:
                print("❌")

        print(f"Migrations completed: {success_count}/{len(pending)} successful")
        return success_count

    def get_migration_status(self) -> dict:
        """获取迁移状态"""
        self.ensure_migration_table()
        executed = self.get_executed_migrations()
        all_migrations = sorted([f.stem for f in self.migrations_dir.glob('*.sql')])

        return {
            'total': len(all_migrations),
            'executed': len(executed),
            'pending': len(all_migrations) - len(executed),
            'executed_list': sorted(executed),
            'pending_list': [m for m in all_migrations if m not in executed]
        }

    def reset_migrations(self):
        """重置迁移记录（谨慎使用）"""
        confirm = input("⚠️  This will reset all migration records. Are you sure? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Operation cancelled.")
            return

        with db_manager.get_cursor() as cursor:
            cursor.execute(f"DELETE FROM {self.schema_name}.migration_history")

        print("Migration history reset.")