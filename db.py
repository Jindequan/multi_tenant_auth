"""
Multi-Tenant Auth 数据库连接管理
"""

import threading
from contextlib import contextmanager
from typing import Optional
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from .config import auth_config


class AuthDatabaseManager:
    """认证库专用数据库管理器"""

    _instance = None
    _lock = threading.Lock()
    _pool: Optional[ThreadedConnectionPool] = None

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialize_pool()
            self._initialized = True

    def _initialize_pool(self):
        """初始化连接池"""
        db_config = auth_config.database_config

        try:
            self._pool = ThreadedConnectionPool(
                minconn=2,
                maxconn=20,
                **db_config
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize database pool: {str(e)}")

    @contextmanager
    def get_connection(self):
        """获取数据库连接的上下文管理器"""
        if self._pool is None:
            raise RuntimeError("Database pool not initialized")

        conn = None
        try:
            conn = self._pool.getconn()
            yield conn
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                self._pool.putconn(conn)

    @contextmanager
    def get_cursor(self, commit=True):
        """获取数据库游标的上下文管理器"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    yield cursor
                    if commit:
                        conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def execute_query(self, query: str, params: tuple = None, fetch_one=False, fetch_all=True):
        """执行查询并返回结果"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())

            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                return None

    def create_schema_if_not_exists(self):
        """创建schema如果不存在"""
        with self.get_cursor() as cursor:
            schema_name = auth_config.get('MULTI_TENANT_AUTH_DB_SCHEMA')

            # 创建schema
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")

            # 设置默认search_path
            cursor.execute(f"SET search_path TO {schema_name}, public")

    def test_connection(self):
        """测试数据库连接"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    return True
        except Exception:
            return False

    def close(self):
        """关闭连接池"""
        if self._pool:
            self._pool.closeall()
            self._pool = None

    def get_pool_status(self):
        """获取连接池状态"""
        if self._pool:
            return {
                'minconn': self._pool.minconn,
                'maxconn': self._pool.maxconn,
                'closed': self._pool.closed
            }
        return None


# 全局数据库管理器实例
db_manager = AuthDatabaseManager()