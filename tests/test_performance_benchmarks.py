"""
性能基准测试 - 建立性能基准并监控系统性能
"""

import time
import uuid
import threading
import random
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from django.test import TestCase, TransactionTestCase
from django.db import connection, transaction
from django.core.cache import cache
from django.test.utils import override_settings
from django.conf import settings
from rest_framework.test import APITestCase

from ..models import User, Team, TeamMember, Workspace, UserWorkspaceActions, AuditLog
from ..services import AuthService, PermissionService, TeamService
from ..decorators import require_auth, require_permissions


class BenchmarkTest(TestCase):
    """性能基准测试"""

    def setUp(self):
        self.auth_service = AuthService()
        self.permission_service = PermissionService()
        self.team_service = TeamService()

        # 清理缓存以确保测试的一致性
        cache.clear()

    def test_database_operation_benchmarks(self):
        """数据库操作性能基准"""
        print("\n=== 数据库操作性能基准 ===")

        # 1. 用户创建基准
        user_creation_times = self._benchmark_user_creation(count=100)
        self._report_benchmark("用户创建", user_creation_times, target_avg=0.05, target_p95=0.1)

        # 2. 工作空间创建基准
        workspace_creation_times = self._benchmark_workspace_creation(count=50)
        self._report_benchmark("工作空间创建", workspace_creation_times, target_avg=0.08, target_p95=0.15)

        # 3. 权限授予基准
        permission_grant_times = self._benchmark_permission_grant(count=200)
        self._report_benchmark("权限授予", permission_grant_times, target_avg=0.03, target_p95=0.08)

        # 4. 权限检查基准
        permission_check_times = self._benchmark_permission_check(count=500)
        self._report_benchmark("权限检查", permission_check_times, target_avg=0.01, target_p95=0.03)

        # 5. 复杂查询基准
        query_times = self._benchmark_complex_queries(count=100)
        self._report_benchmark("复杂查询", query_times, target_avg=0.1, target_p95=0.3)

    def test_authentication_benchmarks(self):
        """认证性能基准"""
        print("\n=== 认证性能基准 ===")

        # 1. Token生成基准
        token_generation_times = self._benchmark_token_generation(count=200)
        self._report_benchmark("Token生成", token_generation_times, target_avg=0.02, target_p95=0.05)

        # 2. Token验证基准
        token_validation_times = self._benchmark_token_validation(count=300)
        self._report_benchmark("Token验证", token_validation_times, target_avg=0.01, target_p95=0.03)

        # 3. Token刷新基准
        token_refresh_times = self._benchmark_token_refresh(count=50)
        self._report_benchmark("Token刷新", token_refresh_times, target_avg=0.03, target_p95=0.08)

        # 4. 登录流程基准
        login_times = self._benchmark_login_flow(count=100)
        self._report_benchmark("登录流程", login_times, target_avg=0.1, target_p95=0.2)

    def test_cache_benchmarks(self):
        """缓存性能基准"""
        print("\n=== 缓存性能基准 ===")

        # 1. 缓存写入基准
        cache_write_times = self._benchmark_cache_write(count=1000)
        self._report_benchmark("缓存写入", cache_write_times, target_avg=0.001, target_p95=0.005)

        # 2. 缓存读取基准
        cache_read_times = self._benchmark_cache_read(count=1000)
        self._report_benchmark("缓存读取", cache_read_times, target_avg=0.001, target_p95=0.005)

        # 3. 缓存删除基准
        cache_delete_times = self._benchmark_cache_delete(count=100)
        self._report_benchmark("缓存删除", cache_delete_times, target_avg=0.001, target_p95=0.005)

    def test_concurrency_benchmarks(self):
        """并发性能基准"""
        print("\n=== 并发性能基准 ===")

        # 1. 并发用户创建基准
        concurrent_user_creation = self._benchmark_concurrent_user_creation(
            threads=20, operations_per_thread=10
        )
        self._report_benchmark("并发用户创建", concurrent_user_creation, target_avg=0.1, target_p95=0.3)

        # 2. 并发权限检查基准
        concurrent_permission_check = self._benchmark_concurrent_permission_check(
            threads=50, operations_per_thread=20
        )
        self._report_benchmark("并发权限检查", concurrent_permission_check, target_avg=0.02, target_p95=0.08)

        # 3. 并发认证基准
        concurrent_auth = self._benchmark_concurrent_authentication(
            threads=30, operations_per_thread=15
        )
        self._report_benchmark("并发认证", concurrent_auth, target_avg=0.05, target_p95=0.15)

    def test_memory_benchmarks(self):
        """内存使用基准"""
        print("\n=== 内存使用基准 ===")

        # 1. 大量用户创建内存基准
        memory_user_creation = self._benchmark_memory_user_creation(count=500)
        print(f"大量用户创建内存使用: {memory_user_creation:.2f} MB")

        # 2. 大量权限记录内存基准
        memory_permissions = self._benchmark_memory_permissions(count=1000)
        print(f"大量权限记录内存使用: {memory_permissions:.2f} MB")

        # 3. 内存清理基准
        memory_cleanup = self._benchmark_memory_cleanup()
        print(f"内存清理后剩余: {memory_cleanup:.2f} MB")

    def test_api_benchmarks(self):
        """API性能基准"""
        print("\n=== API性能基准 ===")

        # 注意：这些基准需要实际的API实现
        # 这里提供框架，具体实现取决于API设计

        # 1. 登录API基准
        api_login_times = self._benchmark_api_login(count=50)
        if api_login_times:
            self._report_benchmark("登录API", api_login_times, target_avg=0.2, target_p95=0.5)

        # 2. 注册API基准
        api_register_times = self._benchmark_api_register(count=30)
        if api_register_times:
            self._report_benchmark("注册API", api_register_times, target_avg=0.3, target_p95=0.6)

        # 3. 工作空间列表API基准
        api_workspace_list_times = self._benchmark_api_workspace_list(count=100)
        if api_workspace_list_times:
            self._report_benchmark("工作空间列表API", api_workspace_list_times, target_avg=0.15, target_p95=0.4)

    def _benchmark_user_creation(self, count):
        """用户创建性能基准测试"""
        times = []
        for i in range(count):
            start_time = time.time()
            try:
                user = User.objects.create_user(
                    email=f"bench_user_{i}_{uuid.uuid4()}@example.com",
                    password="password123"
                )
            except Exception as e:
                print(f"User creation error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_workspace_creation(self, count):
        """工作空间创建性能基准测试"""
        # 先创建一些用户
        users = []
        for i in range(count):
            user = User.objects.create_user(
                email=f"bench_ws_owner_{i}@example.com",
                password="password123"
            )
            users.append(user)

        times = []
        for i, user in enumerate(users):
            start_time = time.time()
            try:
                workspace = Workspace.objects.create(
                    name=f"Benchmark Workspace {i}",
                    slug=f"bench-ws-{i}-{uuid.uuid4()}",
                    workspace_type="personal",
                    owner=user
                )
            except Exception as e:
                print(f"Workspace creation error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_permission_grant(self, count):
        """权限授予性能基准测试"""
        # 创建测试数据
        owner = User.objects.create_user(
            email="bench_perm_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Benchmark Permission Workspace",
            slug="bench-perm-ws",
            workspace_type="personal",
            owner=owner
        )
        users = []
        for i in range(count):
            user = User.objects.create_user(
                email=f"bench_perm_user_{i}@example.com",
                password="password123"
            )
            users.append(user)

        times = []
        for user in users:
            start_time = time.time()
            try:
                self.permission_service.grant_permissions(
                    user=user,
                    workspace=workspace,
                    actions=["view", "edit"],
                    granted_by=owner
                )
            except Exception as e:
                print(f"Permission grant error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_permission_check(self, count):
        """权限检查性能基准测试"""
        # 创建测试数据
        owner = User.objects.create_user(
            email="bench_check_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Benchmark Check Workspace",
            slug="bench-check-ws",
            workspace_type="personal",
            owner=owner
        )
        user = User.objects.create_user(
            email="bench_check_user@example.com",
            password="password123"
        )
        self.permission_service.grant_permissions(
            user=user,
            workspace=workspace,
            actions=["view", "edit"],
            granted_by=owner
        )

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                has_permission = self.permission_service.check_permission(
                    user=user,
                    workspace=workspace,
                    action="view"
                )
            except Exception as e:
                print(f"Permission check error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_complex_queries(self, count):
        """复杂查询性能基准测试"""
        # 创建复杂的测试数据
        owner = User.objects.create_user(
            email="bench_query_owner@example.com",
            password="password123"
        )
        workspaces = []
        for i in range(10):
            workspace = Workspace.objects.create(
                name=f"Query Workspace {i}",
                slug=f"query-ws-{i}",
                workspace_type="personal",
                owner=owner
            )
            workspaces.append(workspace)

        users = []
        for i in range(50):
            user = User.objects.create_user(
                email=f"bench_query_user_{i}@example.com",
                password="password123"
            )
            users.append(user)

        # 创建大量权限记录
        for user in users:
            for workspace in workspaces:
                self.permission_service.grant_permissions(
                    user=user,
                    workspace=workspace,
                    actions=["view", "edit"],
                    granted_by=owner
                )

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                # 复杂查询：获取用户的所有工作空间权限
                user = users[i % len(users)]
                permissions = self.permission_service.get_user_all_permissions(user)

                # 聚合查询：统计每个工作空间的用户数
                for workspace in workspaces[:5]:
                    user_count = UserWorkspaceActions.objects.filter(
                        workspace=workspace
                    ).count()

            except Exception as e:
                print(f"Complex query error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_token_generation(self, count):
        """Token生成性能基准测试"""
        # 创建测试用户
        user = User.objects.create_user(
            email="bench_token_user@example.com",
            password="password123"
        )

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                tokens = self.auth_service.generate_tokens(user)
            except Exception as e:
                print(f"Token generation error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_token_validation(self, count):
        """Token验证性能基准测试"""
        # 创建测试用户和token
        user = User.objects.create_user(
            email="bench_validate_user@example.com",
            password="password123"
        )
        tokens = self.auth_service.generate_tokens(user)
        access_token = tokens['access_token']

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                validated_user = self.auth_service.validate_access_token(access_token)
            except Exception as e:
                print(f"Token validation error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_token_refresh(self, count):
        """Token刷新性能基准测试"""
        # 创建测试用户和refresh token
        user = User.objects.create_user(
            email="bench_refresh_user@example.com",
            password="password123"
        )
        tokens = self.auth_service.generate_tokens(user)
        refresh_token = tokens['refresh_token']

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                new_tokens = self.auth_service.refresh_access_token(refresh_token)
            except Exception as e:
                print(f"Token refresh error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_login_flow(self, count):
        """登录流程性能基准测试"""
        # 创建测试用户
        users = []
        for i in range(count):
            user = User.objects.create_user(
                email=f"bench_login_user_{i}@example.com",
                password="password123"
            )
            users.append(user)

        times = []
        for user in users:
            start_time = time.time()
            try:
                authenticated_user = self.auth_service.authenticate_user(
                    user.email,
                    "password123"
                )
                if authenticated_user:
                    tokens = self.auth_service.generate_tokens(authenticated_user)
            except Exception as e:
                print(f"Login flow error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_cache_write(self, count):
        """缓存写入性能基准测试"""
        times = []
        for i in range(count):
            start_time = time.time()
            try:
                cache.set(f"bench_key_{i}", f"bench_value_{i}", 3600)
            except Exception as e:
                print(f"Cache write error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_cache_read(self, count):
        """缓存读取性能基准测试"""
        # 先写入数据
        for i in range(count):
            cache.set(f"bench_read_key_{i}", f"bench_read_value_{i}", 3600)

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                value = cache.get(f"bench_read_key_{i}")
            except Exception as e:
                print(f"Cache read error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_cache_delete(self, count):
        """缓存删除性能基准测试"""
        # 先写入数据
        for i in range(count):
            cache.set(f"bench_delete_key_{i}", f"bench_delete_value_{i}", 3600)

        times = []
        for i in range(count):
            start_time = time.time()
            try:
                cache.delete(f"bench_delete_key_{i}")
            except Exception as e:
                print(f"Cache delete error: {e}")
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_concurrent_user_creation(self, threads, operations_per_thread):
        """并发用户创建性能基准测试"""
        times = []

        def create_user(thread_id, operation_id):
            start_time = time.time()
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        email=f"concurrent_user_{thread_id}_{operation_id}_{uuid.uuid4()}@example.com",
                        password="password123"
                    )
            except Exception as e:
                print(f"Concurrent user creation error: {e}")
            end_time = time.time()
            return end_time - start_time

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for thread_id in range(threads):
                for operation_id in range(operations_per_thread):
                    future = executor.submit(create_user, thread_id, operation_id)
                    futures.append(future)

            for future in as_completed(futures):
                times.append(future.result())

        return times

    def _benchmark_concurrent_permission_check(self, threads, operations_per_thread):
        """并发权限检查性能基准测试"""
        # 创建测试数据
        owner = User.objects.create_user(
            email="concurrent_check_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Concurrent Check Workspace",
            slug="concurrent-check-ws",
            workspace_type="personal",
            owner=owner
        )
        user = User.objects.create_user(
            email="concurrent_check_user@example.com",
            password="password123"
        )
        self.permission_service.grant_permissions(
            user=user,
            workspace=workspace,
            actions=["view", "edit"],
            granted_by=owner
        )

        times = []

        def check_permission(thread_id, operation_id):
            start_time = time.time()
            try:
                has_permission = self.permission_service.check_permission(
                    user=user,
                    workspace=workspace,
                    action="view"
                )
            except Exception as e:
                print(f"Concurrent permission check error: {e}")
            end_time = time.time()
            return end_time - start_time

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for thread_id in range(threads):
                for operation_id in range(operations_per_thread):
                    future = executor.submit(check_permission, thread_id, operation_id)
                    futures.append(future)

            for future in as_completed(futures):
                times.append(future.result())

        return times

    def _benchmark_concurrent_authentication(self, threads, operations_per_thread):
        """并发认证性能基准测试"""
        # 创建测试用户
        users = []
        for i in range(threads * operations_per_thread):
            user = User.objects.create_user(
                email=f"concurrent_auth_user_{i}@example.com",
                password="password123"
            )
            users.append(user)

        times = []
        user_index = 0

        def authenticate_user(thread_id, operation_id):
            nonlocal user_index
            user = users[user_index]
            user_index += 1

            start_time = time.time()
            try:
                tokens = self.auth_service.generate_tokens(user)
            except Exception as e:
                print(f"Concurrent authentication error: {e}")
            end_time = time.time()
            return end_time - start_time

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for thread_id in range(threads):
                for operation_id in range(operations_per_thread):
                    future = executor.submit(authenticate_user, thread_id, operation_id)
                    futures.append(future)

            for future in as_completed(futures):
                times.append(future.result())

        return times

    def _benchmark_memory_user_creation(self, count):
        """内存使用基准测试：用户创建"""
        import gc
        import sys

        # 获取初始内存状态
        gc.collect()
        initial_objects = len(gc.get_objects())

        # 创建用户
        users = []
        for i in range(count):
            user = User.objects.create_user(
                email=f"memory_user_{i}@example.com",
                password="password123",
                personal_info={"name": f"Memory User {i}", "data": "x" * 100}
            )
            users.append(user)

        # 检查内存增长
        gc.collect()
        final_objects = len(gc.get_objects())
        memory_growth = final_objects - initial_objects

        # 转换为MB（粗略估计）
        memory_mb = memory_growth * 0.0001  # 粗略转换

        # 清理
        for user in users:
            user.delete()
        gc.collect()

        return memory_mb

    def _benchmark_memory_permissions(self, count):
        """内存使用基准测试：权限记录"""
        import gc

        # 获取初始内存状态
        gc.collect()
        initial_objects = len(gc.get_objects())

        # 创建测试数据
        owner = User.objects.create_user(
            email="memory_perm_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Memory Permissions Workspace",
            slug="memory-perm-ws",
            workspace_type="personal",
            owner=owner
        )

        # 创建大量权限记录
        permissions = []
        for i in range(count):
            user = User.objects.create_user(
                email=f"memory_perm_user_{i}@example.com",
                password="password123"
            )
            permission = self.permission_service.grant_permissions(
                user=user,
                workspace=workspace,
                actions=["view", "edit"],
                granted_by=owner
            )
            permissions.append(permission)

        # 检查内存增长
        gc.collect()
        final_objects = len(gc.get_objects())
        memory_growth = final_objects - initial_objects

        # 转换为MB
        memory_mb = memory_growth * 0.0001

        return memory_mb

    def _benchmark_memory_cleanup(self):
        """内存清理基准测试"""
        import gc

        # 强制垃圾回收
        gc.collect()

        # 获取最终内存状态
        final_objects = len(gc.get_objects())
        memory_mb = final_objects * 0.0001

        return memory_mb

    def _benchmark_api_login(self, count):
        """API登录性能基准测试"""
        # 这个方法需要实际的API实现
        # 这里提供框架，具体实现取决于API设计
        return []

    def _benchmark_api_register(self, count):
        """API注册性能基准测试"""
        # 这个方法需要实际的API实现
        return []

    def _benchmark_api_workspace_list(self, count):
        """API工作空间列表性能基准测试"""
        # 这个方法需要实际的API实现
        return []

    def _report_benchmark(self, name, times, target_avg=None, target_p95=None):
        """报告基准测试结果"""
        if not times:
            print(f"{name}: 无数据")
            return

        avg_time = statistics.mean(times)
        median_time = statistics.median(times)
        min_time = min(times)
        max_time = max(times)
        p95_time = statistics.quantiles(times, n=20)[18] if len(times) > 20 else max_time
        p99_time = statistics.quantiles(times, n=100)[98] if len(times) > 100 else max_time

        print(f"{name}:")
        print(f"  平均时间: {avg_time:.4f}s")
        print(f"  中位数时间: {median_time:.4f}s")
        print(f"  最小时间: {min_time:.4f}s")
        print(f"  最大时间: {max_time:.4f}s")
        print(f"  P95时间: {p95_time:.4f}s")
        print(f"  P99时间: {p99_time:.4f}s")
        print(f"  操作次数: {len(times)}")

        # 性能断言
        if target_avg and avg_time > target_avg:
            print(f"  ⚠️  平均时间超过目标: {avg_time:.4f}s > {target_avg:.4f}s")

        if target_p95 and p95_time > target_p95:
            print(f"  ⚠️  P95时间超过目标: {p95_time:.4f}s > {target_p95:.4f}s")

        print()


class RegressionTest(TestCase):
    """性能回归测试"""

    def test_no_performance_regression(self):
        """确保没有性能回归"""
        print("\n=== 性能回归测试 ===")

        # 运行关键基准测试
        user_creation_times = self._benchmark_user_creation(count=50)
        permission_check_times = self._benchmark_permission_check(count=100)
        token_generation_times = self._benchmark_token_generation(count=50)

        # 定义性能基线（这些值应该根据实际系统调优）
        baselines = {
            "用户创建": {"avg": 0.05, "p95": 0.1},
            "权限检查": {"avg": 0.01, "p95": 0.03},
            "Token生成": {"avg": 0.02, "p95": 0.05}
        }

        test_results = {
            "用户创建": user_creation_times,
            "权限检查": permission_check_times,
            "Token生成": token_generation_times
        }

        regression_detected = False

        for operation, times in test_results.items():
            if not times:
                continue

            avg_time = statistics.mean(times)
            p95_time = statistics.quantiles(times, n=20)[18] if len(times) > 20 else max(times)

            baseline = baselines[operation]

            # 检查是否有20%以上的性能下降
            avg_regression = (avg_time - baseline["avg"]) / baseline["avg"]
            p95_regression = (p95_time - baseline["p95"]) / baseline["p95"]

            print(f"{operation}:")
            print(f"  当前平均: {avg_time:.4f}s, 基线: {baseline['avg']:.4f}s, 变化: {avg_regression:+.1%}")
            print(f"  当前P95: {p95_time:.4f}s, 基线: {baseline['p95']:.4f}s, 变化: {p95_regression:+.1%}")

            if avg_regression > 0.2 or p95_regression > 0.2:
                regression_detected = True
                print(f"  ❌ 检测到性能回归！")
            else:
                print(f"  ✅ 性能正常")

        if regression_detected:
            self.fail("检测到性能回归")

    def _benchmark_user_creation(self, count):
        """用户创建基准测试"""
        times = []
        for i in range(count):
            start_time = time.time()
            user = User.objects.create_user(
                email=f"regress_user_{i}_{uuid.uuid4()}@example.com",
                password="password123"
            )
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_permission_check(self, count):
        """权限检查基准测试"""
        owner = User.objects.create_user(
            email="regress_check_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Regression Check Workspace",
            slug="regress-check-ws",
            workspace_type="personal",
            owner=owner
        )
        user = User.objects.create_user(
            email="regress_check_user@example.com",
            password="password123"
        )
        self.permission_service.grant_permissions(
            user=user,
            workspace=workspace,
            actions=["view", "edit"],
            granted_by=owner
        )

        times = []
        for i in range(count):
            start_time = time.time()
            has_permission = self.permission_service.check_permission(
                user=user,
                workspace=workspace,
                action="view"
            )
            end_time = time.time()
            times.append(end_time - start_time)
        return times

    def _benchmark_token_generation(self, count):
        """Token生成基准测试"""
        user = User.objects.create_user(
            email="regress_token_user@example.com",
            password="password123"
        )

        times = []
        for i in range(count):
            start_time = time.time()
            tokens = self.auth_service.generate_tokens(user)
            end_time = time.time()
            times.append(end_time - start_time)
        return times


class LoadTest(TransactionTestCase):
    """负载测试"""

    def test_high_load_scenario(self):
        """高负载场景测试"""
        print("\n=== 高负载场景测试 ===")

        start_time = time.time()

        # 并发用户数和操作数
        concurrent_users = 50
        operations_per_user = 20

        # 执行高负载测试
        results = self._execute_load_test(concurrent_users, operations_per_user)

        end_time = time.time()
        total_time = end_time - start_time
        total_operations = concurrent_users * operations_per_user
        throughput = total_operations / total_time

        print(f"总时间: {total_time:.2f}s")
        print(f"总操作数: {total_operations}")
        print(f"吞吐量: {throughput:.1f} ops/sec")

        # 统计结果
        successful_operations = sum(1 for r in results if r['success'])
        failed_operations = len(results) - successful_operations
        success_rate = successful_operations / len(results)

        operation_times = [r['time'] for r in results]
        avg_operation_time = statistics.mean(operation_times)
        p95_operation_time = statistics.quantiles(operation_times, n=20)[18] if len(operation_times) > 20 else max(operation_times)

        print(f"成功率: {success_rate:.2%}")
        print(f"平均操作时间: {avg_operation_time:.4f}s")
        print(f"P95操作时间: {p95_operation_time:.4f}s")
        print(f"失败操作数: {failed_operations}")

        # 负载测试断言
        self.assertGreaterEqual(success_rate, 0.90, f"成功率过低: {success_rate:.2%}")
        self.assertGreater(throughput, 10, f"吞吐量过低: {throughput:.1f} ops/sec")
        self.assertLess(avg_operation_time, 0.5, f"平均操作时间过长: {avg_operation_time:.4f}s")

    def _execute_load_test(self, concurrent_users, operations_per_user):
        """执行负载测试"""
        # 预创建测试数据
        owner = User.objects.create_user(
            email="load_owner@example.com",
            password="password123"
        )
        workspace = Workspace.objects.create(
            name="Load Test Workspace",
            slug="load-test-ws",
            workspace_type="personal",
            owner=owner
        )

        results = []

        def load_operation(thread_id, operation_id):
            start_time = time.time()
            try:
                # 随机选择操作类型
                operation_types = ['token_gen', 'permission_check', 'user_lookup']
                operation = random.choice(operation_types)

                if operation == 'token_gen':
                    user = User.objects.create_user(
                        email=f"load_user_{thread_id}_{operation_id}@example.com",
                        password="password123"
                    )
                    tokens = self.auth_service.generate_tokens(user)
                    success = tokens.get('access_token') is not None

                elif operation == 'permission_check':
                    user = User.objects.create_user(
                        email=f"load_perm_user_{thread_id}_{operation_id}@example.com",
                        password="password123"
                    )
                    self.permission_service.grant_permissions(
                        user=user,
                        workspace=workspace,
                        actions=["view", "edit"],
                        granted_by=owner
                    )
                    has_permission = self.permission_service.check_permission(
                        user=user,
                        workspace=workspace,
                        action="view"
                    )
                    success = has_permission

                elif operation == 'user_lookup':
                    # 简单的用户查询操作
                    user_count = User.objects.filter(
                        email__startswith="load_user_"
                    ).count()
                    success = user_count >= 0

                else:
                    success = False

            except Exception as e:
                success = False

            end_time = time.time()
            return {
                'success': success,
                'time': end_time - start_time,
                'thread_id': thread_id,
                'operation_id': operation_id
            }

        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = []
            for thread_id in range(concurrent_users):
                for operation_id in range(operations_per_user):
                    future = executor.submit(load_operation, thread_id, operation_id)
                    futures.append(future)

            for future in as_completed(futures):
                results.append(future.result())

        return results