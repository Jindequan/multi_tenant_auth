# Multi-Tenant Auth 完整测试套件

这个测试套件提供了对多租户认证系统的全面测试覆盖，确保系统的正确性、安全性和性能。

## 测试架构概览

### 1. 核心测试文件

| 测试文件 | 覆盖范围 | 主要测试类 | 测试用例数 |
|---------|---------|-----------|-----------|
| `test_models.py` | 数据模型基础功能 | `UserModelTest`, `TeamTest`, `WorkspaceTest` | ~50 |
| `test_complete_crud.py` | 完整CRUD操作 | `UserModelCRUDTest`, `TeamModelCRUDTest` | ~80 |
| `test_authentication_scenarios.py` | 认证流程和场景 | `BasicAuthenticationTest`, `JWTTokenTest` | ~100 |
| `test_permission_system.py` | 权限验证和管理 | `BasicPermissionTest`, `PermissionDecoratorTest` | ~120 |
| `test_edge_cases_and_exceptions.py` | 边界条件和异常处理 | `ModelValidationTest`, `SecurityEdgeCaseTest` | ~90 |
| `test_concurrency_and_performance.py` | 并发和性能测试 | `ConcurrencyTest`, `PerformanceTest` | ~70 |
| `test_integration_scenarios.py` | 集成测试和工作流 | `CompleteUserFlowTest`, `PermissionWorkflowTest` | ~60 |
| `test_performance_benchmarks.py` | 性能基准和回归测试 | `BenchmarkTest`, `RegressionTest` | ~50 |

### 2. 测试分层

#### 单元测试层
- **模型测试**: 验证所有数据模型的CRUD操作、约束和业务逻辑
- **服务测试**: 测试认证服务、权限服务、团队服务的核心功能
- **装饰器测试**: 验证权限装饰器的正确性和安全性

#### 集成测试层
- **API集成测试**: 测试完整的前后端交互流程
- **业务流测试**: 验证复杂的业务场景和工作流
- **系统集成测试**: 测试各组件间的协作和数据流

#### 端到端测试层
- **用户旅程测试**: 从注册到使用的完整用户流程
- **多租户场景测试**: 验证租户隔离和权限分离
- **安全渗透测试**: 检查各种安全漏洞和攻击防护

#### 性能测试层
- **基准测试**: 建立性能基线和回归检测
- **负载测试**: 验证系统在高负载下的表现
- **并发测试**: 测试并发场景下的数据一致性和性能

## 测试覆盖范围

### 1. 模型测试覆盖

#### 用户模型 (User)
- ✅ 用户创建（完整字段、验证、约束）
- ✅ 用户读取（主键、邮箱、属性访问）
- ✅ 用户更新（信息修改、密码更改）
- ✅ 用户删除（软删除、硬删除）
- ✅ 用户约束（邮箱唯一性、必填字段）
- ✅ 边界条件（极长数据、特殊字符、批量操作）

#### 团队模型 (Team)
- ✅ 团队创建（基本信息、设置、所有者）
- ✅ 团队成员管理（添加、更新、删除）
- ✅ 团队约束（slug唯一性、成员唯一性）
- ✅ 团队权限（管理员、成员、邀请）

#### 工作空间模型 (Workspace)
- ✅ 工作空间创建（个人、团队类型）
- ✅ 工作空间关联（团队、所有者关系）
- ✅ 工作空间设置（公开性、权限配置）
- ✅ 工作空间约束（类型验证、关联完整性）

#### 权限模型 (UserWorkspaceActions)
- ✅ 权限授予（用户、工作空间、动作列表）
- ✅ 权限验证（检查、撤销、更新）
- ✅ 权限约束（用户-工作空间唯一性）
- ✅ 临时权限（过期时间、自动失效）

#### 审计日志模型 (AuditLog)
- ✅ 日志创建（用户操作、资源追踪）
- ✅ 日志查询（时间范围、操作类型）
- ✅ 日志排序（时间顺序、分页）

### 2. 认证测试覆盖

#### 基础认证
- ✅ 用户注册（成功、验证错误、重复邮箱）
- ✅ 用户登录（成功、失败、无效凭据）
- ✅ 密码管理（修改、重置、忘记密码）
- ✅ 账户状态（激活、锁定、禁用）

#### JWT Token处理
- ✅ Token生成（访问token、刷新token）
- ✅ Token验证（有效性、过期、黑名单）
- ✅ Token刷新（续期、过期处理）
- ✅ 并发Token（多设备登录、会话管理）

#### 双因素认证 (2FA)
- ✅ 2FA启用（密钥生成、QR码）
- ✅ 2FA验证（TOTP验证、备份码）
- ✅ 2FA禁用（安全确认、权限检查）
- ✅ 2FA登录流程（额外验证步骤）

#### 账户安全
- ✅ 登录失败处理（账户锁定、尝试限制）
- ✅ 会话管理（超时、并发控制）
- ✅ IP安全（检测、限制、验证）
- ✅ User-Agent验证（浏览器指纹、异常检测）

### 3. 权限系统测试覆盖

#### 基础权限
- ✅ 权限检查（单个权限、多个权限）
- ✅ 权限授予（用户、工作空间、动作）
- ✅ 权限撤销（部分撤销、全部撤销）
- ✅ 权限继承（团队成员、工作空间权限）

#### 高级权限
- ✅ 权限层级（查看<编辑<分享<管理）
- ✅ 权限转移（授予者变更、权限交接）
- ✅ 临时权限（过期、自动清理）
- ✅ 批量权限（批量授予、批量撤销）

#### 权限装饰器
- ✅ 认证装饰器（`@require_auth`）
- ✅ 权限装饰器（`@require_permissions`）
- ✅ 工作空间装饰器（`@require_workspace_access`）
- ✅ 组合装饰器（多重权限检查）

#### API权限控制
- ✅ 端点保护（认证、授权、权限检查）
- ✅ 资源访问（工作空间、团队、用户）
- ✅ 权限API（授予、撤销、检查）
- ✅ 管理API（用户管理、系统统计）

### 4. 安全测试覆盖

#### 输入验证
- ✅ SQL注入防护（参数化查询、ORM安全）
- ✅ XSS防护（输入清理、输出编码）
- ✅ CSRF防护（Token验证、安全头）
- ✅ 文件上传安全（类型检查、大小限制）

#### 认证安全
- ✅ 密码策略（强度要求、哈希存储）
- ✅ 暴力破解防护（尝试限制、账户锁定）
- ✅ 会话劫持防护（Token安全、超时）
- ✅ 社会工程防护（信息泄露防护）

#### 权限安全
- ✅ 权限提升攻击防护（权限检查、验证）
- ✅ 横向权限绕过（租户隔离、数据过滤）
- ✅ 垂直权限绕过（角色检查、最小权限）
- ✅ 间接权限攻击（对象引用安全）

#### 系统安全
- ✅ 配置安全（默认设置、环境变量）
- ✅ 日志安全（敏感信息过滤、完整性）
- ✅ 通信安全（HTTPS、证书验证）
- ✅ 部署安全（容器安全、网络隔离）

### 5. 性能测试覆盖

#### 数据库性能
- ✅ 查询优化（索引使用、查询计划）
- ✅ 批量操作（批量创建、批量更新）
- ✅ 事务性能（锁等待、死锁处理）
- ✅ 连接池管理（连接复用、超时）

#### 缓存性能
- ✅ 缓存读写（命中率、过期策略）
- ✅ 缓存一致性（数据同步、失效处理）
- ✅ 分布式缓存（集群、故障转移）
- ✅ 缓存预热（启动性能、命中率）

#### API性能
- ✅ 响应时间（P50、P95、P99指标）
- ✅ 吞吐量（请求/秒、并发连接）
- ✅ 资源使用（内存、CPU、网络）
- ✅ 扩展性（水平扩展、负载均衡）

#### 并发性能
- ✅ 并发操作（线程安全、数据一致性）
- ✅ 锁竞争（乐观锁、悲观锁）
- ✅ 死锁检测（死锁预防、自动恢复）
- ✅ 资源竞争（内存、文件、数据库）

## 运行测试

### 基础测试命令

```bash
# 运行所有测试
python manage.py test multi_tenant_auth.tests

# 运行特定测试文件
python manage.py test multi_tenant_auth.tests.test_models
python manage.py test multi_tenant_auth.tests.test_authentication_scenarios
python manage.py test multi_tenant_auth.tests.test_permission_system

# 运行特定测试类
python manage.py test multi_tenant_auth.tests.test_models.UserModelTest
python manage.py test multi_tenant_auth.tests.test_permission_system.BasicPermissionTest

# 运行特定测试方法
python manage.py test multi_tenant_auth.tests.test_models.UserModelTest.test_create_user
python manage.py test multi_tenant_auth.tests.test_authentication_scenarios.BasicAuthenticationTest.test_successful_registration

# 详细输出
python manage.py test multi_tenant_auth.tests --verbosity=2

# 保留测试数据库（用于调试）
python manage.py test multi_tenant_auth.tests --keepdb

# 并行运行测试（需要安装 parallel-test）
python manage.py test multi_tenant_auth.tests --parallel
```

### 性能测试命令

```bash
# 运行性能基准测试
python manage.py test multi_tenant_auth.tests.test_performance_benchmarks

# 运行并发测试
python manage.py test multi_tenant_auth.tests.test_concurrency_and_performance.ConcurrencyTest

# 运行负载测试（可能需要较长时间）
python manage.py test multi_tenant_auth.tests.test_performance_benchmarks.LoadTest

# 运行性能回归测试
python manage.py test multi_tenant_auth.tests.test_performance_benchmarks.RegressionTest
```

### 代码覆盖率

```bash
# 安装覆盖率工具
pip install coverage

# 运行测试并生成覆盖率报告
coverage run --source='.' manage.py test multi_tenant_auth.tests
coverage report
coverage html  # 生成HTML报告
coverage xml   # 生成XML报告（用于CI/CD）

# 排除特定文件或目录
coverage run --source='.' --omit='*/migrations/*,*/tests/*,*/venv/*' manage.py test multi_tenant_auth.tests
```

### 持续集成配置

#### GitHub Actions示例
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10']

    steps:
    - uses: actions/checkout@v2
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install coverage

    - name: Run tests
      run: |
        coverage run --source='.' manage.py test multi_tenant_auth.tests
        coverage report
        coverage xml

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage.xml
```

## 测试数据管理

### 测试数据隔离

每个测试类都使用事务隔离，确保测试间的独立性：

```python
class BaseTestCase(TestCase):
    def setUp(self):
        # 创建测试数据
        self.user = User.objects.create_user(
            email="test@example.com",
            password="test123"
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            slug="test-workspace",
            owner=self.user
        )

    def tearDown(self):
        # 清理测试数据（可选，Django自动处理）
        pass
```

### 测试数据工厂

使用数据工厂模式创建一致的测试数据：

```python
from multi_tenant_auth.tests import TestDataFactory

class MyTestCase(TestCase):
    def setUp(self):
        self.factory = TestDataFactory()

    def test_something(self):
        user_data = self.factory.create_user_data()
        workspace_data = self.factory.create_workspace_data()

        user = User.objects.create_user(**user_data)
        workspace = Workspace.objects.create(owner=user, **workspace_data)
```

### UUID使用

在测试中使用UUID避免数据冲突：

```python
import uuid

def test_unique_data(self):
    # 使用UUID确保唯一性
    unique_email = f"user_{uuid.uuid4()}@example.com"
    unique_slug = f"workspace-{uuid.uuid4()}"

    user = User.objects.create_user(email=unique_email, password="test123")
    workspace = Workspace.objects.create(
        name="Test Workspace",
        slug=unique_slug,
        owner=user
    )
```

## 性能基准

### 性能目标

| 操作类型 | 目标平均时间 | 目标P95时间 | 测试方法 |
|---------|-------------|-------------|---------|
| 用户创建 | < 50ms | < 100ms | `test_user_creation_performance` |
| 权限检查 | < 10ms | < 30ms | `test_permission_checking_performance` |
| Token生成 | < 20ms | < 50ms | `test_authentication_performance` |
| API响应 | < 100ms | < 300ms | `test_api_response_performance` |
| 批量操作 | < 200ms | < 500ms | `test_bulk_operations_performance` |

### 性能监控

```python
from multi_tenant_auth.tests import benchmark_test

class MyPerformanceTest(TestCase):
    @benchmark_test(iterations=100, max_time=0.1)
    def test_user_creation_performance(self):
        user = User.objects.create_user(
            email=f"perf_{uuid.uuid4()}@example.com",
            password="test123"
        )
        self.assertIsNotNone(user.id)
```

### 回归检测

自动化性能回归检测：

```python
def test_no_performance_regression(self):
    # 运行性能基准
    user_times = self._benchmark_user_creation(count=50)

    # 与基线比较
    avg_time = statistics.mean(user_times)
    baseline_avg = 0.05  # 50ms基线

    regression = (avg_time - baseline_avg) / baseline_avg

    # 允许10%的性能波动
    self.assertLess(regression, 0.1,
                   f"检测到性能回归: {avg_time:.3f}s > {baseline_avg:.3f}s")
```

## 安全测试

### 自动化安全扫描

```bash
# 安装安全扫描工具
pip install bandit safety

# 运行安全扫描
bandit -r multi_tenant_auth/ -f json -o security-report.json
safety check --json --output safety-report.json

# 运行依赖漏洞扫描
pip-audit --format=json --output=audit-report.json
```

### 渗透测试

```python
class SecurityPenetrationTest(TestCase):
    def test_sql_injection_attempts(self):
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users --"
        ]

        for payload in malicious_inputs:
            with self.subTest(payload=payload):
                # 测试各种注入点
                response = self.client.post('/api/auth/login/', {
                    'email': payload,
                    'password': 'test123'
                })
                # 应该返回认证失败，不是服务器错误
                self.assertIn(response.status_code, [400, 401])

    def test_xss_prevention(self):
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]

        for payload in xss_payloads:
            with self.subTest(payload=payload):
                # 测试XSS防护
                user = User.objects.create_user(
                    email=f"xss_{uuid.uuid4()}@example.com",
                    password="test123",
                    personal_info={'name': payload}
                )

                # 验证payload被正确存储但不执行
                self.assertEqual(user.personal_info['name'], payload)
```

## 持续改进

### 测试指标监控

- **代码覆盖率**: 目标 > 90%
- **测试通过率**: 目标 100%
- **性能回归**: 目标 < 5%
- **安全漏洞**: 目标 0 高危漏洞

### 测试优化策略

1. **并行测试**: 使用`--parallel`标志加速测试运行
2. **测试分组**: 将快速测试和慢速测试分离
3. **缓存数据**: 使用`--keepdb`重用测试数据库
4. **选择性运行**: 只运行相关的测试文件

### 定期维护

- **每月**: 更新性能基线，检查测试覆盖率
- **每季度**: 审查安全测试用例，更新威胁模型
- **每年**: 重构测试架构，采用新的测试工具和最佳实践

这个完整的测试套件确保多租户认证系统的可靠性、安全性和高性能，为生产环境提供强有力的质量保障。