# 无汇点语义漏洞发掘 — 架构实现方案

## 背景

当前 agies v3 pipeline 的核心检测模式是 **source → sink 匹配**。所有检测规则都依赖于一个明确的"危险函数"（`exec`、`eval`、`pickle.loads`、`os.system`、`requests.get` 等）。这种模型无法发现**不依赖危险函数、由多个安全操作组合而成**的漏洞（如 MLflow `$ENV_VAR` 泄漏）。

**问题根因：** 漏洞不一定出现在单点代码的"危险调用"上，而是出现在**模块间安全边界的缺失**。三个各自安全的模块，组合起来可能产生严重的安全后果。

**解决方案：** 将推理从"污点传播"升级为"安全规约伪证（Spec Falsification）"——让 LLM 先理解业务语义、推导安全契约、再在实现中寻找契约违反。

---

## 整体架构变更

```
当前:  sink_patterns → pathfinder → intent_agent → logic_agent (切片内矛盾)
                                               
目标:  semantic_anchors → pathfinder → intent_agent (推导契约) 
                                    → logic_agent (契约伪证)
                                    → semantic_leak (语义泄露)
```

### 新增/修改模块一览

| 模块 | 当前 | 目标 | 工作量 |
|------|------|------|--------|
| `pathfinder/sink_patterns.py` | 固定 sink 函数列表 | 语义锚点列表 + 敏感变量名列表 | ~0.5天 |
| `pathfinder/treesitter.py` | 匹配函数调用 | 匹配类名/函数名/注释语义 | ~0.5天 |
| `agents/intent_agent.py` | 输出开发者意图 | 输出意图 + 安全契约声明 | ~1天 |
| `agents/logic_agent.py` | 找切片内矛盾 | 契约伪证（找实现违反契约的路径） | ~1天 |
| `aggregator/blackboard.py` | Intent 缓存 | 契约缓存 + 跨模块知识共享 | ~0.5天 |
| **新增** `pathfinder/semantic_leak.py` | — | 敏感变量命名追踪 | ~0.5天 |

总计约 **4 天**。

---

## 一、寻路器泛化：从"匹配危险函数"到"语义锚点"

### 当前实现

`agies/engine/v3/pathfinder/sink_patterns.py` 定义了每个漏洞类型的 sink 函数：

```python
SSRF_SINKS = [
    "httpx.request", "httpx.get", "httpx.post",
    "requests.request", "requests.get", "requests.post",
    "aiohttp.request", "aiohttp.ClientSession.get",
    ...
]
PICKLE_SINKS = [
    "pickle.loads", "cloudpickle.loads", "pickle.load",
    "dill.loads", "shelve.open",
    ...
]
```

匹配逻辑在 `treesitter.py` 中查找函数调用 AST 节点，匹配这些名字。

### 问题

当漏洞不涉及任何 sink 函数时（如 MLflow 的 `$ENV_VAR` 泄漏），pathfinder 根本不知道切什么代码给 LLM。

### 目标实现

#### 1.1 语义锚点列表

新建 `agies/engine/v3/pathfinder/semantic_anchors.py`：

```python
"""
语义锚点：匹配代码中的"高价值逻辑控制器"——处理安全敏感业务的类/函数。

不匹配具体的函数调用，而是匹配业务语义。锚点命中后，整个类/模块
被打包成"语义切片"送入分析管线。
"""

SEMANTIC_ANCHORS = [
    # 认证与会话
    r"(?i)(auth|authenticate|login|session|token|jwt|oauth)",
    # 凭证与密钥
    r"(?i)(credential|secret|api_key|apikey|password|passphrase)",
    # 网关与入口
    r"(?i)(gateway|endpoint|executor|dispatcher|handler)",
    # 序列化与反序列化
    r"(?i)(serializer|deserializer|serde|marshal|unmarshal|pickle|cloudpickle)",
    # 检查点与状态持久化
    r"(?i)(checkpoint|checkpointer|state\w*|persist|save_state|load_state)",
    # 权限与特权
    r"(?i)(privilege|permission|role|access_control|authorization|admin)",
    # 配置与初始化
    r"(?i)(config|configuration|setting|option|bootstrap)",
    # 加密解密
    r"(?i)(encrypt|decrypt|cipher|crypt|hash|digest|certificate)",
]
```

匹配规则：命中类名、函数名、模块名、顶级注释块。

#### 1.2 敏感语义变量列表

```python
"""命中的变量名提示 LLM 这是敏感数据，需要追踪流向。"""
SENSITIVE_SEMANTIC_VARS = [
    r"(?i)(api_key|apikey|secret|token|password|passphrase|credential)",
    r"(?i)(private_key|public_key|certificate|session_id|csrf)",
    r"(?i)(access_key|secret_access_key|aws_secret|db_password)",
]
```

匹配规则：变量赋值语句左值。

#### 1.3 匹配逻辑变更

当前 `treesitter.py` 的匹配逻辑：

```python
# 当前：在函数体内找 sink 函数调用
for node in query.captures("function_call"):
    if match_sink(node.text, sink_patterns):
        slices.append(build_slice(node))
```

改为：

```python
# 阶段 A：语义锚点发现
for node in query.captures("class_definition|function_definition|module_comment"):
    if match_anchor(node.text, SEMANTIC_ANCHORS):
        # 将整个类的所有方法打包为语义切片
        slices.append(build_semantic_slice(node, scope="full_class"))

# 阶段 B：传统 sink 匹配（保留，作为补充）
for node in query.captures("function_call"):
    if match_sink(node.text, sink_patterns):
        slices.append(build_slice(node))
```

**关键变更：** 锚点命中后不切 4-5 行代码，而是把整个类/模块的所有相关方法打包。

#### 1.4 语义切片结构

```python
@dataclass
class SemanticSlice:
    """语义切片：一个完整的业务域代码块"""
    anchor_type: str              # 匹配到的锚点类型（auth/secret/serializer...）
    class_name: str               # 类名（如有）
    module_path: str              # 文件路径
    methods: list[SourceFunction] # 类下所有方法
    comments: str                 # 类/模块注释
    entry_points: list[str]       # 外部调用入口
    security_contract: str | None # LLM 推导的安全契约（后续填充）
```

---

## 二、逻辑智能体升级：从"污点传播"到"规约伪证"

### 当前实现

`intent_agent.py` 读取 4-5 个函数，输出"开发者意图"。`logic_agent.py` 在同一个切片内找"contradiction"。

### 问题

切片范围太窄，intent 只解释代码做了什么，不推导应该做什么。logic 只做代码内部的矛盾检测，不做"契约 vs 实现"的比对。

### 目标实现

#### 2.1 Intent Agent 升级：输出安全契约

当前 prompt 摘要：
```
Read these functions and explain what the developer intended to do.
```

改为两段式：

```
Phase 1 - Code Understanding:
  Read this class/module. What does it do? What data does it handle?
  
Phase 2 - Security Contract Deduction:
  Given the code's purpose, what SECURITY CONTRACT should this module
  enforce? Consider:
  
  1. Input validation: what should be checked before accepting data?
  2. Trust boundaries: what data must never leave this module?
  3. Authentication/authorization: who should be allowed to call what?
  4. Secrets handling: how should credentials be protected?
  ...
  
  Output a formal contract like:
  "Contract: This module stores API keys in the database.
   [REQUIREMENT-1] All stored values must be literal strings.
   [REQUIREMENT-2] No environment variable references ($VAR) in stored values.
   [REQUIREMENT-3] Stored values must never be sent to external endpoints."
```

输出结构：

```python
@dataclass
class SecurityContract:
    module: str
    purpose: str                    # 模块业务目的
    requirements: list[str]         # 安全要求列表
    trust_boundary: str             # 信任边界描述
    external_outputs: list[str]     # 外部输出点
```

Intent Agent 的输出改变：
- 之前：`{"intent": "This function loads an image from a URL"}`
- 之后：`{"intent": "...", "contract": SecurityContract(...)}`

#### 2.2 Logic Agent 升级：契约伪证

当前 prompt 摘要：
```
Read this code path and find contradictions or bugs.
```

改为：

```
You are given:
  1. A SECURITY CONTRACT that this module SHOULD enforce
  2. The actual Python source code of this module
  
Task: Find FALSIFICATIONS — places where the actual implementation
violates the security contract.

For each violation found, output:
  - Which REQUIREMENT is violated
  - The exact code lines that violate it
  - Why this is a real vulnerability (not a false positive)
  - Exploitation scenario (how an attacker would use this)

Examples of contract violations:
  - Contract says "validate input" but code does no validation
  - Contract says "never expose secrets" but code sends them externally
  - Contract says "restrict access" but code allows unauthenticated calls
```

**MLflow 案例过一遍：**

```
Intent Agent 读 GatewaySecret → 输出契约:
  [R1] secret_value 必须是字面量字符串，不能含 $ 引用
  [R2] api_key 不能被发送到非注册的外部 endpoint

Logic Agent 验证实现:
  handlers.py:L4542 — secret 创建时未过滤 $ → 违反 R1
  gateway_api.py:L153 — secret 值被发到 api_base → 违反 R2

输出: "2 个契约违反，可利用链：$VAR 未过滤 → 存入 DB → 运行时
       解析 → 发到攻击者 api_base → 环境变量泄露"
```

#### 2.3 跨模块契约共享

当前 `blackboard.py` 只缓存 Intent。需要加两样：

```python
# 新增
@dataclass
class ContractEntry:
    module_path: str
    contract: SecurityContract
    confidence: float
    timestamp: datetime

class BlackboardAggregator:
    def __init__(self):
        self.intent_cache: dict[str, CachedIntent]  # 已有
        self.contracts: dict[str, ContractEntry]     # 新增
        self.knowledge: list[KnowledgeEntry]         # 已有
    
    def get_contract(self, module: str) -> SecurityContract | None:
        """查询某个模块的安全契约（供交叉验证）"""
        ...
```

**关键：** A 模块的 Logic Agent 可以查询 B 模块的契约。例如，Gateway Handler 可以查询 Config 模块的契约，发现"Config 模块会解析 $VAR，但 Gateway 没有阻止 $VAR → 组合攻击链"。

---

## 三、数据流重新定义：语义泄露追踪

### 当前实现

物理污点追踪：变量 x 赋值给 y，x 在某行被修改。不关心变量名含义。

### 目标实现

新建 `agies/engine/v3/pathfinder/semantic_leak.py`：

```python
class SemanticLeakDetector:
    """
    追踪敏感语义变量（api_key、secret、token 等），
    判断它们是否越过了信任边界。
    """
    
    def __init__(self):
        self.sensitive_vars = SENSITIVE_SEMANTIC_VARS
    
    def analyze(self, module_path: str, ast_root: Node) -> list[LeakFinding]:
        """
        1. 扫描所有赋值语句
        2. 如果左值匹配敏感变量名 → 记录为"敏感变量" + 赋值来源
        3. 追踪敏感变量的流向
        4. 如果它被用于：
           - HTTP 请求的 header/body
           - 文件写入（非本模块私有文件）
           - 返回给未经授权的调用者
           - 日志输出
           → 标记为"语义泄露"
        """
        ...
```

### MLflow 案例匹配

```
赋值: secret_value["api_key"] = "$ENV_VAR"
      ↑ 左值匹配 SENSITIVE_SEMANTIC_VARS

追踪: api_key → gateway runtime → HTTP header("api-key")

边界检查: api_base 是攻击者可控 → 语义泄露命中

输出: "敏感变量 api_key（值为 $环境变量引用）被发送到
      攻击者可控的出站 HTTP 端点"
```

### 与 Logic Agent 的关系

- **SemanticLeakDetector**：静态规则引擎，快速召回可疑路径（召回率优先）
- **Logic Agent**：LLM 验证每条可疑路径，排除误报（精确率优先）

---

## 四、文件修改清单

### 新增文件

| 文件 | 职责 |
|------|------|
| `agies/engine/v3/pathfinder/semantic_anchors.py` | 语义锚点 + 敏感变量名定义 |
| `agies/engine/v3/pathfinder/semantic_leak.py` | 敏感变量命名追踪引擎 |
| `agies/engine/v3/models/semantic.py` | 语义切片、安全契约、泄露发现的数据模型 |
| `docs/v3/semantic_architecture.md` | 本文档 |

### 修改文件

| 文件 | 修改内容 |
|------|---------|
| `agies/engine/v3/pathfinder/treesitter.py` | 加语义锚点匹配逻辑（类名/函数名/注释），加全类打包 |
| `agies/engine/v3/agents/intent_agent.py` | prompt 加"推导安全契约"阶段，输出 SecurityContract |
| `agies/engine/v3/agents/logic_agent.py` | prompt 改为"契约伪证"，输入增加 SecurityContract |
| `agies/engine/v3/aggregator/blackboard.py` | 加契约缓存 + 跨模块契约查询 |
| `agies/engine/v3/aggregator/models.py` | 加 CachedContract、LeakFinding 模型 |

---

## 五、验证方案

### 验证目标

| 靶子 | 预期检出 | 当前 agies 能否检出 |
|------|---------|-------------------|
| MLflow `$ENV_VAR` 泄漏 | ✅ 语义锚点抓 GatewaySecret → 契约要求过滤 $ → 实际未过滤 | ❌ 不能 |
| transformers `load_image` SSRF | ✅ 语义锚点抓 load_image → 契约要求校验 URL → 实际未校验 | ⚠️ sink 规则能抓到 httpx.get |
| zipp ReDoS | ✅ sink 规则保留，无影响 | ✅ 已能检出 |
| langgraph-api SSRF | ✅ 语义锚点抓 webhook 配置 → 契约要求拦截私有 IP → 实际未拦截 | ⚠️ sink 规则能抓到 |

### 评估指标

- **召回率提升**：之前漏报的跨模块漏洞是否能抓到
- **误报率控制**：语义锚点命中率 vs 实际有效发现的比例
- **Token 成本**：全类打包切片会增加 token 消耗，需要评估增幅

---

## 六、实施优先级

| 顺序 | 改动 | 预期收益 | 风险 |
|------|------|---------|------|
| P0 | 语义锚点定义 + treesitter 匹配 | 直接扩展 pathfinder 覆盖范围 | 低，改得少 |
| P1 | Intent Agent 安全契约输出 | 为 Logic Agent 提供输入 | 中，prompt 质量影响大 |
| P2 | Logic Agent 契约伪证 | 核心推理能力升级 | 高，需要反复调 prompt |
| P3 | 语义泄露追踪 | 补充物理污点追踪盲区 | 低，独立模块 |
| P4 | 跨模块契约共享 | 打通模块间分析 | 中，blackboard 改动 |

建议从 P0 开始，验证语义锚点在现有项目上的命中率，再逐步推进。
