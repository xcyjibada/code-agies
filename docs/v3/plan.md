# agies v3 — 基于静态调用链图 + 数据流图的漏洞发现

> 规划日期：2026-05-30
> 前身：v1（tree-sitter SAST + 单 Agent 验证）→ v2（可插拔图生成层，Joern/tree-sitter ABC 接口 + Director 自动选择）
> v3 核心变化：**从"给 LLM 看代码"变为"给 LLM 看图"** — 在构建好的调用链图和数
> 据流图上，做路径可达性分析、噪音剪枝、攻击路径枚举，然后喂给 LLM 做语义判断。

---

## 核心思路

### v2 做了什么

v2 完成了图生成层的可插拔架构：

```
TreeSitterGraphGenerator ─┐
                          ├── Director → ProgramGraph（节点+边+文件索引）
JoernGraphGenerator ──────┘
```

但 ProgramGraph 只被用来做基本的调用边解析，没有真正参与漏洞发现。

### v3 要做什么

v3 在 ProgramGraph 之上构建三层分析管道：

```
  ProgramGraph（原始图，含全量节点和边）
       │
       ▼
  Phase A: 噪音剪枝 ─── OriginPruner + 文件级过滤 → 干净图
       │
       ▼
  Phase B: 数据流分析 ── Joern DF / 符号执行 → 数据流路径
       │
       ▼
  Phase C: 可达性 + 攻击路径 ── 入口点→sink 追踪 → 候选路径
       │
       ▼
  Phase D: 切片喂 LLM ─── 剪枝后的调用链 + 数据流 → Bulk Analysis
```

核心差异：v2 的图是**给人看的**，v3 的图是**给分析和 LLM 用的**。

---

## Phase A: 噪音剪枝

### 问题

mlflow Java 项目上：13,130 个内部方法，1,850 条内部调用边，其中 95% 是
protobuf 生成代码的 `setX → build → mergeFrom` Builder 样板。

### 方案：分层剪枝

#### A1 文件级剪枝（规则驱动）

```python
# agies/engine/graph/pruner.py

class FileLevelPruner:
    """按文件路径和内容启发式排除噪音。"""

    # 已知生成代码模式
    GENERATED_PATTERNS = [
        r"\.pb\.(java|cc|h)$",          # protobuf
        r"/gen/", r"/generated/",        # 通用生成代码
        r"\.grpc\.(java|py)$",           # gRPC
        r"openapi", r"swagger",          # API 规范生成
        r"Antlr", r"antlr",              # ANTLR 解析器
    ]

    # 已知噪音路径
    NOISE_PATHS = [
        "/test/", "/tests/", "/__tests__/",
        "/vendor/", "/node_modules/",
        "/examples/", "/samples/",
    ]

    def is_noise(self, file_path: str) -> bool:
        """返回 True 表示该文件应排除。"""
```

#### A2 调用图级剪枝 — OriginPruner

思路：同一方法起源的派生调用（如 protobuf 的 `setX → build`）只保留一个代表。

```python
class OriginPruner:
    """基于方法起源的调用图剪枝。

    对 Joern CPG：按 METHOD.NAME 聚类，同名的不同覆写视为同一个 origin。
    对 tree-sitter：按函数名 + 文件路径签名聚类。
    """

    DOMINANT_ORIGINS = {
        # format: {origin_name: max_retain_count}
        "set": 1,           # setter 只保留一条边
        "get": 1,           # getter 只保留一条边
        "build": 1,         # builder
        "mergeFrom": 1,     # protobuf merge
        "addAll": 1,
        "clear": 1,
        "writeTo": 1,
        "equals": 0,        # 完全剪掉
        "hashCode": 0,
        "toString": 0,
        "getDescriptor": 0,
        "getSerializedSize": 0,
        "newBuilder": 0,
        "toBuilder": 0,
        "isInitialized": 0,
        "<init>": 1,        # 构造函数只保留一条
        "<clinit>": 0,
    }

    def prune(self, pg: ProgramGraph) -> ProgramGraph:
        """返回剪枝后的 ProgramGraph。"""
```

#### A3 可达性剪枝 — 入口点反向追踪

只保留从已知入口点（HTTP handler、CLI 命令、main 函数）可达的路径。

```python
class ReachabilityPruner:
    """从入口点反向/BFS 可达性分析，剪掉不可达子图。

    入口来源：
    - AttackSurface Agent 的输出（URL 路由、CLI 命令）
    - main 函数自动检测
    - 已知框架入口模式（@app.route、doGet/doPost 等）
    """

    def prune(self, pg: ProgramGraph, entry_points: set[str]) -> ProgramGraph:
        """只保留 entry_points 可达的节点和边。"""
```

---

## Phase B: 数据流分析

### 问题

v2 只有调用图（谁调了谁），没有数据流（参数怎么传递、返回值怎么流动）。

### 方案

#### B1 Joern 原生数据流

Joern CPG 包含 `REACHING_DEF` 边（约 75 条 / 530 条总边），可以直接查询：

```
cpg.method.isExternal(false).dataFlow
cpg.call.code(".*request.*").argument.reachingDef
```

通过 `joern --script` 脚本批量提取数据流路径：

```
从入口方法 → 定位 CALL 节点 → 追踪 REACHING_DEF → 到达 sink
```

#### B2 轻量级符号执行（tree-sitter 回退）

对于 tree-sitter 生成的图（Python 等），用静态符号执行做基础数据流：

```python
class DataFlowTracer:
    """在 ProgramGraph 上做轻量级数据流追踪。"""

    def trace(
        self,
        pg: ProgramGraph,
        source: str,    # 变量名或函数参数名
        sink: str,      # 危险函数名
    ) -> list[DataFlowPath]:
        """从 source 到 sink 的路径枚举。"""
```

#### B3 数据流路径格式

```python
@dataclass
class DataFlowPath:
    source: str              # "request.getParameter"
    source_node: str         # GraphNode.id
    intermediate: list[str]  # 经过的函数/变量
    sink: str                # "exec"
    sink_node: str           # GraphNode.id
    call_sites: list[tuple[str, int]]  # (file, line)
    is_full_path: bool       # True=完整路径，False=有断点
```

---

## Phase C: 可达性 + 攻击路径

### 入口点 → Sink 矩阵

```
                    Sink: exec   Sink: eval   Sink: SQL   Sink: path_join
入口: HTTP POST        ✅           ❌           ✅           ✅
入口: WebSocket        ❌           ✅           ❌           ❌
入口: CLI args         ✅           ✅           ❌           ✅
入口: Message Queue    ❌           ❌           ✅           ❌
```

### 攻击路径评分

结合 `ProgramGraph.attack_path_score`（已有字段）和数据流完整性：

```python
def score_attack_path(
    pg: ProgramGraph,
    entry: str,
    sink: str,
    df_path: DataFlowPath | None,
) -> float:
    """0-1 评分：1 = 完整可控路径。"""
```

---

## Phase D: LLM 分析回接

### 切片格式升级

v2 的切片：

```
entry: ScoringServer.evaluateRequest
call_chain: [evaluateRequest → predict → toJson]
signals: {regex_match: 0.7}
```

v3 的切片：

```
entry: ScoringServer.evaluateRequest
call_chain: [evaluateRequest → predict → toJson]
data_flow: [request.data → dataWrapper → predictor.predict → result]
reachable_sinks: [Runtime.exec, FileOutputStream]
pruned: true (origin=Iterator.next 裁剪)
```

### Bulk Analysis 增强

- 当前：每个函数独立分析，不知道上下文
- v3：**以切片为单位送入 LLM** — 一个切片包含完整的调用链 + 数据流路径

---

## 文件结构

```
agies/engine/graph/
├── __init__.py
├── base.py              # GraphGenerator ABC（已有）
├── models.py            # GraphNode, ProgramGraph, ProgramSlice（已有）
├── joern.py             # JoernGraphGenerator（已有）
├── joern_docker.py      # Docker 生命周期（已有）
├── treesitter.py        # TreeSitterGraphGenerator（已有）
├── codeql.py            # CodeQLGraphGenerator stub（已有）
│
├── pruner.py            # ★ NEW Phase A：三层噪音剪枝
│   ├── FileLevelPruner
│   ├── OriginPruner
│   └── ReachabilityPruner
│
└── dataflow.py          # ★ NEW Phase B：数据流分析
    ├── DataFlowTracer
    └── DataFlowPath

agies/engine/director/
├── __init__.py          # Director（已有，新增 v3 开关）
├── repomap.py           # （已有）
├── signals.py           # （已有）
├── aggregator.py        # ★ MOD Phase C：攻击路径评分增强
├── reachability.py      # ★ NEW Phase C：入口→sink 可达性矩阵
└── slicer_v3.py         # ★ NEW Phase D：v3 切片 → Bulk Analysis

agies/engine/sast/
├── __init__.py
├── matcher.py           # （已有）
└── pathfinder.py        # ★ MOD Phase B：集成 DataFlowTracer

docs/v3/
├── noise_reduction_research.md  # 去噪技术调研
└── plan.md                      # 本文件
```

---

## 实施路线

| 步骤 | 内容 | 依赖 | 测试 |
|------|------|------|------|
| **P1** | `pruner.py` — FileLevelPruner + OriginPruner | 无 | 在 mlflow 图上验证边数从 1,850 → ~100 |
| **P2** | `pruner.py` — ReachabilityPruner | AttackSurface 入口点 | 验证只保留真实可达路径 |
| **P3** | `dataflow.py` — Joern 脚本提取 REACHING_DEF | Joern Docker | 从 mlflow 提取数据流路径 |
| **P4** | `dataflow.py` — tree-sitter 轻量级符号执行 | 无 | 在 zipp Python 图上验证 |
| **P5** | `reachability.py` — 入口→sink 矩阵 | P1-P4 | 自动化测试 |
| **P6** | `slicer_v3.py` — v3 切片 → Bulk Analysis | P5 | 对比 v2 切片输出 |
| **P7** | Director `use_v3=True` 开关 | P6 | 全量回归 627+ tests |

---

## 成功标准

1. mlflow Java 图：从 13,130 方法 / 1,850 边 → **<200 方法 / <100 边**（剪枝率 > 90%）
2. 剪枝后不丢失真实漏洞路径（在已知 CVE 上验证）
3. v3 切片输入 LLM 后，Bulk Analysis 的分析质量不低于 v2（在 zipp CVE-2024-5569 上验证）
4. 全量测试回归通过（627+ tests）
