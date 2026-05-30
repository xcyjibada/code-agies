# Agies v2 架构：Brain 驱动的战略审计引擎

> 2026-05-16 架构决策记录
> 替代旧有"全量函数 → 全量 LLM"的线性管道。

---

## 0. 核心原则

```
SAST 是传感器，不是闸门；它给每个入口打标签，但不决定谁能通过。
Brain 是安全总监，它看项目地图 + 标签来做战略判断。
总监可以因为"这个支付模块逻辑复杂"而挑战 SAST 的"没问题"。
天花板在 Brain 的高度，不在 SAST 的高度。
```

**三条铁律：**

1. **SAST 只输出标签（Signals），不输出判决（Judgments）。** `["re.match"]` 是标签，"这是 ReDoS" 是判决。SAST 只做前者。

2. **Brain 决定看什么，不看什么。** 所有函数都对 Brain 可见，SAST 标签只影响优先级，不影响可见性。

3. **LLM 只做推理（Reason），不做搜索（Search）。** 上下文在 LLM 看代码之前就准备好了，不需要 LLM 花 10 轮 tool loop 去"发现"谁调了谁。

---

## 1. 架构总览（5+1 层）

```
                    ┌──────────────────────────────┐
                    │         Brain                 │
                    │   (1 次 LLM, 战略决策)        │
                    │   看项目地图, 分配审计资源     │
                    └──────────┬───────────────────┘
                               │  selected entries
                               ▼
┌──────────────────────────────────────────────────┐
│              Director 情报聚合层                  │
│      (纯确定性, 零 LLM, ~100ms)                  │
│                                                   │
│   ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│   │ Sourcer  │  │  SAST    │  │ AttackSurface │  │
│   │ callgraph│  │ Signals  │  │ 入口发现      │  │
│   │ 函数索引  │  │ 标签系统  │  │ (HTTP/库API)  │  │
│   └──────────┘  └──────────┘  └───────────────┘  │
│                                                   │
│   输出: 对每个入口的攻击链卡片 + SAST 标签         │
│   ├── glob.match → 3 函数, [regex, user_input]    │
│   ├── Path.read → 1 函数, [file_io]               │
│   └── /health → 1 函数, []                        │
└──────────────────────────────────────────────────┘
                               │
                               ▼
           ┌───────────────────────────────────┐
           │    定向 Bulk Analysis              │
           │   (N 次 LLM, 上下文预加载)         │
           │   只分析 Brain 选中的入口关联函数   │
           │   不跑 tool loop, 一次性推理        │
           └────────────────┬──────────────────┘
                            │
                            ▼
           ┌───────────────────────────────────┐
           │      Verification                  │
           │   (M 次 LLM, 按需 tool loop)       │
           │   对 candidates 验证可利用性        │
           └────────────────┬──────────────────┘
                            │
                            ▼
           ┌───────────────────────────────────┐
           │      Report                        │
           │   (确定性, 结构化输出)             │
           └───────────────────────────────────┘
```

---

## 2. 各层详细设计

### 2.1 Director 情报聚合层（新增）

**核心算法：基于 Aider RepoMap 改造的 Tag 提取 + PageRank 风险排序。**

Aider 的原版 RepoMap 使用 tree-sitter 提取 def/ref Tag 后跑 PageRank，回答的是**"哪些文件最热门"**。我们改造为回答**"哪些路径最危险"**：
- Tag 提取从 def/ref 扩展到 SAST 信号（SQL_SINK、CMD_EXEC 等），通过 `.scm` query 文件定义
- PageRank 的 `mul` 倍率注入信号权重，偏置排序到危险代码
- 新增 `nx.has_path` 可达性检测，标记"入口点→危险函数"路径上的所有函数

**目录结构：**
```
agies/engine/
├── director/
│   ├── __init__.py           # Director 入口, 编排三条线
│   ├── repomap.py            # 改造自 Aider RepoMap: Tag 提取 + PageRank
│   ├── signals.py            # 信号权重配置 + .scm query 管理
│   └── aggregator.py         # 攻击链聚合器 (PageRank score + EntryAnalysisCard 生成)
│
├── director/queries/         # tree-sitter .scm query 文件（语言独立）
│   ├── python-tags.scm       # Python: def/ref + 信号查询
│   ├── java-tags.scm         # Java
│   └── js-tags.scm           # JavaScript/TypeScript
```

#### 2.1.1 signals.py — SAST 信号标签系统

**不是说这是"漏洞"，而是打标签说"这里有个可疑的东西"。**

**核心设计原则：**

1. **grep 优先，tree-sitter 仅用于需要 AST 的场景。** 15 个信号里 13 个是纯关键词匹配（如搜索 `execute(` 来标记 SQL_SINK），不需要 AST。只有 `WEB_ROUTE`（识别 route decorator）和 `AUTH_CHECK`（确认是函数定义级别的特征）需要用 tree-sitter 确认结构。

2. **信号不是二元有/无，而是带置信度和频次的。** 同一个信号出现 1 次和 20 次，对 Brain 的意义不同。

3. **正信号和负信号并存。** 正信号（危险操作出现）提高优先级，负信号（测试代码、死代码）降低优先级。

**信号规则定义（grep + AST hybrid）：**

```python
from enum import Enum

class MatchMode(Enum):
    KEYWORD = "keyword"     # 纯文本搜索，最快
    REGEX = "regex"        # 正则模式
    AST = "ast"            # tree-sitter query，仅用于需要结构理解时

SIGNAL_RULES = {
    # ── 正信号：发现可疑模式 ──
    "regex_operation": {
        "description": "函数包含正则操作",
        "match_mode": "keyword",
        "patterns": ["re.match", "re.search", "re.sub", "re.compile", "re.findall"],
        "risk_weight": 0.7,       # 正则操作本身风险中等
    },
    "dynamic_exec": {
        "description": "函数包含动态执行",
        "match_mode": "keyword",
        "patterns": ["eval(", "exec(", "compile("],
        "risk_weight": 0.9,       # 动态执行风险高
    },
    "file_operation": {
        "description": "函数包含文件 I/O",
        "match_mode": "keyword",
        "patterns": ["open(", "os.open", "pathlib.Path("],
        "risk_weight": 0.5,
    },
    "shell_command": {
        "description": "函数包含 shell 调用",
        "match_mode": "keyword",
        "patterns": ["os.system(", "subprocess.", "os.popen("],
        "risk_weight": 0.9,
    },
    "sql_operation": {
        "description": "函数包含数据库操作",
        "match_mode": "keyword",
        "patterns": ["execute(", "cursor.", "session.query", "raw_sql"],
        "risk_weight": 0.8,
    },
    "network_operation": {
        "description": "函数包含网络请求",
        "match_mode": "keyword",
        "patterns": ["requests.", "urllib.", "httpx.", "aiohttp."],
        "risk_weight": 0.5,
    },
    "auth_check": {
        "description": "函数看起来像鉴权逻辑（权限验证是攻击者最喜欢绕过的点）",
        "match_mode": "ast",       # 需要确认是函数定义
        "patterns": ["authenticate", "authorize", "verify_token", "check_role"],
        "risk_weight": 0.7,        # 鉴权逻辑高权重：有鉴权意味着绕过有价值
    },
    "crypto_operation": {
        "description": "函数包含加密操作",
        "match_mode": "keyword",
        "patterns": ["hashlib.", "cryptography.", "jwt.", "hmac."],
        "risk_weight": 0.4,
    },
    "serialization": {
        "description": "函数包含序列化/反序列化",
        "match_mode": "keyword",
        "patterns": ["pickle.", "yaml.load", "json.loads", "marshal."],
        "risk_weight": 0.8,        # pickle 反序列化高风险
    },
    "web_route": {
        "description": "API 入口/路由定义",
        "match_mode": "ast",       # 需要 tree-sitter 确认 decorator
        "patterns": ["@app.route", "@blueprint.route", "@RequestMapping"],
        "risk_weight": 0.6,
    },
    "user_input_reachable": {
        "description": "函数的参数对外部输入可达",
        "match_mode": "ast",       # 由 call graph BFS 追溯，见 2.1.4
        "via": "call_graph_trace",
        "risk_weight": 0.9,        # 用户输入可达大幅提升风险
    },

    # ── 负信号：降权（将权重乘以 discount）──
    "test_code": {
        "description": "函数位于测试文件或测试目录",
        "match_mode": "keyword",
        "patterns": [],            # 由 path 判断：test_, _test, conftest
        "weight_discount": 0.0,    # 测试代码的信号权重归零
        "is_negative": True,
    },
    "dead_code": {
        "description": "函数在 call graph 中没有任何调用者",
        "match_mode": "ast",       # 来自 call graph 分析
        "weight_discount": 0.1,    # 几乎不可达
        "is_negative": True,
    },
    "pure_helper": {
        "description": "纯工具函数：无 I/O 无副作用，只做计算",
        "match_mode": "ast",       # 由 AST 分析：调用的函数全是内置或纯函数
        "weight_discount": 0.3,
        "is_negative": True,
    },
}
```

**为什么不写 2000 条规则？** 因为角色不同。Semgrep 的 2000 条规则目的是"找出漏洞"，所以对上下文敏感、误报率要低。agies 的信号系统目的是"提示 Brain 这里有料"，不需要高精度——这 10 条正信号 + 3 条负信号覆盖了 90% 的常见漏洞模式入口，漏掉的由 Brain 的直觉和 Track B 兜底。

##### confidence 计算规则

信号不是二元有/无。每次扫描返回一个 `Signal` 对象：

```python
@dataclass
class Signal:
    tag: str                # 信号标签名
    risk_weight: float      # 信号类型的基础权重（0-1，预定义）
    hit_count: int          # 命中次数
    is_negative: bool       # 是否为负信号
    weight_discount: float  # 负信号：权重乘数（0 = 完全忽略）
    source: str             # 信号来源："keyword" | "regex" | "ast" | "call_graph"

    @property
    def effective_weight(self) -> float:
        """信号对 Brain 决策的有效影响权重。"""
        if self.is_negative:
            return self.weight_discount              # 负信号直接返回 discount

        # 正信号：基于命中次数调整置信度
        if self.hit_count >= 5:
            confidence = 1.0
        elif self.hit_count >= 2:
            confidence = 0.7
        else:
            confidence = 0.3                         # 只出现 1 次 -> 低可信

        return self.risk_weight * confidence
```

**为什么要用 confidence 计算规则？** 没有规则的 confidence 是噪声。如果一个信号只在 136 个函数里出现 1 次，它不应该和同一个信号出现 20 次有相同的权重。

**输出示例（挂载到每个函数上）：**

```python
# signals.py 的 scan_function(fn, call_graph) 输出
FunctionSignals = {
    "positive": [
        Signal(tag="regex_operation", risk_weight=0.7, hit_count=3, ...),
        Signal(tag="user_input_reachable", risk_weight=0.9, hit_count=1, ...),
    ],
    "negative": [
        Signal(tag="pure_helper", weight_discount=0.3, ...),
    ],
    "effective_weight": max(0.7 * 1.0, 0.9 * 0.3) * 0.3,
    # = max(0.7, 0.27) * 0.3 = 0.21  （因为 pure_helper discount）
    # 这个函数虽然危险操作多，但它是纯工具函数，整体权重被降权
}
```

#### 2.1.2 aggregator.py — 攻击链聚合器（PageRank + 可达性权重）

**核心算法：改造 Aider RepoMap 的 `get_ranked_tags()`，将"热门度排序"替换为"风险排序"。**

```
Aider 原版:
  提取 Tag (def/ref) → PageRank → "哪些文件最热门"

Agies 改造:
  提取 Tag (def/ref + signal) → PageRank + has_path → "哪些路径最危险"
```

##### 算法步骤

```
Step 1: 提取 Tag
  repomap.py: get_tags_raw(fname)
    → tree-sitter parse 每个文件
    → 提取 def/ref Tag（来自 {lang}-tags.scm 的 def/ref 查询）
    → 提取 signal Tag（来自 {lang}-tags.scm 追加的信号查询）
    → 输出: Tag(rel_fname, fname, line, name, kind="def"|"ref"|"signal", signal_type=...)

Step 2: 构建图 + 注入信号权重
  repomap.py: get_ranked_tags()
    → 构建 MultiDiGraph G
    → 边: referencer → definer, weight = num_refs × mul
    
    关键改造：mul 注入信号权重
      if tag.kind == "signal":
          mul *= SIGNAL_MUL.get(tag.signal_type, 1.0)
      if tag.name in entry_points:
          mul *= 100                    # 入口点权重最高
      if is_auth_logic(tag.name):
          mul *= 20                     # 鉴权逻辑是攻击者关注点
      if is_dead_code(tag.name):
          mul *= 0.1                    # 死代码降权
      if has_negative_signal(tag.name):
          mul *= 0.0                    # 测试代码直接归零

    → 跑 PageRank: ranked = nx.pagerank(G, weight="weight")

Step 3: 可达性权重（has_path）
  上述 PageRank 回答的是"哪些节点引用最多"，但我们需要的是"哪些节点在攻击路径上"。
  
  for each sink (SQL_SINK, CMD_EXEC 等信号节点):
      for each entry (WEB_ROUTE, public API 等入口节点):
          if nx.has_path(G, entry, sink):
              # 标记从 entry 可达 sink 的所有函数
              reachable_from_entry = nx.descendants(G, entry)
              can_reach_sink = nx.ancestors(G, sink)
              on_attack_path = reachable_from_entry & can_reach_sink
              
              for node in on_attack_path:
                  G.nodes[node]['attack_path_score'] += 500

Step 4: 最终排序分
  final_score = PageRank × 0.3 + attack_path_score × 0.7
  → 按 final_score 降序排列
  → sleep(0) 函数自然排最后, password_reset 排最前
```

**输入：** FunctionIndex + 入口点列表 + FunctionSignals

**输出：** EntryAnalysisCard 列表（每个入口一张卡片，`urgency_score` 来自 PageRank 综合排序）

```python
@dataclass
class AggregatedSignal:
    """信号在入口调用链上的聚合结果"""
    tag: str
    total_hits: int                      # 调用链上该信号总命中次数
    unique_functions: int                # 涉及的不同函数数
    max_depth: int                       # 最深出现深度（deep = more critical）
    effective_weight: float              # 聚合后的有效权重
    is_user_controlled: bool             # 链路上是否包含 user_input_reachable

class EntryAnalysisCard(BaseModel):
    entry: str                           # 入口标识
    entry_type: str                      # http_endpoint | public_api
    file_path: str
    line_number: int
    
    # 调用链信息——来自 call graph 的图遍历
    involved_functions: list[FunctionInfo]
    call_chain_depth: int                # 从入口最深的调用链
    function_count: int                  # 涉及的总函数数
    total_code_lines: int                # 涉及的总代码行数
    
    # SAST 信号聚合
    aggregated_signals: list[AggregatedSignal]  # 聚合后的信号列表
    saast_signals: list[str]                    # 去重聚合的所有信号名（向后兼容）
    
    # 业务特征
    code_complexity: str                 # low | medium | high
    risk_indicators: list[str]           # "深层调用链"等提示
    
    # ── PageRank + 攻击路径综合评分（替代旧的启发式 urgency_score） ──
    pagerank_score: float = 0.0          # 基础热度分
    attack_path_score: float = 0.0       # 可达性分（入口→sink 路径上的节点）
    final_score: float = 0.0             # final = pagerank × 0.3 + attack_path × 0.7
    
    urgency_score: float = 0.0           # = final_score（向后兼容名）
```

**信号权重配置：**

```python
SIGNAL_MUL = {
    # 用于注入 PageRank 的 mul 倍率
    "entry_point": 100,         # 入口点：最重要的推荐倍率
    "sql_sink": 80,             # SQL 注入路径
    "cmd_exec": 80,             # 命令执行
    "auth_check": 20,           # 鉴权逻辑（用户指出我低估了它）
    "regex_operation": 15,      # ReDoS
    "serialization": 20,        # 反序列化
    "file_operation": 10,       # 文件操作需要上下文判断
    "crypto_operation": 5,      # 加密误用通常需要人工
    "network_operation": 5,     # 网络请求需要上下文
    # 负信号
    "test_code": 0.0,           # 测试代码直接归零
    "dead_code": 0.1,           # 死代码几乎归零
    "pure_helper": 0.3,         # 纯工具函数大幅降权
}
```

**追踪调用链的算法（纯确定性）：**

```python
def expand_call_chain(entry_func: str, function_index: FunctionIndex, 
                      max_depth: int = 10) -> list[FunctionInfo]:
    """
    BFS 遍历 call graph, 从 entry_func 出发找到所有可达函数。
    不分析数据流, 不判断善恶, 只做图遍历。
    """
    visited = set()
    queue = [(entry_func, 0)]
    result = []
    
    while queue and len(queue) < 100:   # 防止爆炸
        fn_name, depth = queue.pop(0)
        if fn_name in visited or depth > max_depth:
            continue
        visited.add(fn_name)
        
        fn = function_index.find(fn_name)
        if fn:
            result.append(FunctionInfo(
                name=fn_name, file=fn.file_path, 
                line=fn.line_start, depth=depth,
                signals=fn.signals,    # 来自 signals.py 的标签
            ))
        
        # BFS 下一层
        for callee in function_index.get_callees(fn_name):
            queue.append((callee, depth + 1))
    
    return result
```

**成本：** PageRank O(N·I) 其中 N=节点数（~200）, I=迭代数（~100）≈ 20ms。BFS O(E) 其中 E=边数（~500）≈ 5ms。

#### 2.1.3 处理库项目（zipp 类型）

AttackSurface Agent 在库项目模式下输出 `__all__` + 模块顶层函数作为入口点：

```python
# 库项目的分析卡片
{
    "entry": "glob.match",
    "entry_type": "public_api",
    "functions_involved": [
        {"name": "match", "signals": ["regex_operation"]},
        {"name": "_compile_pattern", "signals": ["regex_operation"]},
        {"name": "translate_core", "signals": ["regex_operation", "user_input_reachable"]},
    ],
    "saast_signals": ["regex_operation", "user_input_reachable"],
    "call_chain_depth": 3,
    "function_count": 3,
    "code_complexity": "medium",
}
```

---

#### 2.1.4 `user_input_reachable` 信号的计算算法

这个信号是**整个 SAST 系统里唯一真正需要跨函数分析的信号**，也是 Brain 做决策时权重最高的信号。需要明确定义计算方式。

**算法：BFS 向上追溯 caller，判断是否可达入口函数**

```python
def compute_user_input_reachable(
    fn: SourceFunction,
    call_graph: CallGraph,
    entry_points: list[str],       # 已知的入口函数名
) -> bool:
    """
    从 fn 向上追溯 callers，如果某个 caller 是已知入口函数，
    则认为 fn 的参数是用户可控的。
    
    纯 call graph BFS，不做数据流分析。
    """
    visited = set()
    queue = [fn.fullname]
    max_traversal = 100             # 防止爆炸
    
    while queue and len(visited) < max_traversal:
        name = queue.pop(0)
        if name in visited:
            continue
        visited.add(name)
        
        # 找到了入口点 -> 用户输入可达
        if name in entry_points:
            return True
        
        # 继续向上追溯
        for caller in call_graph.get_callers(name):
            queue.append(caller)
    
    return False
```

**为什么不直接做全量 taint tracking？**

因为 SS 不需要知道"数据流怎么走的"，只需要知道"数据能不能从用户到这儿"——一个 bool 就够了。call graph BFS 在毫秒级完成，full taint tracking 在秒级。

**但这个算法的局限：**

1. 只追踪函数调用链，不追踪数据流。如果参数通过全局变量、返回值、回调等间接方式传递，BFS 会漏掉。
2. 只向上追溯 caller，不往下追 callee。

**应对：**

- 初期用这个简单算法覆盖 80% 的场景
- 在 `agies/analyzer/taint.py` 已有的 taint tracking 完成后，用其结果补充 `user_input_reachable` 信号（taint 确认的 +0.2 权重加成）
- 但 **Director 层不阻塞在 taint 上**——先出 BFS 结果，taint 完成后 patch 进去

**Brain 做的是战略决策，不是微观调度。** 它只看 Director 聚合好的分析卡片，不看源码。

**改动集中在 `brain.py` 的 `_build_calls` 方法**，增加一个 `_brain_decide_strategy()` 的 LLM 决策步骤。

#### 2.2.1 Brain 的输入

```python
brain_input = {
    "project": {
        "name": "zipp",
        "language": "Python",
        "type": "library",              # library | webapp | cli
        "file_count": 18,
        "function_count": 136,
    },
    "entry_points": [
        {
            "entry": "glob.match",
            "type": "public_api",
            "file": "zipp/glob.py",
            "function_count": 3,
            "call_chain_depth": 3,
            "total_code_lines": 48,
            "saast_signals": ["regex_operation", "user_input_reachable"],
            "risk_indicators": ["正则操作, 用户输入可达"],
        },
        {
            "entry": "Path.read_bytes",
            "type": "public_api",
            "file": "zipp/__init__.py",
            "function_count": 2,
            "call_chain_depth": 1,
            "total_code_lines": 12,
            "saast_signals": ["file_operation"],
            "risk_indicators": [],
        },
        # ... 3-10 个入口点
    ],
    "modules": [
        {"name": "glob", "signals": ["regex", "user_input"], "functions": 3, "lines": 88},
        {"name": "core", "signals": ["file_io"], "functions": 15, "lines": 420},
        {"name": "compat", "signals": [], "functions": 6, "lines": 45},
    ]
}
```

**绝不传入：** `136` 个函数签名列表，不传函数体源码。

#### 2.2.2 Brain 的 Prompt（新写）

```
You are the **Strategic Director** of the agies code audit engine. 

Your role is like a CISO assigning tasks to security analysts.
You do NOT read source code. You read **intelligence summaries**.

## Input

You receive:
1. **Project profile** — language, type (library/webapp/CLI), scale
2. **Entry points** — each entry point comes with:
   - How many functions it touches (via call graph)
   - How deep the call chain is
   - SAST signal tags (regex/file_io/sql/network/crypto...)
   - Risk indicators
3. **Module structure** — high-level module breakdown

## Your Task

Decide which entry points to audit. Your decision is strategic:

1. **Prioritize risk**: Entry points handling user input + dangerous operations
   (regex, SQL, file I/O, eval) get priority.
2. **Prioritize core logic**: Business-critical modules (payment, auth, data processing)
   deserve attention even without strong SAST signals.
3. **Skip low-value targets**: Utility functions, compatibility shims, health checks.
4. **Your decision is final**: You can override SAST — if a module looks suspicious
   despite clean SAST signals, flag it. SAST tags are information, not verdicts.

## Output

Return a JSON object:

{
  "selected_entries": [
    {
      "entry": "glob.match",
      "reason": "regex with user-controlled input → ReDoS risk",
      "risk_level": "high",
      "analysis_focus": "regex operations in call chain"
    },
    {
      "entry": "Path.read_bytes",
      "reason": "file I/O in core path",
      "risk_level": "medium",
      "analysis_focus": "path traversal"
    }
  ],
  "skipped_entries": [
    {
      "entry": "/health",
      "reason": "no external input, no dangerous operations",
      "risk_level": "none"
    }
  ],
  "strategic_reasoning": "The main attack surface is glob pattern matching...",
  "coverage_estimate": "~80% of risk surface covered by selected entries",
  "confidence": "high"
}
```

#### 2.2.3 Brain 的决策流程（伪代码）

```python
# brain.py 的新逻辑

def _build_calls_new_pipeline(self, name: str, agent, state):
    if name == "mapping":
        return [mapping_call]               # 不变
    
    if name == "sourcer":
        return [sourcer_call]               # 不变
    
    # --- 新增：Brain 战略决策 ---
    if name == "brain_strategy":
        # Director 已经准备好了分析卡片
        cards = state.analysis_cards        # 来自 director/aggregator.py
        
        decision = llm.chat_completion(
            messages=[
                {"role": "system", "content": BRAIN_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps({
                    "project": state.project_summary,
                    "entry_points": [c.to_decision_input() for c in cards],
                    "modules": state.modules,
                })}
            ]
        )
        # 解析出 {selected_entries: [...], skipped_entries: [...]}
        strategy = parse_brain_decision(decision)
        state.strategy = strategy
        return []       # 不直接产生 AgentCall, 而是设置 state
    
    if name == "bulk_analysis":
        # 只对 Brain 选中的 entry 的 involved_functions 做分析
        selected = state.strategy.get("selected_entries", [])
        all_function_names = set()
        for entry in selected:
            card = state.find_card(entry["entry"])
            all_function_names.update(
                fi.name for fi in card.involved_functions
            )
        
        return [
            AgentCall(
                agent_name="bulk_analysis",
                agent=agent,
                params={
                    "target_functions": list(all_function_names),
                    "entry_context": state.strategy,   # 把战略上下文传下去
                    "function_index": state.function_index,
                }
            )
        ]
    
    if name == "verification":
        # 不变，但 candidate 数量已经是缩小后的
        ...
```

#### 2.2.4 Brain 的调度流程

```python
# brain.py run() 的新流程

def run(self, project_path, use_new_pipeline):
    state = ProjectState(project_path, use_new_pipeline)
    
    # Phase 0: 确定性情报收集 (Director)
    self._run_director(state)          # repomap + signals + aggregator (PageRank + has_path)
    
    # Phase 1: Brain 战略决策 (1 次 LLM)
    self._brain_decide_strategy(state) # 写入 state.strategy
    
    # Phase 2: 定向分析 + 验证
    # 只对 Brain 选中的 entry 做 bulk → verification → report
    ...
```

---
### 2.2.5 Brain 的决策标准：确定性排序 + LLM 重排

Brain 不直接收 50 个入口全量去决策——那样 LLM 也会 Lost in the Middle。改为两步：

**第一步：Director 层确定性排序（零 LLM）**

Director 的 repomap.py 已经完成了 PageRank + 可达性权重计算，每个入口带有 `final_score`：

```python
# Director 排序入口：PageRank × 0.3 + attack_path_score × 0.7
# 自然结果：sleep(0) 排最后, password_reset 排最前
cards = sorted(cards, key=lambda c: c.final_score, reverse=True)

# 只把 top N 或 top 30% 交给 Brain
max_cards = min(15, max(5, len(cards) // 3))
shortlist = cards[:max_cards]

# 剩下的入口自动标记为 skipped
skipped_default = [
    {"entry": c.entry, "reason": "Low urgency score", "risk_level": "low"}
    for c in cards[max_cards:]
]
```

**第二步：Brain LLM 重排（1 次 LLM 调用）**

Brain 接收 shortlist（不超过 15 个入口），从中做精细选择：

```python
brain_input = {
    "project": {...},
    "shortlisted_entry_points": [
        # 每个入口已经带上了 urgency_score 和完整的信号聚合
        c.to_brain_format() for c in shortlist
    ],
    "already_skipped": [
        # 告知 Brain 有哪些被跳过了（透明化）
        {"entry": c.entry, "reason": "auto-skipped: urgency too low"}
        for c in skipped_default
    ],
}

# LLM 重排
strategy = llm.decide(brain_input)
# 输出：从 15 个 shortlisted 入口中选最终要分析的 3-8 个
```

**为什么需要这个两步？**

- 纯确定性排序：快、稳、可解释，但死板（只看数值不看业务语义）
- 纯 LLM 决策：灵活但贵，且 >15 个入口时 LLM 注意力稀释

> **两步的结合是关键：确定性负责砍数量（50 → 15），LLM 负责提质量（15 → 5）。**
> 两者中间没有重叠——每个入口要么走 shortlist（给 Brain 判断），要么走 skipped（确定性判定）。
> Brain 可以否决 shortlist 里的入口（"这个虽然分高但其实是安全的兼容垫片"），
> 但**不能把 skipped 里的入口拉回来**。要防止 LLM 被 50 个入口冲垮。

**不再用旧版的 `analyze_single_functions` 所有函数遍历，** 改为按入口点批量拉取：

```python
def analyze_targeted_functions(
    function_names: list[str],
    entry_cards: list[EntryAnalysisCard],
    function_index: FunctionIndex,
    llm: Any,
    max_workers: int = 10,
) -> BulkAnalysisOutput:
    
    # 对每个被选中的入口，分析其 entire call chain
    candidates = []
    for card in entry_cards:
        # 预加载该入口所有关联函数的上下文
        context_bundle = build_context_bundle(card, function_index)
        
        # 一次 LLM 调用分析整条链（不是逐函数）
        chain_candidates = _analyze_entry_chain(context_bundle, llm)
        candidates.extend(chain_candidates)
    
    return BulkAnalysisOutput(candidates=candidates, ...)
```

**不再对每个函数独立调 LLM**，而是对一个入口的整条调用链一次性分析：

```python
# 新的 bulk prompt 是 "分析这条攻击链"
BULK_SYSTEM_PROMPT = """
You are analyzing a call chain starting from an entry point.

Entry Point: {entry_name}
SAST Signals: {signals}

Call Chain Functions:
{逐函数列出: 函数名, 签名, SAST标签, 关键代码行}

Analyze whether this call chain contains exploitable vulnerabilities.
Consider:
1. Does the entry point accept untrusted input?
2. How does input flow through the call chain?
3. Are there dangerous operations (regex, SQL, file I/O, eval)?
4. Is there validation that prevents exploitation?

Output vulnerabilities found in this chain.
"""
```

效果：136 个函数 → 5 个入口 → 3 个被选中 → 3 次 LLM 调用（每次分析一整个调用链）。

---

## 3. 天花板分析

### 不会锁天花板的三条回路

```
回路 A: SAST 信号 → Brain 确认 → 审计
   起点: SAST 发现正则操作 → Brain 认为高风险 → 派 Agent
    
回路 B: SAST 信号 → Brain 否决 → 跳过（但有记录）
   起点: SAST 发现 file I/O → Brain 认为"只是日志写入" → 跳过
   如果之后发现有漏洞，回归分析会质疑 Brain 的决策
    
回路 C: SAST 无信号 → Brain 直觉 → 审计
   起点: 支付模块 SAST 只看到"加法" → Brain 看项目地图
        发现是核心业务逻辑 → 派 Agent 深度分析 → 
        Agent 发现"状态机绕过导致双重支付"
   → 这是 agies 的核心价值场景。SAST 永远找不到的漏洞。
```

**回路 C 证明了天花板不在 SAST。** Brain 不知道"代码里面有什么"，但知道"这是支付模块"——这种业务信息不是从代码模式中提取的，而是从 Mapping Agent 的项目结构分析中来的。

### "但如果 Brain 也不觉得那里重要呢？"

那就和全量扫描一样漏了。区别在于：

- 全量扫描：每个函数都看，但质量差（因为上下文不足、token 预算有限、LLM 注意力被稀释）
- Brain 策略：只看最关键的 10-20%，但质量高（上下文充分、token 集中）

**后者在有限预算下的效果更好。** 无限预算的话当然是全量好——但在生产环境，预算永远有限。

---

## 4. 与当前架构的成本对比

### zipp 案例（18 个文件, 136 个函数, 5 个入口）

| 步骤 | 当前架构 | v2 架构 |
|------|---------|---------|
| Director | — | 0 LLM, ~100ms |
| Brain 战略 | — | **1 次 LLM** |
| Bulk 分析 | **136 次 LLM** (逐函数) | **3-5 次 LLM** (逐入口调用链) |
| Verification | **~100 次 LLM** | **~15 次** |
| **总计** | **~236 次 LLM, ~5 分钟** | **~20 次 LLM, ~30 秒** |
| **成本估算** | ~$1.2 | ~$0.10 |

### 5 万行 Spring Boot 项目

| 步骤 | 当前架构 | v2 架构 |
|------|---------|---------|
| Director | — | 0 LLM, ~500ms |
| Brain 战略 | — | **1 次 LLM** |
| Bulk 分析 | ~8,000 次 LLM | ~50-80 次 LLM (10-15 入口 × 5-8 函数/入口) |
| Verification | ~2,000 次 LLM | ~100-200 次 |
| **总计** | **~10,000 次 LLM, ~2 小时** | **~200 次 LLM, 5-10 分钟** |
| **成本估算** | ~$50 | ~$1 |

### Verification 的 20% 失败率为什么消失

答案很简单：**上下文预加载消除了 tool loop。**

旧：LLM 每次只看到 1 个孤立的函数体 → 必须通过 10 轮 tool call 去"发现"谁调了我、我的输入来自哪里
新：LLM 看到的是完整的攻击链 + 标签 + 调用序列 → 一次 LLM 调用就能做出判断

**不需要 iteration limit 就不存在 iteration limit failure。**

---

## 5. 落地步骤

### Phase 1：Director 情报层（2 天）

| # | 内容 | 文件 | 行数 |
|---|------|------|------|
| 1 | 精简并改造 Aider `repomap.py`：提取 get_tags_raw + get_ranked_tags，去掉 diskcache/pygments/grep-ast 依赖 | `director/repomap.py` | ~300 |
| 2 | 创建 SAST 信号 `.scm` query 文件：在 def/ref 查询外追加 15 条信号查询 | `director/queries/python-tags.scm` | ~80 |
| 3 | 创建 `director/signals.py` — 信号权重配置 + compute_confidence + 信号聚合 | 新建 | ~80 |
| 4 | 创建 `director/aggregator.py` — PageRank 排序 + has_path 可达性 + EntryAnalysisCard 生成 | 新建 | ~150 |
| 5 | 创建 `director/__init__.py` — Director 入口编排 | 新建 | ~50 |
| 6 | AttackSurface 扩展库项目模式 | 修改 | ~30 |
| | **小计** | | **~690** |

### Phase 2：Brain 战略决策（1 天）

| # | 内容 | 文件 | 行数 |
|---|------|------|------|
| 5 | 编写 Brain 战略决策 Prompt | `brain.py` | ~80 |
| 6 | 实现 `_brain_decide_strategy()` | `brain.py` | ~60 |
| 7 | 改造 `_build_calls` 新管道分支 | `brain.py` | ~80 |
| 8 | 改造 `run()` 新流程 | `brain.py` | ~40 |
| | **小计** | | **~260** |

### Phase 3：定向 Bulk + 适配（1 天）

| # | 内容 | 文件 | 行数 |
|---|------|------|------|
| 9 | 实现入口级别的 bulk 分析 | `analysis/bulk.py` | ~100 |
| 10 | 验证适配：AnalysisCard 输入 | `agents/verification_agent.py` | ~50 |
| 11 | 移除旧的全量扫描路径 | `analysis/bulk.py` | ~-30 |
| 12 | 更新 `state.py` 支持新数据结构 | `state.py` | ~60 |
| | **小计** | | **~180** |

### 总计

- **3 天工作量**
- **~820 行新增 / ~30 行删除**
- **不破坏现有代码**（`use_new_pipeline=True/False` 切换，旧管道保留）

---

## 6. 风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| Brain 选错了入口 | 漏掉漏洞 | Track B 兜底：`--no-brain-strategy` 回退全量扫描；同时记录决策 log 供事后分析 |
| SAST 标签太少 | 区分度不够 | 初期 10 条规则已够，后续按需 +5-10 条，不做 2000 条 |
| 调用链 BFS 爆炸 | Director 变慢 | 设 max_depth=10, max_functions=100，超限截断 |
| 库项目的入口定义争议 | 漏掉或囊括过多 | AttackSurface 的库模式先输出 `__all__` + 模块顶层函数 (exported + 10行以上) |
| Brain 的决策与全量扫描不一致 | 信心不足 | 添加 `--verify-strategy` 模式：Brain 决策后，对跳过的 entry 随机采样 5% 做盲审验证 |

---

## 7. 扩展设想（后续迭代）

### 回归分析（Feedback Loop）

每次审计结束后，把结果反馈给 Brain：

```
审计发现: /api/pay 有漏洞(已确认)
Brain 决策: 选中 /api/pay 为 high priority ✓ (正确)

回顾分析: /health 被跳过, 虽然本次未发现漏洞
但审计后确认 /health 确实无风险 → Brain 决策正确
```

长期积累后变为"这个代码库的审计签名"，下次跑更快。

### 多轮 Brain

第一轮 Brain 选择入口 A，审计发现了漏洞。Brain 可以决定：既然在 A 上发现了漏洞，B、C、D 同属一个模块，要不要扩大范围？

这是 Xint 式的动态调度（不是全量也不是固定范围），在 v2 架构中扩展到第二轮很简单——回到 Director 更新状态，再调一次 Brain 决策。

---

> **与其他架构的关系**
>
> 本架构不替代 `IDEA.md` 中的 Architecture Design 长期规划。
> 它描述的是 `use_new_pipeline=True` 下具体如何落地。
> 旧管道（mapping → attack_surface → dataflow → vulnerability → verify）保持不变，
> 用于兼容已有测试和工作流。

---

## 8. Architecture Critique：函数级 vs 路径级分析的偏差

> 2026-05-30 基于 xint 商业产品 + sandyaa 开源的对比分析
> 本架构文档的设计方向基本正确，但实现存在重大偏差。

### 8.1 文档 vs 实现的偏差

| 维度 | 文档描述（第 2.2.5 节） | 实际代码（bulk.py） |
|------|-----------------------|-------------------|
| 分析单位 | **入口的整条调用链** | 单函数（附带调用链注释） |
| 函数筛选 | 只分析 Brain 选中的入口关联函数 | 所有函数都分析，按优先级排序 |
| 调用链角色 | LLM 在路径上下文中推理 | LLM 看到的是"函数 body + 文本附注" |
| LLM 调用量 | ~3-5 次（每入口一次） | 200-400 次（每函数一次） |

**v2 实际在做的事：** 给 LLM 看单个函数体 body + 一段文本附注（"此函数从 /upload 可达，风险分 0.85"）。LLM 只能**猜测**漏洞是否可利用——"参数好像是用户控制的吧？不确定..."

**v2 应该做的事：** 把"函数"作为路径上的节点，只给 LLM 看入口→sink 的整条代码路径。LLM 可以**断定**漏洞的可利用性——"handle_request 把 request.body 传给 process_data，没有校验就调了 unsafe_deserialize(pickle.load(input))，路径走通，RCE。"

### 8.2 为什么分析单位应该是"路径"而不是"函数"

**单函数的可疑性是模糊的**——`pickle.loads(data)` 出现在函数里，但调用者是否已经校验过输入？LLM 只看这个函数说不清。

**路径的可利用性是确定的**——入口→中间处理→sink，每一步的数据流动 LLM 都能看见。它可以判断：
- "这条路能走通" → 确认漏洞
- "这里做了 sanitize" → 排除误报
- "参数是内部生成的不是用户控制的" → 降级为低危

这个差异的本质是 **LLM 从"猜"变成了"判断"**。猜需要更多的交叉验证轮数，判断可以一次性做出。

### 8.3 xint 的猜想：入口→sink 的路径过滤

根据 Theori 的公开架构 + ZeroDay Cloud 结果（Redis/PostgreSQL/MariaDB 百万行级项目的 0-day），大概率不是逐函数分析：

```
入口点识别（有限的几个，来自 AIxCC 的 challenge binary 经验）
  → 从入口点做可达性分析
  → 只有"从入口可达且有可疑 sink"的路径进入 LLM
  → LLM 分析整条路径的完整代码
  → 确认可利用性 → PoC
```

如果逐函数分析百万行项目，仅 token 成本就几万美元，不现实。

### 8.4 修复方向：三层漏斗

```
第一层（全量，确定性，零 LLM，低成本）
  tree-sitter/Joern CPG 扫描
  → 标注每个函数: 入口可达? 含 sink? 类型?
  → 建立调用图: 谁调了谁, 从哪来

第二层（路径过滤，确定性）
  路径构建: 入口 → 中间函数 → sink
  过滤规则: 只有完整路径（入口可达 + sink 可达）才进入候选
  → 这条路径上的所有函数作为一个分析单元
  → 不在任何路径上的函数 → 跳过

第三层（LLM 推理，带路径上下文）
  LLM 收到的是整条路径的代码:
    handle_request (入口, HTTP body)
      → process_data (中间, 无校验)
        → unsafe_deserialize (sink, pickle.load)
  → LLM 判断: "数据流成立, 参数可控, RCE"
  → 每分析一条路径 = 1 次 LLM 调用
```

### 8.5 具体改动

**分析粒度从函数→路径**：

```python
# 现在的 bulk.py:
for fn in all_functions:
    candidates += analyze_single_function(fn, context)

# 应该改成:
for path in build_paths(function_index, entry_points, sinks):
    candidates += analyze_path(path)
    # 1 次 LLM 调用, 传入整条路径的代码
```

**调用链上下文从"附注"变成"代码"**：

```python
# 现在的 context:
"此函数从 /upload 可达, 风险分 0.85"

# 应该变成:
"入口: handle_request at app.py:42\n"
"  → process_data at utils.py:15 (param: request.body)\n"
"  → unsafe_deserialize at io.py:88 (param: data, calls pickle.load)\n"
+ handle_request body + process_data body + unsafe_deserialize body
```

**LLM 从逐函数调用变成逐路径调用**：

```
当前: 400 个函数 × 1 次 LLM = 400 次调用, 每次猜"这个函数有洞吗?"
目标: 15 条路径 × 1 次 LLM = 15 次调用, 每次判断"这条路走得通吗?"
```

### 8.6 为什么不立即改

1. v3 的 Joern CPG 已经在做精确的入口→sink 路径构建——等 v3 稳定后再合并方向
2. 当前 v2 对中小项目（<500 函数）仍有效——全量分析的开销可控
3. 需要确保路径构建的完备性——漏路径比漏函数更严重
4. 依赖 `IDEA.md` 中的 v3 长期规划——路径分析是 v3 的核心能力

### 8.7 过渡期建议

| 项目规模 | 当前策略 | 建议 |
|---------|---------|------|
| < 200 函数 | 全量分析 | 继续用 v2，收益大于成本 |
| 200-2000 函数 | 按优先级截断 | v2 bulk 的`max_functions` 硬限制已启动 |
| > 2000 函数 | 全量不可行 | 切换到 v3 路径分析（Joern CPG + 路径过滤） |
