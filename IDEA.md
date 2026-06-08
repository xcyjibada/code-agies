# agies 架构思路

> 目标：复现 Xint Code 级别的 AI 代码审计能力。核心思路是"确定性调度 + 多 Agent 协作"，而非"一个 LLM 做所有事"。
>
> 当前阶段：v3 — 在 ProgramGraph 之上做噪音剪枝、数据流分析、攻击路径枚举。
> 详见图谱 v3 规划：`docs/v3/plan.md`。

---

## 核心哲学

### agies 不是另一个 Semgrep

传统工具（Semgrep、CodeQL）死于模式匹配。它们找的是危险函数（`eval`、`exec`、SQL 拼接），但发现不了业务逻辑漏洞——因为业务逻辑漏洞的本质不是"代码有危险函数"，而是"开发者想了一件正确的事，写出来却有偏差"。

LLM 的不可替代优势是**理解开发者的意图**：
- 读代码时能猜到"这人本来想干什么"
- 对比"想的"和"写的"之间的差距
- 把差距定性为漏洞，给出攻击路径假设

### Vulnerability Agent 是产品核心，其他都是上下文

```
不是：
  Mapping → Surface → DataFlow → Vulnerability → Verify
                                    ↑
                              只是一个分析步骤

而是：
  Vulnerability Agent ← 核心价值在这里
          ↑
  需要什么上下文就给什么
          │
  Mapping ── 项目在做什么？信任了什么？什么值得怀疑？
  Surface ── 攻击者能从哪里进来？
  DataFlow ─ 输入从哪里流到了哪里？
 ```
 
 所以开发优先级也变了：
 ```
 Step 0: 搭骨架（state, base, brain, runner） → 已完成骨架
 Step 1: Mapping Agent + Vulnerability Agent  ← 核心价值优先
 Step 2: Attack Surface Agent → 让 Vuln Agent 更精准
 Step 3: DataFlow Agent → 让 Vuln Agent 能追踪复杂调用链
 Step 4: Verify + Report Agent
 Step 5: 上下文管理 + 压缩
 ```

### 安全研究员的思维模型

Vulnerability Agent 模仿的是安全研究员的工作方式：

1. **理解上下文**：这个项目是做什么的？核心模块是什么？
2. **问"如果"问题**：如果用户传入这个参数会怎样？如果把这两个无关端点组合呢？
3. **打破信任假设**：开发者信任了什么？这些信任站得住吗？
4. **验证攻击路径**：入口 → 中间处理 → 最终影响，整条链能走通吗？

每一步都需要 LLM 理解意图，不是模式匹配。

---

## SAST 的定位：证据方，不是验证者

> 2026-05-12 架构决策

### 核心矛盾

LLM 有能力发现**全新类型的漏洞**（比如 Xint 发现的 CVE-31431），但如果用 SAST 当"质量门"去验证 LLM 的输出，新漏洞会因为"SAST 没有匹配规则"而被否决——产品的上限被锁死在 SAST 的知识上限。

### 决策：SAST 贡献证据，LLM 做判断

```
LLM 发现可疑点
    ↓
SAST（确定性分析）提供三方面证据：
  1. taint_trace(suspect_line) → 输入能否到达 → 路径存在性
  2. call_graph.trace(entry, sink) → 调用链是否完整
  3. pattern_match(code) → 是否匹配已知漏洞模式
    ↓
证据进入置信度评分，不是一票否决
```

### 信任模型

```
SAST 说"是"                SAST 说"否"
─────────────────────────────────────────────
路径确认 ✓                未发现路径 ≠ 不存在
模式匹配 ✓（已知类型）     不匹配已知模式 ≠ 不是漏洞
调用链完整 ✓              调用链不完整 → 降低置信度

证据是加分制：路径确认 +0.3，模式匹配 +0.2...
LLM 的推理永远是起点，不被 SAST 沉默。
```

### 架构影响

- `agies/analyzer/` → 重组为 `engine/sast/`，分两阶段实现，**相互独立**：

  - **Phase A（规则匹配器，先做）**  
    - `matcher.py` — 基于 tree-sitter 的模式匹配引擎（~500 行，简单规则匹配）  
    - `rules/` — 从 Semgrep 社区翻译的 2000 条规则（翻译已知漏洞模式知识）  
    - 在 Verify Agent 中给 LLM 发现的候选漏洞打上"是否匹配已知模式"标签  
    - 不执行文件（不可执行文件，只做纯规则匹配）  

  - **Phase B（定向 taint 引擎，五个 Agent 完成后做）**  
    - `taint_engine.py` — 定向数据流追踪引擎，只回答"LLM 指出的 A→B 路径通不通"  
    - `call_graph.py` — 调用链查询（已有改造复用）  
    - 知识来自 CodeQL 标准库（source/sink/propagation 定义），不抄 Datalog 引擎  
    - 不与 Phase A 共享代码，两个模块完全独立

- Phase A 和 Phase B 是**不同工具**：前者匹配已知模式，后者验证数据流路径。不互相依赖。
- `engine/sast/` 全部用 Python/tree-sitter 写，零外部 CLI 依赖，LLM Agent 里并行调几百次无压力
- Vulnerability Agent 不等待 SAST，SAST 的输出作为 Verify Agent 的输入
- 新增漏洞时，匹配规则和 taint source/sink 都可以后续补上（回归检测）

---

## Xint Code 的顶层架构推断

基于公开信息（RSA 2026 发布、Theori 背景、赛事成绩）推断的 Xint 架构：

```
┌──────────────────────────────────────────────┐
│              "大脑" Brain LLM                  │
│  系统角色：代码审计项目经理                      │
│  输入：当前状态快照 + 所有 Agent 输出摘要        │
│  输出：下一步决策（派谁 + 查什么 + 原因）        │
│  本质：每次决策都是一次 LLM 调用                  │
│       根据已发现的结果动态决定下一步              │
├──────────────────────────────────────────────┤
│                                              │
│  Agent 1     Agent 2    Agent 3    Agent N    │
│  (Mapping)  (Surface)  (DataFlow)  (Vuln)     │
│  (建项目图)  (找入口点)  (追踪数据流) (发现漏洞)  │
│                                              │
│  每个 Agent 也是 LLM 调用，但 prompt 聚焦单一职责  │
│  Agent 之间无依赖时可并行执行                    │
│                                              │
│  每个 Agent 可调用底层确定性工具:                 │
│  query_ast() / taint_trace() / call_graph()   │
│  grep() / read_file() / list_files()           │
│  这些是确定性代码，不是 LLM                      │
└──────────────────────────────────────────────┘
```

## 核心思路

### 大脑不是状态机表，而是 LLM 决策者

- 不是 `if state == A → do B` 的硬编码转移
- 每次给 LLM 当前状态快照 + Agent 工具箱，让 LLM 决定下一步
- 因为漏洞挖掘是探索性问题，硬编码注定跟不上实际情况

### 多 Agent 并行

- 建图（Mapping）→ 找入口（Surface）有依赖关系，必须串行
- 之后：每个入口点追踪数据流、每个数据流路径查漏洞、每个候选漏洞验证
  — **全是独立的，可以并行**

### Agent 是"瘦封装"

- 每个 Agent = 一段 system prompt + 可调用的工具列表
- 同一个 LLM provider 可以服务不同 Agent（换 prompt 就行）
- Agent 没有状态，状态全在大脑那里

### 确定性工具层

- AST 解析、taint 追踪、call graph、grep、文件读取
- 这些是传统代码，供 Agent 调用
- Agent 不应该直接用 LLM 读文件，应该通过工具层做结构化查询

---

## 文件结构规划

```
agies/
├── engine/                    # ★ 新增：状态机引擎
│   ├── __init__.py
│   ├── brain.py               # 大脑 LLM 决策循环
│   ├── state.py               # 项目分析状态数据结构
│   ├── runner.py              # 并行 Agent 执行器
│   ├── context.py             # 上下文管理（各 Agent 结果摘要 + 压缩）
│   └── agents/                # Agent 定义
│       ├── __init__.py
│       ├── base.py            # Agent 基类
│       ├── mapping.py         # 项目建图 Agent
│       ├── attack_surface.py  # 攻击面识别 Agent
│       ├── dataflow.py        # 数据流追踪 Agent
│       ├── vulnerability.py   # 漏洞发现 Agent
│       └── report.py          # 报告生成 Agent
│
├── analyzer/                  # 已有，无需大改
│   ├── parser.py / parser_java.py / parser_js.py
│   ├── call_graph.py
│   ├── taint.py / taint_java.py / taint_js.py
│   └── ...
│   → 改造为 Agent 可调用的工具接口
│
├── verification/              # 已有，成为验证子系统的工具层
│   ├── pipeline.py
│   ├── attacker_control.py
│   ├── exploitability.py
│   └── ...
│   → 成为 Vulnerability Agent / Verify Agent 的工具
│
├── core/                      # 已有，需要重构
│   ├── orchestrator.py        # 从线性流水线 → 调用 engine/
│   └── ...
│
├── cli.py                    # 入口点，改指向新 engine
```

---

## 各 Agent 职责

### Mapping Agent（项目建图）
- **输入**：项目根目录路径
- **输出**：项目结构摘要 + **信任假设列表**（"开发者信任了什么？这为什么可能出问题？"）
- **工具**：`list_directory()`、`read_file()`、`grep_search()`
- **为什么需要**：后续 Agent 需要知道"这个项目是啥"才能做分析
- **关键输出**：`trust_assumptions` —— 每个假设是一条"开发者相信了X，但这样可能不安全"的记录
- **串行依赖**：必须先跑

### Attack Surface Agent（攻击面识别）
- **输入**：项目结构图（含 trust_assumptions）
- **输出**：所有外部可触达的代码入口点列表（HTTP 端点、消息监听、CLI 命令等）
- **附加输出**：**组合攻击面** —— 多个端点组合能造成什么效果（如"上传文件+访问文件=任意文件读取"）
- **工具**：`grep(route_patterns)`、`read_file()`
- **为什么需要**：告诉 Vulnerability Agent "攻击者可以从哪里进来"
- **串行依赖**：依赖 Mapping 结果

### DataFlow Agent（数据流追踪）
- **输入**：一个入口点 + 项目结构
- **输出**：从该入口点到各 sink 的数据流路径
- **工具**：`taint_trace(source, sink_patterns)`、`call_graph.trace_path()`
- **为什么可以并行**：每个入口点独立追踪
- **实例数**：N（N = 入口点数量）

### Vulnerability Agent（漏洞发现） ← ★ 核心 Agent
- **输入**：项目的业务上下文（Mapping 输出）+ 攻击面摘要（Airface 输出）+ 具体代码片段
- **输出**：候选漏洞列表（类型、位置、推理链、攻击路径假设）
- **工具**：`read_file()`、`grep_search()`、`get_taint_flows()`、`call_graph.trace_path()`
- **工作方式**：不是匹配模式，而是理解意图：
  1. 读一段代码，猜开发者原本想做什么
  2. 对比"想的"和"写的"之间的差距
  3. 把差距定性为漏洞
  4. 给出攻击路径假设（"如果我从入口A传入参数B..."）
- **触发方式**：Brain 判断哪些代码片段"值得怀疑"，把可疑片段分发给独立的 Vulnerability Agent 实例深度分析
- **为什么可以并行**：每个可疑片段独立分析
- **实例数**：Brain 决定，取决于有多少值得怀疑的代码

### Verify Agent（漏洞验证）
- **输入**：候选漏洞 + 完整上下文
- **输出**：验证结果（真/假/不确定 + 可利用性评分）
- **工具**：`attacker_control.verify()`、`exploitability.score()`
- **为什么可以并行**：每个候选漏洞独立验证
- **实例数**：N（N = 候选漏洞数）

### Report Agent（报告生成）
- **输入**：所有已验证的漏洞
- **输出**：结构化的安全报告
- **工具**：报告模板、格式化器
- **串行依赖**：所有验证完成后

---

## 大脑的决策循环

```python
# 伪代码：brain.py
class Brain:
    def run(self, project_path: str) -> Report:
        state = ProjectState(project_path)

        while not state.is_complete():
            # 1. 给大脑 LLM 当前状态，让它决定下一步
            decision = self.brain_llm.decide({
                "project_summary": state.summary,
                "completed": state.completed_agents,
                "findings_so_far": state.findings_summary,
                "available_agents": state.get_available_agents(),
            })
            # decision = {
            #   "batch": [
            #     {"agent": "dataflow", "params": {"entry": "/api/users"}},
            #     {"agent": "dataflow", "params": {"entry": "/api/orders"}},
            #   ],
            #   "reason": "发现了 5 个入口点需要追踪",
            # }

            # 2. 并行执行这一批 Agent
            results = parallel_run(decision["batch"])

            # 3. 聚合结果到状态
            state.update(results)

        # 4. 生成报告
        return Report(state)
```

### 决策 prompt 设计

```python
BRAIN_SYSTEM_PROMPT = """你是 agies 代码审计引擎的决策大脑。
你的职责是管理一个代码审计项目的分析流程。

## 可用的 Agent
- mapping: 分析项目结构、语言、框架、依赖
- attack_surface: 发现外部可触达的代码入口点
- dataflow: 追踪从入口点到 sink 的数据流
- vulnerability: 在数据流路径中发现漏洞
- verify: 验证可候选漏洞的真实性和可利用性
- report: 生成最终报告

## 决策规则
1. mapping 必须先执行，且只执行一次
2. attack_surface 依赖 mapping 的结果
3. dataflow 可以在 attack_surface 之后对每个入口点并行执行
4. vulnerability 可以在 dataflow 之后对每条路径并行执行
5. verify 在 vulnerability 之后执行
6. 当发现足够关键的漏洞时，可以提前终止不必要的路径分析
7. 每一步都应该说明"为什么选择这个 Agent"

## 输出格式
返回 JSON: {{
  "batch": [{{"agent": "agent_name", "params": {{...}}}}],
  "reason": "选择理由",
  "signal": "continue" | "stop"
}}
"""
```

---

## 状态数据结构

```python
@dataclass
class ProjectState:
    path: str                           # 项目路径
    summary: str = ""                   # 项目摘要（给大脑看的）
    mapping_result: dict | None = None
    entry_points: list[dict] = field(default_factory=list)
    dataflow_paths: list[dict] = field(default_factory=list)
    candidate_vulnerabilities: list[dict] = field(default_factory=list)
    verified_findings: list[dict] = field(default_factory=list)
    completed_agents: list[str] = field(default_factory=list)
    running_agents: list[str] = field(default_factory=list)
    
    def get_available_agents(self) -> list[str]:
        """根据当前状态，返回可用的 Agent 列表"""
        agents = []
        if not self.mapping_result:
            agents.append("mapping")
        elif not self.entry_points:
            agents.append("attack_surface")
        elif [p for p in self.entry_points if not p.get("analyzed")]:
            agents.append("dataflow")
        elif [d for d in self.dataflow_paths if not d.get("analyzed")]:
            agents.append("vulnerability")
        elif [v for v in self.candidate_vulnerabilities if not v.get("verified")]:
            agents.append("verify")
        if not agents and self.candidate_vulnerabilities:
            agents.append("report")
        return agents
```

---

## 与现有代码的关系

| 现有模块 | 在新架构中的角色 | 改动量 |
|----------|-----------------|--------|
| `analyzer/` (tree-sitter AST + taint) | Agent 的确定性工具层 | 小：封装成可调用 API |
| `verification/` (4+1 层验证) | Verify Agent 的内部步骤 | 小：封装成工具 |
| `strategy/` (优先级 + 分块) | 大脑决策的参考信息 | 小：状态中包含策略结果 |
| `llm/` (provider) | 所有 Agent 和大脑都通过它 | 不改 |
| `core/` | 从线性流水线改为调用 engine/ | 大：核心重构 |
| `cli.py` | 基本不改，入口点 | 几乎不改 |

---

## 实战验证反馈（2026-05-13）

> vulpy (bad) 全流水线测试暴露的问题和修复方向。

### 1. 重复报告问题（核心）

**现象**: 243 条发现，实际唯一漏洞 ~15 类，膨胀约 16 倍。

**根因链（3 层）**:
1. **Agent prompt 不限定范围** — 系统提示说"Analyze the given source code file"，但 `read_file`/`grep_search` 可访问整个 `project_path`。LLM 自然探索全代码，每轮产出 17-20 个**跨文件**漏洞。
2. **测试脚本绕过 Brain** — `test_vuln_real.py` 直接在 for 循环里调 `vuln_agent.run()`，从未经过 `engine/brain.py` 或 `engine/runner.py`。Brain 的并行 dispatch、priority gating、去重机制完全未被使用。
3. **无去重层** — `all_vulns.extend(vulns_found)` 盲目追加。同一 SQLi 在 libuser.py 被报告 39 次，只是标题措辞不同。

**类别分裂**: 同一漏洞在不同轮次被标注为不同 type（`sqli` vs `sql_injection`），进一步加剧膨胀。

**修复方向（三选一或组合）**:
- **A: Per-file scope 限定** — **已否决**。丢失跨文件调用链漏洞，那是 Agent 相比 Linter 的唯一价值。
- **✅ B: 收集后去重** — **已实现**（`state.py`）。三层去重：精确位置匹配 → 邻近行匹配（±3 行）→ 标题相似度（0.70 阈值）。见下面"去重实现细节"。
- **✅ C(变体): Brain dispatch** — **已实现**。测试脚本改为走 Brain.run()，Runner 用 ThreadPoolExecutor 并行执行。原方案"一个 Agent 实例吞全部"被否决（上下文窗口压力），改为 Brain 分发多个实例 + state 层合并。

#### 去重实现细节（2026-05-13）

```
分层策略:
  Tier 1: (file_path, line_number, normalised_type) 精确匹配
  Tier 2: (file_path, normalised_type) + abs(line_diff) ≤ 3
  Tier 3: title 文本相似度 ≥ 0.70 + 同文件同类型

类型规范化映射（VULN_TYPE_ALIASES）:
  sqli → sql_injection    xss → cross_site_scripting
  auth_bypass → authentication_bypass    session_tampering → session_forgery
  csrf → cross_site_request_forgory     ...

效果（vulpy 测试）:
  242 raw → ~15 unique (典型压缩率 ~94%)
```

### 2. 速度瓶颈

**现象**: 772 行代码跑了 ~30 分钟。

**根因**: 速度慢**不是** Brain/Runner 架构设计问题，是测试脚本完全绕过了它们。15 次 LLM 调用串行执行，每次生成 6000-8000 tokens 输出，15 × ~7000 = ~100k 输出 token，全是重复劳动。

**修复方向**:
- **✅ Brain batch dispatch**（优先修复） — **已实现**。Runner 使用 `ThreadPoolExecutor` 并行执行，`--workers N` 控制并发度。理论时间从 30 分钟降到 3-5 分钟。
- **Attack Surface 前置** — 后续实现。让 AttackSurface Agent 识别 3-5 个核心入口点，代替盲目扫描。
- **Incremental output** — 已规划未实现。修改 Prompt 分层输出。
- **Context pruning** — 已规划未实现。减少输入 token。

#### llm_kwargs 传递链路（已实现）

```
VulnerabilityAgent.DEFAULT_LLM_KWARGS = {"max_tokens": 8192}
    → Brain._build_batch() 读取 agent.DEFAULT_LLM_KWARGS
      → AgentCall.llm_kwargs 携带
        → Runner.execute() 传 **call.llm_kwargs
          → agent.run(params, llm, max_tokens=8192)
            → llm.chat_completion(max_tokens=8192)
```

### 3. 输出膨胀

**现象**: `max_tokens=8192` 导致每次调用生成 6-8k tokens 的输出。15 次调用 → 100k+ 输出 tokens，95% 是重复内容。

**根因**: Vulnerability Agent 每次分析都输出完整的 reason/attack_path/suggestion（每个漏洞 200-400 tokens）。17 个漏洞 × 300 tokens = ~5100 tokens，加上 JSON 结构 ≈ 8000 tokens。

**修复方向**:
- **分层输出**: 🔲 已规划未实现。漏洞发现阶段只输出摘要；Verify/Report 阶段补充详情。
- **Output token 预算**: 🔲 已规划未实现。Prompt 限制总输出。
- **Note**: 去重后输出膨胀问题大幅缓解（不再 15 次重复），但每次调用的 6-8k 输出仍可优化。

### 4. JSON 鲁棒性不足

**现象**: `db_init.py` 分析失败，错误 `Expecting ',' delimiter`。

**根因**: LLM 生成的 JSON 偶尔缺少逗号、有多余逗号、或末尾缺少关闭 `}`。Brace-depth counter 能处理嵌套结构和省略 ```，但无法修复格式错误。

**修复方向**:
- **引入 json-repair 库** (`pip install json-repair`): 自动补全括号、修复引号错误、处理尾部逗号。替换 `json.loads()` 为 `json_repair.repair_json()` + `json.loads()`。
- **重试机制**: 第一次 JSON 解析失败时，用修复后的文本重试一次。
- **Prompt 强化**: 在系统提示里加 "Output valid JSON only. No trailing commas. All keys quoted."

### 5. Benchmark 数据污染

**现象**: vulpy 是 600+ stars 的知名教学项目，LLM 训练数据**几乎必然包含它**。~90% 覆盖率可能体现的是 LLM 的记忆力，不是 Agent 的推理能力。

**影响**: 当前测试无法区分"LLM 凭记忆知道这里有漏洞"和"Agent 通过读代码推理出漏洞"。

**修复方向**:
- **私有代码测试**: 在公司或个人的私有仓库上跑，这些代码不在训练数据中。
- **新 CVE 测试**: 选取训练数据截止日期后披露的 CVE，测试 Agent 能否在 0-day 场景下发现漏洞。
- **自包含测试应用**: 创建一个全新的、不公开的漏洞测试应用（不是 vulpy/DVWA 等知名项目）。

---

## 实施路线（状态总览）

| Step | 内容 | 状态 |
|------|------|------|
| 0 | 骨架搭建（Brain+State+Runner+Mapping） | ✅ 已完成 |
| 1 | Vulnerability Agent（核心 LLM Agent） | ✅ 已完成 |
| 2 | Xint 架构重构（sourcer+bulk+verification+index_tools） | ✅ 已完成 |
| 3 | 提示词系统（YAML prompt + PromptManager + context 压缩） | ✅ 已完成 |
| 4 | 任务队列系统（TaskQueue + 超时 + 重试 + 并发限制） | ✅ 已完成 |
| 5 | Attack Surface Agent（HTTP/消息/CLI 入口点发现） | ✅ 已完成 |
| 6 | DataFlow Agent（复杂调用链追踪） | ✅ 已完成 |
| 7 | Verify + Report Agent（漏洞验证 + 报告生成） | ✅ 已完成 |
| 8 | BountyBench 实战验证 + 管道加固 | ✅ 已完成 |
| **9** | **Director 情报聚合层（风险 PageRank + has_path）** | **✅ 已完成** |
| **A** | **情报驱动型调度重构（三段式分发 + Priority Router + Warm Start）** | **✅ 已完成** |
| **P4** | **SAST Phase A — 规则匹配引擎（matcher.py + 6 条 YAML 规则）** | **✅ 已完成** |
| **P5** | **SAST ↔ LLM 反馈闭环（FeedbackStore 持久化）** | **✅ 已完成** |
| **B** | **黑板架构（discovered_logic + prior_knowledge 注入）** | **✅ 已完成** |
| **C** | **上下文注入 + 确定性候选 + SAST 文件保障** | **✅ 已完成** |

### Step 5：提示词系统（Prompt System）✅ 已完成
> 参考 Xint `crs/common/prompts.py` + `prompts/default.yaml` 架构复刻
> 目的：把 prompt 从 Python 硬编码中解放出来，支持模板化、模型级覆写、上下文压缩

#### 5.1 为什么需要

现在所有 Agent 的 system prompt 和工具描述都是 Python 字符串硬编码在代码里的。带来的问题：
- 改 prompt 要改 Python 代码
- 不同模型（DeepSeek vs Claude）只能用同一套 prompt
- 大项目 context 超限时没有恢复机制
- 没有缓存策略导致反复付 prompt token 的花销

Xint 用一套 YAML + Jinja2 的模板系统解决这些问题，我们直接复刻。

#### 5.2 文件结构

```
agies/engine/
├── prompts/
│   ├── default.yaml           ← 所有 Agent 的 prompt 模板
│   ├── deepseek-chat.yaml     ← (可选) DeepSeek 版覆写
│   └── claude-sonnet-4.yaml   ← (可选) Claude 版覆写
├── prompt/
│   ├── __init__.py
│   ├── models.py              ← PromptMapping, AgentPrompts, ToolPrompt (pydantic)
│   └── manager.py             ← PromptManager, BoundAgent, BoundCustom
├── context.py                 ← compress_context() + apply_cache_annotations()
```

#### 5.3 YAML 文件格式（default.yaml）

```yaml
# 顶层三个字段
custom:                          # 全局自定义片段，模板中用 {{ custom.xxx }} 引用
  prompt_intro: |
    You are a security researcher...

  vuln_location_advice: |
    Here are some examples...

tool:                           # 全局工具描述
  read_file:
    summary: Read the source code at {path}.
    params:
      path: The file to read, relative to project root.
    returns: The contents of the file.

  grep_search:
    summary: Search for {pattern} in the project.
    params:
      pattern: The regex pattern to search.
    returns: Matching file:line pairs.

  lookup_function:
    summary: Find a function by name in the FunctionIndex.
    params:
      name: Function name (may include class scope, e.g. Foo::bar).
    returns: Function location and signature.

agents:                        # 各 Agent 的 prompt
  MappingAgent:
    system: |
      {{ custom.prompt_intro }}

      <instructions>
      Analyze the project structure...
      </instructions>
    user: |
      Project path: {{ agent.project_path }}
    tool:                      # 该 Agent 特有工具（与全局 merge）
      list_directory:
        summary: ...

  VulnerabilityAgent:
    system: |
      {{ custom.prompt_intro }}

      <instructions>
      {{ custom.vuln_location_advice }}
      Analyze the given file for vulnerabilities...
      </instructions>
    user: |
      File: {{ agent.key_file_path }}
      Project summary: {{ agent.project_summary }}
      Trust assumptions: {{ agent.trust_assumptions }}
```

**继承规则**（与 Xint 一致）：
1. Agent 的 system/user 优先用自身的，未定义则继承 default
2. Agent 的 tools 和全局 `tool:` 合并——同名 tool 的 description 以 Agent 为准
3. Agent 的 custom 和全局 `custom:` 合并
4. 模型级 YAML 文件（如 `deepseek-chat.yaml`）deep-copy default 后按需覆写，未写的保持 default

#### 5.4 PromptManager 实现

```python
# prompt/models.py

class ToolPrompt(BaseModel):
    summary: str
    params: dict[str, str] = Field(default_factory=dict)
    returns: str | None = None

class AgentPrompts(BaseModel):
    system: str
    user: str
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> "TemplateAgent":
        return TemplateAgent(
            system=jinja2.Template(self.system),
            user=jinja2.Template(self.user),
            tools=self.tools,
            custom={k: jinja2.Template(v) for k, v in self.custom.items()},
        )

class PromptMapping(BaseModel):
    """代表一个 YAML 文件的全部内容"""
    agents: dict[str, AgentPrompts]
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> "TemplateMapping":
        agents = {n: a.compile() for n, a in self.agents.items()}
        custom = {k: jinja2.Template(v) for k, v in self.custom.items()}
        return TemplateMapping(agents=agents, tools=self.tools, custom=custom)
```

```python
# prompt/manager.py

class BoundAgent:
    """绑定到 Agent 实例后的 prompt（可求值）"""
    name: str
    kwargs: dict                       # 含 {"agent": agent_instance}
    agent: TemplateAgent
    custom: BoundCustom

    @property
    def system(self) -> str:
        return self.agent.system.render(self.kwargs)

    @property
    def user(self) -> str:
        return self.agent.user.render(self.kwargs)

class PromptManager:
    """加载 YAML → compile Jinja2 → 按模型选版 → 绑定到 Agent"""

    @classmethod
    def from_path(cls, path: Path) -> Self:
        """读取 prompts/ 目录下所有 *.yaml"""
        models = {}
        for p in path.iterdir():
            if not p.name.endswith(".yaml"):
                continue
            with open(p) as f:
                raw = yaml.safe_load(f)
            name = p.name.removesuffix(".yaml")
            models[name] = PromptMapping.model_validate(raw)
        return cls(models)

    def model(self, name: str) -> TemplateMapping:
        """按模型名称获取版本，没有则用 default"""
        return self.models.get(name, self.default)

    def __init__(self, models: dict[str, PromptMapping]):
        # 1. 弹出 "default"
        # 2. 对每个 model, deepcopy default + merge (agent/tool/custom)
        # 3. compile() 全部转为 TemplateMapping
        ...
```

#### 5.5 Agent 绑定流程

```python
# 在 BaseAgent.__init__() 中（或首次 run 时）
class BaseAgent:
    def _bind_prompts(self, model_name: str):
        mapping = prompt_manager.model(model_name)
        self.prompts = mapping.bind(
            self.__class__.__name__,   # 优先按类名匹配
            "DefaultAgent",            # fallback
            kwargs={"agent": self},
        )

    def _build_tools_api(self) -> list[dict] | None:
        """将 Python 函数 docstring 与 YAML 中的工具描述合并"""
        for name, tool_fn in self.tools.items():
            if tool_fn.__doc__ is not None:
                continue  # 已有 docstring 的优先
            prompt = self.prompts.tools.get(name)
            if prompt:
                # 用 YAML 的 summary + params + returns 拼 docstring
                tool_fn.__doc__ = self._format_tool_doc(prompt, tool_fn)
        return convert_tools(self.tools)
```

#### 5.6 上下文压缩

```python
# context.py

def compress_context(msgs: list[dict]) -> list[dict]:
    """Context 超限时保留头尾，丢弃中间 tool result"""
    pre = msgs[:2]  # system + 第一条 user
    pre.append({"role": "user",
                "content": "[context compressed]"})
    post = msgs[2 * len(msgs) // 3:]  # 最近 1/3
    while post and post[0]["role"] != "assistant":
        post.pop(0)
    if not post:
        raise ValueError("not enough context to preserve")
    return pre + post
```

触发链路（在 LLM provider 层或 Agent.run 循环中）：
```
llm.chat_completion() → 返回上下文超限错误
    → compress_context(msgs) → 替换 msgs
    → 重试 llm.chat_completion()
    → 仍失败 → 降级返回当前结果 / 报错
```

#### 5.7 Prompt 缓存（Anthropic 省钱）

```python
# context.py

def apply_cache_annotations(msgs: list[dict]) -> list[dict]:
    """给 system message 和最后几条 user/tool 消息打缓存标记"""
    cacheable = []
    prev, count = None, 0
    for msg in reversed(msgs):
        if msg["role"] == "system":
            cacheable.append(msg)
        if count < 2 and prev and prev["role"] == "assistant" \
           and msg["role"] in {"user", "tool"}:
            count += 1
            cacheable.append(msg)
        prev = msg
    for msg in cacheable:
        msg["cache_control"] = {"type": "ephemeral"}
    return msgs
```

#### 5.8 迁移步骤

| # | 内容 | 行数 |
|---|------|------|
| 1 | 创建 `prompt/models.py`（pydantic 数据模型） | ~60 |
| 2 | 创建 `prompt/manager.py`（PromptManager + BoundAgent） | ~120 |
| 3 | 创建 `prompts/default.yaml`，将现有 Agent prompt 从 Python 迁出 | ~300 |
| 4 | 修改 `BaseAgent` 绑定 PromptManager | ~30 |
| 5 | 修改 `BaseAgent._build_tools_api()` 从 YAML 合并 tool 描述 | ~40 |
| 6 | 创建 `context.py`（压缩 + 缓存） | ~50 |
| 7 | 将 `apply_cache_annotations()` 挂入 LLM provider | ~20 |
| **合计** | | **~620** |

---

### Step 6：任务队列系统（Task System）✅ 已完成
> 参考 Xint `crs/common/workdb.py` + `crs/common/scheduler.py` 架构复刻
> 目的：给 Brain 加上并发限制、超时控制、失败重试、优先级调度

#### 6.1 为什么需要

现在 Brain 的调度模型是"一个 iteration 构建一个 batch 一起跑完再下一步"：

```python
# 当前问题
batch = self._build_batch(available, state)
results = self.runner.execute(batch)   # 全部跑完才继续
for result in results:
    state.register_result(...)          # 全部完成后才更新状态
```

没有超时 → 一个 Agent 卡死整批都等。没有重试 → 失败直接跳过。没有并发限制 → 100 个 candidate 一次全启动。没有优先级 → 高优漏洞和低优候选人一样待遇。

Xint 的 WorkDB 用 SQLite + 优先级堆 + per-type 并发限制解决了这些问题。我们做一个轻量版（去掉 SQLite 持久化，保留核心调度能力）。

#### 6.2 文件结构

```
agies/engine/
├── task_queue/
│   ├── __init__.py
│   ├── models.py              ← Task, TaskDesc, AgentType, TaskStatus
│   └── queue.py               ← TaskQueue（堆 + 并发控制 + 重试）
├── brain.py                   ← 集成 TaskQueue（修改）
└── runner.py                  ← 支持 timeout（修改）
```

#### 6.3 核心数据结构

```python
# task_queue/models.py

from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Callable

class AgentType(IntEnum):
    MAPPING = auto()
    SOURCER = auto()
    BULK_ANALYSIS = auto()
    ATTACK_SURFACE = auto()
    DATAFLOW = auto()
    VULNERABILITY = auto()
    VERIFICATION = auto()
    VERIFY = auto()
    REPORT = auto()

class TaskStatus(IntEnum):
    SUBMITTED = auto()
    RUNNING = auto()
    DONE = auto()
    FAILED = auto()
    CANCELLED = auto()

@dataclass(order=True)
class Task:
    priority: float             # 越小越优先（主排序）
    submitted_at: float         # FCFS（次排序）
    task_id: int
    agent_type: AgentType
    agent_name: str
    params: dict
    status: TaskStatus = TaskStatus.SUBMITTED
    failure_count: int = 0
    timeout: float = 300        # 秒，0=无超时
    started_at: float = 0

class TaskDesc:
    """每种任务类型的资源配置 — 对标 Xint WorkDesc"""
    max_concurrency: int        # 同时运行数上限
    max_attempts: int           # 失败重试次数
    timeout: float              # 超时（秒）
    retry_delay_base: float = 2.0  # 指数退避基数
```

#### 6.4 TaskQueue 实现

```python
# task_queue/queue.py

import heapq
import time
import threading
from collections import defaultdict

class TaskQueue:
    """线程安全的优先级任务队列"""

    def __init__(self):
        self._queue: list[Task] = []                  # heap
        self._running: dict[int, Task] = {}            # task_id → Task
        self._counts: dict[AgentType, int] = defaultdict(int)  # 类型当前并行数
        self._desc: dict[AgentType, TaskDesc] = {}
        self._next_id = 0
        self._lock = threading.Lock()

    def register(self, agent_type: AgentType, desc: TaskDesc):
        self._desc[agent_type] = desc

    def submit(self, agent_type: AgentType, agent_name: str,
               params: dict, priority: float = 0.5,
               timeout: float = 0) -> int:
        """提交任务，返回 task_id"""
        max_priority = 1.0
        min_priority = 0.0
        with self._lock:
            tid = self._next_id
            self._next_id += 1
            task = Task(
                priority=priority,
                submitted_at=time.monotonic(),
                task_id=tid,
                agent_type=agent_type,
                agent_name=agent_name,
                params=params,
                timeout=timeout or self._desc[agent_type].timeout,
            )
            heapq.heappush(self._queue, task)
            return tid

    def poll(self) -> list[Task]:
        """取出所有当前可运行的任务"""
        now = time.monotonic()
        ready = []
        with self._lock:
            remaining = []
            while self._queue:
                task = heapq.heappop(self._queue)
                if task.status != TaskStatus.SUBMITTED:
                    continue
                desc = self._desc[task.agent_type]
                if self._counts[task.agent_type] >= desc.max_concurrency:
                    remaining.append(task)  # 超限，放回
                    continue
                task.status = TaskStatus.RUNNING
                task.started_at = now
                self._running[task.task_id] = task
                self._counts[task.agent_type] += 1
                ready.append(task)
            for t in remaining:
                heapq.heappush(self._queue, t)
        return ready

    def complete(self, task_id: int):
        with self._lock:
            task = self._running.pop(task_id, None)
            if task:
                task.status = TaskStatus.DONE
                self._counts[task.agent_type] -= 1

    def fail(self, task_id: int) -> bool:
        """返回 True = 需要重试"""
        with self._lock:
            task = self._running.pop(task_id, None)
            if not task:
                return False
            task.failure_count += 1
            desc = self._desc[task.agent_type]
            if task.failure_count >= desc.max_attempts:
                task.status = TaskStatus.FAILED
                self._counts[task.agent_type] -= 1
                return False
            # 指数退避后重新入队
            task.status = TaskStatus.SUBMITTED
            task.started_at = 0
            heapq.heappush(self._queue, task)
            self._counts[task.agent_type] -= 1
            return True

    def cancel(self, task_id: int):
        with self._lock:
            task = self._running.pop(task_id, None)
            if task:
                task.status = TaskStatus.CANCELLED
                self._counts[task.agent_type] -= 1

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def running(self) -> int:
        with self._lock:
            return len(self._running)

    def idle(self) -> bool:
        """没有待处理和运行中的任务"""
        with self._lock:
            return not self._queue and not self._running
```

#### 6.5 Brain 集成模式（两种方案择一）

**方案 A（轻量，推荐）**：保持 Brain 的 iteration 循环不变，只在 Runner 层加超时和重试。

```python
# runner.py 修改
def execute(self, batch: list[AgentCall]) -> list[AgentResult]:
    with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
        future_map = {
            pool.submit(self._run_one, call, i): i
            for i, call in enumerate(batch)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                result = future.result(timeout=call.timeout)  # ← 超时
            except TimeoutError:
                result = AgentResult(error="timeout")
                if call.retry_count < call.max_retries:
                    self._retry(call)  # ← 重试
    ...
```

**方案 B（完整）**：Brain 持续调度，不依赖 iteration。

```python
# brain.py 修改
def run(self, project_path: str) -> ProjectState:
    state = ProjectState(project_path)

    for name, agent in self.agents.items():
        self.task_queue.register(
            AgentType[name.upper()],
            TaskDesc(
                max_concurrency=agent.max_concurrency or 5,
                max_attempts=agent.max_attempts or 3,
                timeout=agent.timeout or 300,
            ),
        )

    while not state.is_complete():
        # 1. 根据 state 提交新任务
        for name in state.get_available_agents():
            if not self._already_submitted(name, state):
                calls = self._build_calls(name, self.agents[name], state)
                for call in calls:
                    self.task_queue.submit(
                        agent_type=AgentType[name.upper()],
                        agent_name=name,
                        params=call.params,
                        priority=self._priority(name),
                        timeout=call.llm_kwargs.get("timeout", 0),
                    )

        # 2. poll 可运行任务
        ready = self.task_queue.poll()
        if not ready:
            if self.task_queue.idle():
                break
            time.sleep(0.1)
            continue

        # 3. 执行批次
        batch = [
            AgentCall(name=t.agent_name,
                      agent=self.agents[t.agent_name],
                      params=t.params)
            for t in ready
        ]
        results = self.runner.execute_with_timeout(batch)

        # 4. 处理结果
        for t, r in zip(ready, results):
            if r.error:
                if self.task_queue.fail(t.task_id):
                    continue  # 已重试入队
            else:
                self.task_queue.complete(t.task_id)
            state.register_result(...)
```

#### 6.6 并发限制配置建议

| Agent 类型 | max_concurrency | max_attempts | timeout | 理由 |
|------------|----------------|-------------|---------|------|
| `mapping` | 1 | 3 | 120s | 读项目结构，一次即可 |
| `sourcer` | 1 | 1 | 60s | 确定性无 LLM，不会失败 |
| `bulk_analysis` | 1 | 2 | 600s | 本身内部 20 线程并行 |
| `attack_surface` | 1 | 3 | 120s | 一次即可 |
| `dataflow` | 5 | 3 | 300s | 每 entry point 独立 |
| `vulnerability` | 8 | 3 | 300s | key_file 多时可并行 |
| `verification` | 10 | 3 | 180s | candidate 多时可并行 |
| `verify` | 10 | 3 | 180s | candidate 多时可并行 |
| `report` | 1 | 3 | 60s | 一次即可 |

#### 6.7 实现步骤

| # | 内容 | 行数 |
|---|------|------|
| 1 | 创建 `task_queue/models.py`（Task, TaskDesc, AgentType） | ~50 |
| 2 | 创建 `task_queue/queue.py`（TaskQueue 堆 + 并发控制 + 重试） | ~130 |
| 3 | 修改 `runner.py` 支持 timeout 参数 | ~20 |
| 4 | 方案 A 或 B 集成到 brain.py（推荐先方案 A） | ~50 |
| **合计** | | **~250** |

---

### Step 7：Attack Surface Agent ✅ 已完成
> 参考 Xint CRS 的 entry-point discovery 思路，但用 LLM Agent 替代确定性路由扫描。
> 目的：给 Vulnerability Agent 提供"攻击者从哪里进来"的上下文，缩小搜索范围。

#### 7.1 为什么需要

Vulnerability Agent 在没有攻击面信息时只能盲目扫描 key_files。Attack Surface Agent 先找出所有外部入口点：
- 让 Vulnerability Agent 聚焦在"攻击者能触达的代码"上
- 发现**组合攻击面**（如"上传文件 + 路径遍历 = 任意文件读取"）
- Priority gating：当 AttackSurface Agent 注册且可用时，Brain 推迟 Vulnerability Agent 的 Mode 1（Mapping 分发），让 AttackSurface 先跑

#### 7.2 实现方式

```
不是确定性路由扫描（AST 解析路由表），而是 LLM Agent 用 grep_search + read_file 探索：
  1. list_directory → 了解项目结构
  2. grep_search(route_patterns) → 找 @RequestMapping, @app.route, router.get()
  3. read_file → 深入 controller/route 文件
  4. 输出结构化 entry_points 列表
```

**为什么用 LLM 而不是 AST**：路由模式的多样性和框架差异使确定性解析需要大量适配。LLM 一次 prompt 能覆盖 Spring Boot、Flask、Express、FastAPI 等所有框架。

#### 7.3 文件结构

```
agies/engine/
├── agents/
│   └── attack_surface.py       ← AttackSurfaceAgent（~120 行）
├── prompts/default.yaml        ← attack_surface 系统提示词已在 YAML 中
```

#### 7.4 核心数据结构

```python
# attack_surface.py — pydantic 输出 schema

class EntryPoint(BaseModel):
    type: str = "http_endpoint"           # http_endpoint | message_listener | cli_command | file_io
    path: str = ""                         # URL 路径（如 /api/users/{id}）
    method: str = ""                       # GET/POST/PUT/DELETE
    file_path: str = ""                    # 源码位置
    line_number: int = 0
    description: str = ""
    parameters: list[EntryPointParameter] = Field(default_factory=list)
    auth_required: bool = True
    combined_attack_surface: list[str] = Field(default_factory=list)  # 组合攻击面描述

class AttackSurfaceOutput(BaseModel):
    entry_points: list[EntryPoint] = Field(default_factory=list)
```

#### 7.5 Brain 集成

Priority gating 逻辑（在 `brain._build_batch()` 或 `brain.run()` 中）：

```python
# 当 AttackSurface Agent 注册且可用时：
#   Vulnerability Mode 1（Mapping 分发）被推迟
#   AttackSurface 先跑 → state.entry_points 填充
#   然后 Vulnerability Agent 使用 entry_points 作为额外上下文
```

在 Runner 中与 Mapping Agent 同优先级（attack_surface max_concurrency=1, max_attempts=3, timeout=120s）。

#### 7.6 迁移步骤

| # | 内容 | 行数 |
|---|------|------|
| 1 | 创建 `engine/agents/attack_surface.py`（Agent + schema + parse） | ~120 |
| 2 | 添加到 `engine/agents/__init__.py` | ~5 |
| 3 | `default.yaml` 添加 attack_surface prompt | ~40 |
| 4 | `brain.py` 注册 AttackSurfaceAgent + Priority gating | ~15 |
| 5 | `auditor.py` 初始化 AttackSurfaceAgent | ~10 |
| **合计** | | **~190** |

---

### 开发路线图（更新版）

```
v2 Pipeline (完成，保留作回退):
Step 0:  骨架搭建（Brain + State + Runner + Mapping）                         ✅ 已完成
Step 1:  Vulnerability Agent（核心 LLM Agent）                               ✅ 已完成
Step 2:  Xint 架构重构（sourcer + bulk + verification + index_tools）         ✅ 已完成
Step 3:  提示词系统（YAML prompt + PromptManager + context 压缩）              ✅ 已完成
Step 4:  任务队列系统（TaskQueue + 超时 + 重试 + 并发限制）                     ✅ 已完成
Step 5:  Attack Surface Agent（HTTP/消息/CLI 入口点发现）                      ✅ 已完成
Step 6:  DataFlow Agent（复杂调用链追踪）                                      ✅ 已完成
Step 7:  Verify + Report Agent（漏洞验证 + 报告生成）                           ✅ 已完成
Step 8:  BountyBench 实战验证 + 管道加固                                      ✅ 已完成
Step 9:  Director 情报聚合层（风险加权 PageRank + has_path 可达性）             ✅ 已完成
Step A:  情报驱动型调度重构（三段式分发 + Priority Router + QuotaMonitor）      ✅ 已完成
Step B:  黑板架构（discovered_logic + record_knowledge + prior_knowledge 注入） ✅ 已完成
Step C:  上下文注入 + 确定性候选 + SAST 文件保障                               ✅ 已完成
Step D/E/F:  mlflow/gunicorn 实战验证 + 批量修复 + 断裂修复                    ✅ 已完成
P4/SAST: Phase A 规则匹配引擎（matcher.py + 6 条 YAML 规则）                   ✅ 已完成
P5:      SAST ↔ LLM 反馈闭环（FeedbackStore 持久化）                           ✅ 已完成

v3 Pipeline (当前阶段, 详见 docs/v3/plan.md):
P0-P8:   目录骨架 → pathfinder/slicer/prompt/Intent/Logic/黑板/编排器          ✅ 已完成
P9:      CLI `--v3` 开关                                                       ✅ 已完成
进阶:    BridgeVerifier + EvidenceChecker + AdversaryAgent + PoCAgent           ✅ 已完成
P1:      CodeQL 数据库创建 + 查询执行                                          🔴 等待 CodeQL CLI
P10:     动态沙箱验证（Docker PoC）                                             🔴 待做
P11:     已知 CVE 项目上验证                                                    🔴 待做
```

---

## Step 9：Director 情报聚合层（2026-05-16）

### 核心思路

将 Aider 的`repomap.py`（热门度 PageRank）改造为"风险加权 PageRank"引擎，替换旧的启发式 `urgency_score`：

```
改造前：热门函数 → 高风险入口
改造后：SAST 信号加权 PageRank + has_path 可达性 → 按危险度排序

SAST 信号注入方式：
  mul = 1.0
  if tag.kind == "signal":
    mul *= SIGNAL_MUL[tag.signal_type]   # sql_sink=80, ...
  if tag in entry_points:
    mul *= 100                            # 入口点 100x

最终分数：
  final = PageRank × 0.3 + attack_path_score × 0.7
```

### 关键设计

- **不可绕过 SAST**：所有文件都跑 PageRank，SAST 信号只影响边权重（`mul` 倍率），不决定谁能进入图
- **has_path 使用交集**：`nx.descendants(entry) ∩ nx.ancestors(sink)` 找出攻击路径上的所有节点，比单条路径更鲁棒
- **纯 Python PageRank**：自实现迭代收敛，无 scipy 依赖
- **库模式保护**：>50 个入口点时按 PageRank 取 top 10 再跑 path 分析
- **增量展开 API**：`get_neighbors(symbol)` 允许递归 Agent 在审计过程中动态展开未预加载的函数
- **三级负信号**：test_code=0.0 完全归零，dead_code=0.1 接近归零，pure_helper=0.3 大幅削弱

---

## Step 8：BountyBench 实战验证（2026-05-15）

### 架构决策 1：DeepSeek 原生 API 优于 Anthropic 代理

**问题**：之前 DeepSeek 模型通过 `ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic` 访问。但 DeepSeek 的 Anthropic 代理不支持 `tool_use`/`tool_result` 格式的 content block，导致所有带 tool calling 的 Agent 调用 400 错误。

**决策**：`DeepSeekProvider` 直接用 OpenAI SDK + 原生 `https://api.deepseek.com`，不做代理转换。

**改动**：
```
agies/llm/deepseek.py
  - 去掉 kwargs.get("base_url") 透传
  - base_url 硬编码为 https://api.deepseek.com
  - api_key 回退检查：DEEPSEEK_API_KEY → ANTHROPIC_API_KEY
```

**原理**：BaseAgent 默认使用 OpenAI 格式构建消息（`assistant.tool_calls` + `tool:tool_call_id`），OpenAIProvider/DeepSeekProvider 透传，AnthropicProvider 需要一次 `_convert_messages()` 转换。原生 DeepSeek API 直接吃 OpenAI 格式，绕过了转换层。

### 架构决策 2：DeepSeek LLM 会忽略 schema 多传参数

**现象**：DeepSeek 在 tool call 中额外传入 `find_callers` schema 没有定义的 `file_glob` 参数，导致 `TypeError`。

**决策**：所有 index_tools 函数加 `**kwargs: Any` 做静默忽略，不依赖 LLM 遵守 schema。

**影响文件**：`agies/tools/index_tools.py` — `lookup_function`、`find_callers`、`find_callees` 全部加 `**kwargs`。

### 架构决策 3：迭代上限 final call 必须禁止 tool calls

**现象**：Agent 在 10 轮迭代后收到"提供最终 JSON"指令，但 DeepSeek 仍发出 tool calls 而不是 JSON，导致 `_parse_output` 返回 "no JSON found"。

**决策**：在 iteration limit handler 中：
1. 剥离消息队列尾部最后一组 `assistant(tool_calls) + tool(result)` 对，切断模型的工具调用惯性
2. 传入 `tools=[]` 明确告知 API 无可用工具

**影响文件**：`agies/engine/agents/base.py` — `_execute_tool_loop()` iteration limit 分支。

### 架构决策 4：新管道 findings 桥接到 legacy 报告系统

**问题**：`_run_new_pipeline()` 的结果存在 `state.verified_findings` 中，但 `run_audit()` 的报告生成读 `get_findings()`（legacy `tools/report.py`），导致报告始终显示 0 finding。

**决策**：在 `_run_new_pipeline()` 末尾，将 triggerable 的 verified findings 写入 `_findings` 全局变量。

**影响文件**：`agies/core/auditor.py` — `_run_new_pipeline()`。

### 当前已知问题（已全部修复）

以下问题已在代码中修复，文档滞后于代码：

| 问题 | 修复方式 | 修复日期 |
|------|---------|----------|
| ~20% VerificationAgent "no JSON found" | 收敛警告 prompt + 迭代上限 final call `tools=[]` + schema 模板 + 文本降级 fallback | 2026-05-15 |
| Mapping/AttackSurface 撞迭代上限 | 同迭代上限修复（剥离工具调用上下文 + JSON 模板强制输出） | 2026-05-15 |
| `grep_search` 空参调用 | Crash Defender（`router.py`: `TOOL_PARAM_RULES` + `validate_tool_call()`） | 2026-05-20 |
| Bulk analysis candidate 数波动 | `_inject_director_candidates()` 确定性注入兜底 | 2026-05-23 |
| function_context 只覆盖卡片函数 | Chunk 内全部函数扫描上下文 | 2026-05-23 |

---

## Step A：情报驱动型调度重构（2026-05-20）

> 核心问题：`state.analysis_cards` 存而不用，Brain `_build_calls()` 无差别分发所有 `key_files`，LLM 预算浪费且无法聚焦高危路径。
> 目标：从"全量暴力扫描" → "情报驱动型指挥系统"，在预算有限时自动聚焦高风险路径。

### 核心架构变更

```
重构前：
  Director → analysis_cards(存入state) → Brain → 遍历key_files无差别分发 → LLM Agent

重构后：
  Director → analysis_cards → Brain
                                ├── 高危(hot)   → Vulnerability(precision_hunter, 全量预加载)
                                ├── 中危(warm)  → Vulnerability(quick_scanner, 工具探索)
                                └── 低危(cold)  → SAST 信号记录，不分发 LLM
```

### A.1 三段式弹性分发（替换当前无差别遍历）

用**百分位阈值**替代绝对阈值，解决项目规模差异导致的数值偏差：

```python
def _classify_card(score: float, scores: list[float]) -> str:
    """百分位分类: hot(≥80%) / warm(40-80%) / cold(<40%)"""
    sorted_scores = sorted(scores)
    n = len(sorted_scores)
    p80 = sorted_scores[int(n * 0.8)] if n > 1 else scores[0]
    p40 = sorted_scores[int(n * 0.4)] if n > 1 else scores[0]
    if score >= p80:
        return "hot"
    elif score >= p40:
        return "warm"
    return "cold"
```

三层行为：

| 分类 | 阈值 | LLM 行为 | Context 注入 | max_iterations |
|------|------|---------|-------------|----------------|
| **hot** | top 20% | `precision_hunter` 精确猎杀 | 预加载 `functions_involved` 全量源码 | 10-15（深度） |
| **warm** | 20-60% | `quick_scanner` 快速扫描 | 仅传文件路径，LLM 自行探索 | 3-5（浅度） |
| **cold** | bottom 40% | 不分发 LLM | SAST 信号写入报告尾部 | 0 |

**收益**：将 `key_files` 无差别分发（15 文件×每个 8000 tokens）压缩为 hot 3-4 文件深度分析 + warm 5-8 文件浅扫描。

### A.2 Warm Start（热启动）Context Preloading

**原则**：预加载核心路径源码，保留工具探索权。

```python
def _preload_context(card: EntryAnalysisCard, project_path: str) -> str:
    """构建预加载代码块注入 System Prompt"""
    preloaded = []
    for symbol, location in card.symbol_link_table.items():
        file_path, line_str = location.split(":")
        line = int(line_str)
        # 读取该函数附近 20 行
        code = read_file_range(project_path, file_path, line - 5, line + 15)
        preloaded.append(f"### {symbol} @ {file_path}:{line}\n{code}")
    
    return "\n\n".join([
        "## 预加载上下文（Director 已识别的关键路径）",
        *preloaded,
        "---",
        "注意：以上是核心路径的源码。如果逻辑链延伸到这些函数之外，",
        "请使用 read_file / find_callers / find_callees 进一步探索。"
    ])
```

**System Prompt 追加**：

```
你的角色: precision_hunter（高危） / quick_scanner（中危）

precision_hunter:
- Director 已经为你锁定了关键路径的源码（见上方预加载区域）
- 你的任务是：深入分析这些代码中的逻辑矛盾，理解开发者的意图和实际实现之间的差距
- 如果发现跨预加载区域的调用链，使用工具进一步探索

quick_scanner:
- 这是一个快速扫描任务
- 阅读文件，判断是否有明显的、可直接利用的安全漏洞
- 限制在 3 轮工具调用内，没有明确发现就跳过
```

**收益**：
- 工具调用从 8-15 轮降到 2-5 轮（hot 路径）
- Agent 启动时直接处于代码上下文中，无需先 `list_directory` + `read_file` 建图
- 间接解决 `~20% no JSON found`：工具轮次少了，LLM 在迭代上限前出 JSON 的概率更高

### A.3 新旧流水线统一指挥

Director 输出作为全局调度信号，同时影响新旧两条流水线：

**Sourcer（新流水线）**：Director 告诉 Sourcer 哪些文件可跳过索引
```python
# sourcer/loader.py
def build_index(project_path: str, skip_low_rank: bool = False, analysis_cards: list = None):
    if skip_low_rank and analysis_cards:
        # 只索引 hot + warm 文件（跳过 cold 文件）
        keep_files = {c.file_path for c in analysis_cards if c.final_score >= p40_threshold}
        all_files = [f for f in all_files if f in keep_files]
```

**BulkAnalysis（新流水线 Phase 1）**：将 `final_score` 作为优先级传入并行队列
```python
# analysis/bulk.py
async def analyze_single_functions(index, max_functions=None, priority_map=None):
    # priority_map: function_name → final_score
    # 高优先级函数先分析，Token 耗尽时保留的是 low-priority 未分析项
    sorted_functions = sorted(
        index.functions,
        key=lambda f: priority_map.get(f.name, 0) if priority_map else 1,
        reverse=True,
    )
```

**DataFlow（旧流水线）**：按 entry_point 的 `final_score` 排序分发
```python
# brain.py _build_calls dataflow 分支
# 将 Director 发现的入口点 final_score 附加到 AgentCall 的 priority 字段
```

### A.4 Priority Router（P1 — 预算控制闸门）

新文件 `agies/engine/router.py` — 无状态"流量闸门"，位于 Brain 和 Runner 之间。

**不要 numpy 依赖**，纯 Python 百分位计算：

```python
def _percentile(values: list[float], pct: float) -> float:
    """纯 Python 百分位计算"""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = int(len(sorted_v) * pct / 100)
    return sorted_v[min(idx, len(sorted_v) - 1)]
```

三个子模块：

#### Quota Monitor — Token 熔断器

```python
class QuotaMonitor:
    """实时 Token 预算监控。"""
    
    def __init__(self, budget: float = float("inf")):
        self.budget = budget  # e.g. $5.00
        self.consumed = 0.0
        self._model_cost_per_1k_input = 0.00015    # DeepSeek-chat
        self._model_cost_per_1k_output = 0.0006
    
    def record_usage(self, input_tokens: int, output_tokens: int):
        cost = (input_tokens / 1000 * self._model_cost_per_1k_input +
                output_tokens / 1000 * self._model_cost_per_1k_output)
        self.consumed += cost
    
    def is_budget_exhausted(self) -> bool:
        return self.consumed >= self.budget
    
    def remaining_budget(self) -> float:
        return max(0, self.budget - self.consumed)
```

集成到 `brain.py`：每次 `_handle_result()` 时调用 `quota.record_usage()`，预算耗尽时停止提交新任务。

#### Urgency Evaluator — 动态 max_iterations

```python
def map_iterations(card_class: str, base_iterations: int = 10) -> int:
    """hot=full, warm=limited, cold=0"""
    return {"hot": base_iterations, "warm": 3, "cold": 0}.get(card_class, 0)
```

注入 `AgentCall` 的 `llm_kwargs.max_iterations` 字段，在 `BaseAgent._execute_tool_loop()` 中生效。

#### Crash Defender — 工具调用前置校验

```python
TOOL_PARAM_VALIDATORS = {
    "grep_search": {"pattern": lambda v: isinstance(v, str) and len(v) > 0},
    "read_file": {"file_path": lambda v: isinstance(v, str) and len(v) > 0},
    "find_callers": {"name": lambda v: isinstance(v, str) and len(v) > 0},
    "find_callees": {"name": lambda v: isinstance(v, str) and len(v) > 0},
}

def validate_tool_call(tool_name: str, kwargs: dict) -> str | None:
    """返回 None=合法, str=错误信息"""
    rules = TOOL_PARAM_VALIDATORS.get(tool_name, {})
    for param, validator in rules.items():
        if param in kwargs and not validator(kwargs[param]):
            return f"Tool '{tool_name}': invalid param '{param}' = {kwargs[param]!r}"
    return None
```

**注意**：Crash Defender 在 `tools/search.py` 函数入口执行，不在 Router 层。LLM 在调用工具的瞬间传参，不是在提交任务时。

### A.5 State 层扩展

```python
@dataclass
class ProjectState:
    # 现有字段保持不变，新增以下字段
    
    # Director cards 分类缓存（由 Brain 在 Phase 0 后计算）
    hot_cards: list = field(default_factory=list)      # final_score >= p80
    warm_cards: list = field(default_factory=list)     # p40 <= final_score < p80
    cold_cards: list = field(default_factory=list)     # final_score < p40
    
    # 预算监控
    total_tokens_consumed: int = 0
    token_budget: int = 0  # 0 = 不限
    
    # SAST 弱信号（cold cards 的记录，不分发 LLM）
    silent_signals: list[dict] = field(default_factory=list)
```

### A.6 实施步骤总览

| 优先级 | 步骤 | 组件 | 改动 | 行数 | 测试数 |
|--------|------|------|------|------|--------|
| **P0** | A.1 三段式分发 | `brain.py` | `_build_calls()` 按百分位分类 | ~60 | +10 |
| **P0** | A.2 Warm Start | `agents/base.py` + `brain.py` | Context 预加载注入 | ~40 | +8 |
| **P0** | A.3 动态阈值 | `engine/router.py` | `_percentile()` 纯 Python 实现 | ~15 | +3 |
| **P1** | A.4 Quota Monitor | `engine/router.py` | Token 预算追踪 + 熔断 | ~40 | +5 |
| **P1** | A.4 Urgency Eval | `engine/router.py` + `base.py` | score→max_iterations 映射 | ~25 | +4 |
| **P1** | A.4 Crash Defender | `tools/search.py` | 工具入口参数校验 | ~20 | +5 |
| **P2** | A.4 Router 集成 | `brain.py` | `_handle_result()` 钩入 quota | ~15 | +2 |
| **P3** | Sourcer 联动 | `sourcer/loader.py` | Director 指导文件过滤 | ~30 | +3 |
| **P3** | BulkAnalysis 联动 | `analysis/bulk.py` | priority_map 排序 | ~20 | +3 |
| **P4** | SAST Phase A | `engine/sast/matcher.py` | 规则匹配器 | ~500 | +40 |
| **P5** | 反馈闭环 | `engine/feedback.py` | LLM→SAST 信号增强 | ~200 | +15 |

| **P6** | 黑板架构 | `engine/state.py`, `brain.py`, `tools/` | 跨 Agent 知识共享 | ~250 | +40 |

---

## Step C：上下文注入 + 确定性候选 + SAST 文件保障（2026-05-23）

> 核心问题：BentoML `runner_app.py` 的 `_deserialize_single_param` 始终不是第一名 Candidate。
> 三层根因：① Director 15-card 截断 → ② Sourcer 未全量提取 → ③ 注入过滤器阻塞。
> 修复策略见 PROGRESS.md [P6] 章节。

### 架构决策 1：两通道隔离 — Card 排名不影响 SAST 关键文件提取

**问题**：Director 的 `run(max_cards=15)` 可能截断 runner_app.py 的 card（排 ~#14-16），导致 Sourcer 不对此文件做全量 AST 提取，`_deserialize_single_param` 不出现在 FunctionIndex 中。

**决策**：将"LLM 预算分配"和"Sourcer 提取范围"解耦为两个独立通道：

```
通道 1（预算分配）: Director cards → Brain 三段式分发 → 决定哪些文件给 LLM
通道 2（提取范围）: Director entry_points（含 SAST 提升文件）→ state.director_entry_points
                     → Sourcer full_index_paths 无条件包含
```

- Director 的 SAST 预扫描（`prescan_sinks`）将关键文件自动提升为 entry_points
- 所有 entry_points（无论是否在 top-15 cards 中）都存入 `state.director_entry_points`
- `_build_calls("sourcer")` 将这些路径无条件加入 `full_index_paths`
- 即使 card 被截断，关键文件的函数仍被 tree-sitter 全量提取到 FunctionIndex

**收益**：
- SAST 发现的危险函数不会被 card 排名波动影响
- 函数索引是全量知识库，LLM 分析是预算导向的子集
- 两条通道互不阻塞

### 架构决策 2：确定性候选注入作为 LLM 的安全网

**问题**：Bulk analysis 的 per-function LLM 扫描有 ~5% 输出波动，且跨函数间接调用（pickle.loads 在 Payload 类中，不在 `_deserialize_single_param` 体内）对单函数 LLM 不可见。

**决策**：双层候选生成——LLM 输出 + 确定性 SAST 信号，互为补充：

```
候选列表 = LLM 批量分析输出 ∪ 确定性注入
         (波动 ~5%)      (稳定 100%，不受 LLM 变化影响)
```

确定性注入条件：
1. 文件在 Director cards 中（HTTP 可达，含 `serialization`/`critical_sink` 信号）
2. 函数名通过结构启发式验证（多词或含大写 → 非 repomap 噪音）

**为什么不用 defn_names 过滤**：
- `defn_names` 来自于 `function_index.funcs`——当 Sourcer 没有全量提取时，函数就不在 defn_names 中
- 这是循环依赖：索引不包含 → 不注入 → 验证不覆盖 → 即使修了索引也看不到
- 结构启发式（单词全小写 = 噪音）足够区分项目函数和 repomap 噪音

**为何不在 Sourcer/loader.py 层面解决**：
- 问题不是 tree-sitter 解析失败，而是 `full_index_paths` 参数没包含目标文件
- 修复点在 Brain 的调度逻辑，不在 Sourcer 的解析逻辑

### 架构决策 3：人类可读的威胁情报注入（不要数字，要情报）

**来源**：op.md 用户要求 "不要只是给个数字分数，要给'人类能听懂的威胁情报'"。

**实现**：`function_context` 字典构建在 `brain.py` 的 `_build_calls("bulk_analysis")` 中：

```python
# 之前（纯数字）
priority_map[fn_name] = 1.40  # LLM 只看到一个浮点数，毫无意义

# 之后（人类可读）
function_context[fn_name] = (
    "This function is on a path reachable from an HTTP endpoint (runner_app.py). | "
    "Risk score: 1.40 (PageRank: 0.0023, Attack path: 0.85) | "
    "SAST signals: serialization."
)
```

**注入方式**：在 `SINGLE_FUNCTION_USER` 和 `MULTI_FUNCTION_USER` 模板中添加 `{context}` 占位符，位于函数信息之前。无 context 时渲染为空字符串，不影响模板兼容性。

### 架构决策 4：multi-function chunk 上下文扫描

**问题**：当同一个文件有 ≥2 个函数时，bulk analysis 使用 multi-function chunking。初始实现只从 `fns_list[0]` 查找 context，但 chunk 中可能只有非首函数有 context 匹配。

**决策**：扫描 chunk 内全部函数寻找上下文：

```python
# 之前的
ctx = _lookup_context(fns_list[0])

# 之后的
chunk_ctx = ""
for fn in fns_list:
    chunk_ctx = _lookup_context(fn)
    if chunk_ctx:
        break
```

### 当前关键设计原则

| 原则 | 说明 |
|------|------|
| 两通道隔离 | Card 排名不阻塞文件提取，预算和索引解耦 |
| 双保险候选 | LLM 输出 + 确定性信号，任一通道不丢关键发现 |
| 人类可读 > 数字 | 上下文注入用自然语言描述威胁，不是孤立分数 |
| 结构过滤 > 集合过滤 | 函数名合法性用启发式判断，不依赖 FunctionIndex 存在性 |

> 2026-05-20：P6 核心升级。解决"Agent A 算出的调用链，Agent B 进来时一无所知"的问题。
> 关键设计：不要让 Agent 自己去拼凑跨文件的逻辑链，而是让 Brain 在分发任务时自动把之前 Agent 发现的"相关结论"注入到新 Agent 的上下文中。
> 背景：P5 实现了 get_call_chain_logic（确定性路径折叠），但 Agent 的发现仍然是"用完即丢"——这些宝贵的调用链分析结果没有传递给后续 Agent。

### 核心痛点

```
当前状态：
  Agent A 发现 db_query 可以通过 handle_login → verify_user → db_query 触发
    ↓
  Agent A 输出 verified_finding（结论是"triggerable"）
    ↓
  Agent B 分析 db_query 相关的另一条路径，从零开始
    ↓
  Agent B 不知道 Agent A 已经发现了 debug_mode 绕过认证
```

### 解决方案：黑板架构

在 `ProjectState` 中增加 `discovered_logic: dict[str, str]`，作为一个"全局推导结论池"。区别于 `verified_findings`（只存最终结论，不存推理过程），`discovered_logic` 存的是 Agent 在分析过程中发现的"有意义的事实"——不仅限于漏洞，还包括调用链结构、逻辑分支、权限绕过点等。

```
ProjectState
├── verified_findings: list[dict]        # 最终漏洞结论（只增不减）
├── discovered_logic: dict[str, str]     # 推理过程中发现的事实（key = 函数/文件）
│   ├── "db_query" → "Chain: handle_login → verify_user → db_query. verify_user has check_auth with is_debug bypass"
│   ├── "handle_login" → "Entry point parses request, calls verify_user. No input sanitization at this level."
│   └── "process_data" → "Calls validate_input then write_db. validate_input has SQL escaping [Sanitized]."
│
└── (existing fields...)
```

### B.1 Agent → Blackboard：record_knowledge 工具

Agent 在分析过程中可以调用新工具 `record_knowledge(key, value)`，主动将自己发现的事实写入黑板。Key 是函数名（或文件路径），value 是结论摘要。

```python
# Agent 调用示例（LLM 自行决定何时记录）：
# record_knowledge("db_query", "Path from handle_login: verify_user has debug bypass, then calls db_query with SQL injection risk")
```

**工具设计原则**：
- 写入即持久化：`record_knowledge` 写入的 `(key, value)` 立即进入 `state.discovered_logic`
- 幂等：同一 key 多次写入会 append 新信息（换行分隔），不会丢失旧结论
- 零开销：不消耗 LLM token，纯内存操作

### B.2 Brain → Agent：自动 PRIOR_KNOWLEDGE 注入

当 Brain 准备分发一个 Agent 任务时，在 `_build_calls()` 中做关联搜索：

```
匹配逻辑（优先级递减）：
1. 函数名精确匹配 — 候选的函数名
2. 文件路径匹配 — 候选所在的文件
3. 关联函数匹配 — 候选调用的或被调用的函数
```

当匹配到 prior knowledge 时，注入到 Agent params。在 `BaseAgent.run()` 中自动将 `[PRIOR_KNOWLEDGE]` 区块拼接到 System Prompt 开头。

当无相关 prior knowledge 时，不注入任何内容，System Prompt 不受影响。

### B.3 自动证据留存

在两个层面确保证据不丢失：

**层面 1（Agent prompt 引导）**：在 Verification Agent 的 System Prompt 中增加指令：

> "After using get_call_chain_logic, if you discover a meaningful call chain, use record_knowledge to persist it. This helps future agents."

**层面 2（Tool 输出引导）**：`get_call_chain_logic` 工具描述的末尾提示 LLM 用 `record_knowledge` 保存结论。

### B.4 文件变更

| 文件 | 变更 |
|------|------|
| `engine/state.py` | +`discovered_logic: dict[str, str]`，+`record_knowledge` 方法 |
| `engine/brain.py` | `_build_calls()` 中加入 prior_knowledge 关联搜索 + 注入 |
| `engine/agents/base.py` | `run()` 中加入 prior_knowledge 注入到 system prompt |
| `tools/index_tools.py` | +`record_knowledge(key, value)` 工具（使用全局 `_state`） |
| `tools/__init__.py` | 注册 `record_knowledge` |
| `engine/agents/verification_agent.py` | 工具列表 + prompt 增加记录指令 |
| `engine/agents/verify.py` | 工具列表增加 `record_knowledge` |
| `tests/test_blackboard.py` | 新增 P6 测试集 |

### B.5 数据流

```
Agent 分析阶段：
  Agent.run()
    ↓
  调用 get_call_chain_logic("db_query")
    ↓
  返回 dossier
    ↓
  Agent 调用 record_knowledge("db_query", "chain: login→verify→db_query, debug bypass")
    ↓
  ToolResult → 写入 state.discovered_logic["db_query"]

Brain 分发阶段：
  Brain._build_calls("verification", ...)
    ↓
  检查 candidate.function_name 是否在 state.discovered_logic 中
    ↓
  是 → params["prior_knowledge"] = "chain: login→verify→db_query..."
    ↓
  Agent.run()
    ↓
  BaseAgent.run() 检测 prior_knowledge → 注入 system prompt
```

### B.6 与现有系统的关系

- **P5 Feedback 闭环** vs **P6 黑板**：正交。P5 影响下一扫描周期的 PageRank 权重（长期记忆）。P6 影响同一扫描周期内的跨 Agent 推理（短期记忆）。
- **verified_findings** vs **discovered_logic**：前者是最终结论（报告用），后者是推理过程（辅助推理用）。discovered_logic 不在最终报告中出现。
- 两个模块完全独立，互不依赖。

### B.7 验证指标

| 指标 | 期望效果 |
|------|----------|
| Agent 在遇到已知函数时自动获得 prior knowledge | 不重复探索相同调用链 |
| record_knowledge 工具调用成功率 | 100%（纯内存写入，无外部依赖） |
| prior_knowledge 注入不改变 Agent 行为 | 注入空字符串时功能不变 |
| 不误引入无关知识 | 仅精确匹配函数名/文件路径 |
| 回归影响 | 所有现有测试继续通过 |

### 架构决策 5：跨函数调用链对 per-function 扫描完全不可见

**发现背景**：2026-05-26 setuptools v69.5.1（含 CVE-2024-27309 漏洞代码）实战验证。

**问题**：
```
CVE-2024-27309 调用链:
  process_line(url)          ← 攻击者控制 URL
    → _download_url(url, ...)  ← 转发 URL
      → self.opener.open(url)  ← urllib.request.urlopen
        → urlopen(url)         ← 网络请求 sink

问题：没有单个函数同时包含"攻击者输入"和"危险 sink"
      urlopen 本身是正常网络请求，不是危险函数
      危险在于"攻击者可控 URL + 自动下载执行"的链式组合
```

**影响的漏洞类型**：
- 跨函数数据流漏洞（CVE-2024-27309）
- 多层调用链才能触发的复杂逻辑漏洞
- 需要跨函数上下文才能判断危险性的 sink（如 `urlopen`、辅助函数中的 `exec`）

**不影响的场景**：
- 单函数注入（`exec(user_input)`、`subprocess(user_input)`、`pickle.loads(attacker_data)`）— 当前架构已覆盖

**决策方向**：推荐 Hybrid Call Graph + 选择性展开
- tree-sitter 已有调用边提取（`extractor.py` `PYTHON_CALL_QUERY`）
- NetworkX 已有 PageRank 基础设施（Director repomap.py）
- 增量改动：Director 出卡后加一步调用图展开，把调用链上下文注入 bulk prompts
- 不引入新依赖，不改流水线结构

**四个方案详见 `op.md`**。

---

### A.7 验证指标

| 指标 | 当前 | 目标 |
|------|------|------|
| vulpy (772 行) LLM 调用成本 | ~30 分钟 / ~$0.50 | <5 分钟 / <$0.10 |
| zipp (18 文件) LLM 调用次数 | 93-112 (全量 bulk) | 30-50 (hot + warm 聚焦) |
| Verification "no JSON found" | ~20% | <5% |
| 工具调用轮次/Agent (hot) | 8-15 | 2-5 |
| 误丢真实漏洞（false skip） | N/A | 0% |
