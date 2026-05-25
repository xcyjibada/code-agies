# Brain 与 SAST/LLM 协作架构分析

> 基于 `2026-05-20` 代码库状态的分析文档。
> 核心问题：SAST（Director/repomap）产出信息后如何传递给 LLM，Brain 在其中扮演什么角色，现有 Agent 的完整度和缺失。

---

## 一、SAST 阶段（Director/repomap）— 宁错杀不放过

### 1.1 当前流程

Director 作为 Phase 0，在所有 LLM Agent 之前运行，是**纯确定性代码**（无 LLM 调用）：

```
源码文件列表
    ↓
tree-sitter .scm 查询 (python/java/js-tags.scm)
    ├── def 标签  ── 函数/类/方法定义
    ├── ref 标签  ── 函数/方法调用引用
    └── signal 标签 ── SAST 信号（13 种）
        ├── sql_sink (80x)      cursor.execute(), session.query()
        ├── cmd_exec (80x)      subprocess.run(), os.system()
        ├── dynamic_exec (80x)  eval(), exec()
        ├── serialization (20x) pickle.load(), yaml.load()
        ├── file_io (10x)       open(), os.open()
        ├── regex_operation (15x) re.match(), re.search()
        ├── ... (network, crypto, auth)
        ├── test_code (0.0)     ← 负信号：完全归零
        ├── dead_code (0.1)     ← 负信号：接近归零
        └── pure_helper (0.3)   ← 负信号：大幅削弱
    ↓
信号加权 PageRank (自实现纯 Python)
    └── 边权重 = base_mul × signal_score × sqrt(num_refs)
    └── entry_point 额外 10x personalization boost
    ↓
has_path 可达性分析
    └── nx.descendants(entry) ∩ nx.ancestors(sink)
    └── 路径上每节点 +500 分
    ↓
EntryAnalysisCard 列表（按 final_score 降序）
    ├── entry         入口点标识
    ├── final_score   PageRank × 0.3 + attack_path × 0.7
    ├── functions_involved  路径上所有 NodeMetadata
    ├── symbol_link_table   symbol → "file:line" 查表
    └── aggregated_signals  聚合信号计数
```

### 1.2 "宁错杀不放过"的表现

这套 SAST 的设计哲学确实是"宁错杀不放过"：

1. **信号是乘数，不是过滤器** — `sql_sink=80` 把对应边的权重放大 80 倍，而不是"只保留这些"。**所有文件都进 PageRank 图**，没有文件被跳过。

2. **has_path 用交集** — `descendants(entry) ∩ ancestors(sink)` 找出**所有可能路径上的所有节点**，比单条路径更鲁棒，但也会包含更多"可能不相关"的节点。

3. **负信号不归零，只是削弱** — `dead_code=0.1`、`pure_helper=0.3` 不是直接排除，只是大幅降低权重。

4. **无 sink 时的 fallback** — 当 Director 没找到任何高危信号 sink 时，`sinks = set(G.nodes)` 回退为**所有节点都是潜在 sink**。

### 1.3 打标签（.scm 查询系统）

三种语言的 `.scm` 查询文件定义了标签规则：

| 文件 | 覆盖 | def 查询 | ref 查询 | signal 查询 |
|------|------|----------|----------|-------------|
| `python-tags.scm` | Python/PyW | 函数/类/装饰器 | 调用/方法/import | 12 种信号（含 sql_sink, cmd_exec, dynamic_exec, file_io, regex, network, auth, crypto, serialization） |
| `java-tags.scm` | Java | 类/方法/构造器 | 方法调用/对象创建 | 7 种信号（含 sql_sink, cmd_exec, file_io, network, auth, serialization, dynamic_exec） |
| `js-tags.scm` | JS/TS | 函数/箭头函数/方法/类 | 调用/方法/import | 6 种信号（含 sql_sink, cmd_exec, file_io, network, auth, serialization, dynamic_exec） |

**缺陷**：查询由纯文本 `.scm` 定义，不支持运行时动态调整。要新增信号类型必须改文件 + 重启。

### 1.4 "纠错"机制

当前架构中 SAST 阶段的"纠错"非常有限：

- **负信号削弱**：`test_code=0.0` 可以理解为纠正"测试代码中的函数不应该被 LLM 关注"
- **has_path 验证**：要求 entry→sink **存在有向路径**，不存在的路径不会被加分

但**没有**：
- 跨文件调用链的静态验证（Phase B 定向 taint 引擎未实现）
- 类型推断/数据流验证（只在 legacy analyzer 中有，未接入 Director）
- LLM 发现与 SAST 信号的比对/矫正

---

## 二、Brain 的局限

### 2.1 最大的问题：Director 输出被"存而不用"

`brain.py:152-183` 的 Phase 0：

```python
if use_new_pipeline:
    director = Director(project_path=project_path)
    cards = director.run(max_cards=15)
    state.analysis_cards = cards  # ★ 存进去了
    # 然后就没了！
```

`state.analysis_cards` 在 `state.py` 中定义（第 72 行），但：
- **`get_available_agents()`** 完全不读它（第 82-151 行）
- **`register_result()`** 不消费它（第 153-263 行）
- **`_rebuild_brain_summary()`** 不包含它（第 432-483 行）
- **`_build_calls()`** 不参考它（第 378-544 行）

直接后果：Director 的 `final_score` 排名完全不影响 LLM Agent 的调度优先级。

### 2.2 没有预算分配机制

Brain 对所有 `key_files`、`entry_points`、`candidates` 一视同仁：

```python
# vulnerability Mode 1: 所有 key_file 都分发一个 Agent
for kf in state.key_files:
    if not kf.get("vuln_analyzed"):
        calls.append(AgentCall(params={"key_file_path": kf_path, ...}))

# verification: 所有 candidate 都分发一个 Agent
for idx, c in enumerate(state.candidates):
    if not getattr(c, "verified", False):
        calls.append(AgentCall(params={"candidate_index": idx, ...}))
```

没有"高风险文件优先分析"、"低风险文件跳过"的逻辑。Director 的 `final_score` 排序信息被浪费。

### 2.3 没有反馈循环

Brain 是**单向的前馈调度器**：

```
Director → mapping → agents → report
           ↑
      一次性的
```

没有：
- LLM 发现漏洞后→反向增强 SAST 信号权重（learning loop）
- SAST 指向的文件被 LLM 确认安全后→降低该路径未来优先级
- 多次审计同一项目的增量知识积累

### 2.4 状态机是硬编码的，不是学习的

`get_available_agents()` 是确定性 if-else 链：

```python
if mapping not done → mapping
if use_new_pipeline → sourcer → bulk → verification
if legacy → attack_surface → dataflow → vulnerability → verify
→ report
```

不能根据上下文动态调整 Agent 调度策略（例如"如果 Director 发现 sql_sink 密集，优先派 vulnerability"）。

### 2.5 去重跨 Agent 但不跨类型

三点去重覆盖的是 Vulnerability Agent 的内部重复报告。但：
- 同一漏洞可能被 Mapping → Vulnerability → Verify 三个阶段分别报告
- Director 的信号发现和 LLM Agent 的发现之间没有关联/去重

---

## 三、LLM Agent 做了什么

### 3.1 Mapping Agent

**输入**：`project_path`
**输出**：`project_summary`, `modules`, `key_files`, `trust_assumptions`, `language`, `framework`
**工具**：`list_directory`, `read_file`, `grep_search`
**耗时**：~49s / 941 tokens（vulpy 实测）
**本质**：LLM 读项目结构，理解"这个项目是做什么的"，输出信任假设列表。

### 3.2 AttackSurface Agent

**输入**：`project_path`
**输出**：`entry_points`（HTTP 端点/消息监听/CLI 命令/文件 IO）
**工具**：`grep_search`（路由模式匹配）, `read_file`, `list_directory`
**本质**：LLM grep 路由定义文件，标记每个入口点的类型和参数。**可以和 Director 互补**——Director 基于文件名 heuristics 检测入口点，AttackSurface 基于代码内容检测。

### 3.3 Sourcer Agent（新流水线，无 LLM）

**输入**：`project_path`
**输出**：`FunctionIndex`（函数定义 + 调用关系）
**工具**：无（直接调用 tree-sitter）
**本质**：确定性代码，不调用 LLM。按文件遍历→tree-sitter 解析→提取函数/调用。

### 3.4 BulkAnalysis Agent（新流水线 Phase 1）

**输入**：`FunctionIndex`
**输出**：`CandidateFinding` 列表
**本质**：对每个函数并行调用 LLM，问"这个函数有漏洞吗？"。**过杀阶段**——宁可多报 10 倍不可漏报。

```python
# 对每个函数:
prompt = f"Analyze function {func_name} at {file}:{line} for vulnerabilities..."
response = llm.chat_completion(prompt)
candidates.append(parse_candidates(response))
```

### 3.5 Vulnerability Agent（核心 Agent）

**输入**：Mode 1: `key_file_path` + `trust_assumptions`；Mode 2: `dataflow_path`
**输出**：`VulnerabilityOutput`（漏洞列表）
**工具**：`read_file`, `grep_search`, `get_taint_flows`
**本质**：LLM 深度分析一个文件或一条数据流路径，读代码→理解意图→发现逻辑矛盾→输出候选漏洞。

### 3.6 DataFlow Agent

**输入**：`entry_point`（来自 AttackSurface）
**输出**：`DataFlowOutput`（数据流路径列表）
**工具**：`read_file`, `grep_search`, `lookup_function`, `find_callers`, `find_callees`, `get_taint_flows`
**本质**：LLM 从入口点出发，追踪输入流向哪些 sink。

### 3.7 Verification Agent（新流水线 Phase 2）

**输入**：`CandidateFinding`（来自 BulkAnalysis）
**输出**：`verified_findings`（含 triggerable 标记）
**工具**：`read_file`, `grep_search`, `lookup_function`, `find_callers`, `find_callees`
**本质**：LLM 带工具对每个候选漏洞做深度验证。目前 ~20% 返回 "no JSON found"（迭代上限问题）。

### 3.8 Verify Agent（旧流水线）

**输入**：`candidate_vulnerability`（来自 Vulnerability Agent）
**输出**：`VerifyOutput`（含 verified 标记）
**工具**：同上
**本质**：同 Verification Agent，但处理旧流水线的输出格式。

### 3.9 Report Agent

**输入**：所有 state 中的发现
**输出**：`ReportOutput`（markdown + summary）
**工具**：无（LLM 生成式报告）
**本质**：LLM 读所有发现，写成结构化安全报告。有确定性回退。

---

## 四、从 SAST 到 LLM 的信息流

### 4.1 当前实际路径

```
Director Phase 0
    ↓ analysis_cards（只存储，未被消费）
Mapping Agent
    ↓ key_files + trust_assumptions
Sourcer Agent（新流水线）
    ↓ FunctionIndex
BulkAnalysis Agent（新流水线 Phase 1）
    ↓ CandidateFinding
AttackSurface Agent → DataFlow Agent（旧流水线）
                                          ↓
Vulnerability Agent
    ↓ candidate_vulnerabilities
Verification/Verify Agent
    ↓ verified_findings
Report Agent
```

### 4.2 信息丢失点

1. **Director cards 到 BulkAnalysis**：Director 已经知道哪些文件有 sql_sink、哪条路径可达，但 BulkAnalysis 仍然对所有函数**全量扫描**。

2. **Director cards 到 Vulnerability**：Director 已经排序出最高风险的入口点，但 Vulnerability Agent 接收的 `key_files` 来自 Mapping 的**全量输出**（15 个文件，一视同仁）。

3. **Director cards 到 AttackSurface**：Director 已经检测出一组入口点（基于文件名），AttackSurface Agent 用 LLM 重新发现一遍——**重复劳动**。

---

## 五、还有哪些 Agent 没写

### 5.1 规划中未实现的

| Agent/模块 | 文件 | 状态 | 说明 |
|-----------|------|------|------|
| **SAST Phase B: 定向 taint 引擎** | `engine/sast/taint_engine.py` | ❌ 未实现 | 只回答"LLM 指出的 A→B 路径通不通"，不独立发现漏洞 |
| **SAST Phase B: 调用链查询** | `engine/sast/call_graph.py` | ❌ 未实现 | 已有部分功能在 `sourcer/extractor.py` 中，但未独立成工具 |
| **SAST Phase A: 规则匹配器** | `engine/sast/matcher.py` | ❌ 未实现 | 基于 tree-sitter 的模式匹配引擎，给 Verify Agent 提供证据 |
| **SAST Phase A: 规则库** | `engine/rules/` | ❌ 未实现 | 从 Semgrep 社区翻译的 ~2000 条规则 |
| **上下文管理器** | `engine/context.py` (仅有压缩) | ⚠️ 部分实现 | 有 `compress_context()` 和 `apply_cache_annotations()`，但没有 `ContextManager` 类（分区、摘要、滑动窗口） |
| **分区分析** | 未创建 | ❌ 未实现 | 大项目拆子任务，见 DEVELOPMENT.md Phase 3.2 |
| **POC 生成器** | 未创建 | ❌ 未实现 | 漏洞分类 + POC 模板 + 只读验证 |
| **回归检测器** | 未创建 | ❌ 未实现 | git blame 回归检测 |
| **SARIF 报告生成器** | 未创建 | ❌ 未实现 | SARIF 2.1 格式输，GitHub Code Scanning 集成 |
| **增量报告合并** | 未创建 | ❌ 未实现 | 多次运行结果合并/对比 |

### 5.2 结构上缺失的关键能力

**SAST → LLM 的反馈闭环 Agent**：

```
当前架构：SAST → LLM → 报告 (单向)
缺失能力：LLM → 增强 SAST 规则 → 重跑 SAST → 验证 (闭环)
```

具体来说，缺少这些"粘合剂"：

1. **Priority Router**（未实现）— 读取 Director cards 的 `final_score`，决定哪些 key_file / entry_point / candidate 先进入 LLM 流水线，哪些跳过。应该是一个轻量 Python 函数，不是 LLM Agent。

2. **Signal Refiner**（未实现）— LLM 确认某个漏洞后，反向在 Director 的 `SIGNAL_MUL` 中增强对应信号类型的权重。下次审计同项目时更敏感。

3. **False Positive Reducer**（未实现）— LLM 排除了某个候选后，在 Director 的标签系统中标记对应函数为"已检查安全"，降低其未来优先级。

4. **Cross-Project Learning**（未实现）— 跨项目的漏洞模式积累（从一次审计学到的信号组合推广到下次）。

### 5.3 现有 Agent 的已知缺陷

| Agent | 缺陷 | 严重性 |
|-------|------|--------|
| Verification Agent | ~20% "no JSON found"，迭代上限 10 不够 | 中 |
| Mapping Agent | 偶尔撞迭代上限 | 低 |
| AttackSurface Agent | 偶尔撞迭代上限 | 低 |
| BulkAnalysis | 候选数波动 ~5%（LLM 输出自然变化） | 低 |
| **所有 BaseAgent** | 没有 tool call 参数校验（LLM 传空参数） | 低 |

---

## 六、总结：架构中最需要改的三个点

### 6.1 Director Card Consumer（最高优先级）

Brain 需要从 `state.analysis_cards` 读取信息来：
1. **指导 BulkAnalysis 优先级** — 高风险文件先扫，低风险可跳过
2. **指导 Vulnerability Agent 分派** — 按 `final_score` 排序 `key_files`，设定预算上限
3. **指导 Verification Agent 的验证顺序** — 高危候选先验证

### 6.2 Brain 的预算管理（次优先级）

Brain 需要知道"每个 Agent 应该花多少 token"，根据：
- Director 的 `final_score`
- 项目规模（文件数、函数数）
- 用户指定的 `max_tokens` 预算

而不是现在的"一个 key_file 一个 Agent，不限 token"。

### 6.3 SAST ↔ LLM 反馈循环（远期）

LLM 的发现应该能反向影响 SAST：
- 确认的漏洞 → 增强对应信号权重
- 排除的候选 → 降低对应信号权重
- 新发现的信号模式 → 动态添加 .scm 查询规则

当前架构没有任何反馈机制，SAST 和 LLM 是完全解耦的两段式管道。
