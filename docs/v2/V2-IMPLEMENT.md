# v2 架构补齐实现计划（V2-IMPLEMENT）

> 目标：完整实现 ARCHITECTURE-v2.md 中设计的 Director→Brain→链级 Bulk 架构。
> 核心收益：跨函数调用链对 LLM 可见，解决当前"只有单函数可疑才调用 LLM"的问题。

---

## 差距总览

```
v2 设计:                   当前实际:
Director                    Director ✅
  ↓                           ↓
Brain 战略 (1次LLM选入口)    Brain 确定性调度器（无 LLM 选入口）❌
  ↓                           ↓
链级 Bulk (~5次LLM/入口)     逐函数 Bulk (~100次LLM/函数) ❌
  ↓                           ↓
Verification                Verification ✅
```

**必须补的 3 个 gap：**

| # | 组件 | 文件 | 行数 | 依赖 |
|---|------|------|------|------|
| 1 | `expand_call_chain()` — BFS 展开入口调用链 | `director/aggregator.py` | ~60 | FunctionIndex |
| 2 | 链级 prompt 模板 | `analysis/prompts.py` | ~60 | — |
| 3 | `analyze_entry_chains()` — 链级 Bulk 入口 | `analysis/bulk.py` | ~150 | #1, #2 |
| 4 | Brain 分发接入 | `brain.py` | ~50 | #3 |
| **合计** | | | **~320** | |

**不做（现阶段）：**
- Brain 战略 LLM 决策 `_brain_strategy()` — 优化项，非核心。当前 hot/warm/cold 百分位分类已提供等价功能
- 链级 Verification — Verification Agent 已有 tool loop，链上下文在 CandidateFinding 中携带

---

## Gap 1: expand_call_chain() — BFS 展开调用链

### 位置
`agies/engine/director/aggregator.py` 末尾新增

### 功能
从入口函数名出发，BFS 遍历 FunctionIndex 的 call graph，收集整条调用链上所有函数及其源码。

### 为什么不在 Director 阶段做
Director 运行时 FunctionIndex 尚未构建（Sourcer 在 Director 之后运行）。所以这个函数在 Brain 分发 bulk_analysis 时调用，此时 `state.function_index` 已可用。

### 伪代码

```python
def expand_call_chain(
    entry_func_name: str,
    function_index: FunctionIndex,
    max_depth: int = 8,
    max_nodes: int = 30,
) -> list[tuple[str, SourceFunction, int]]:
    """BFS 从 entry 向下展开调用链，返回 (函数名, SourceFunction, 深度) 列表。

    使用 FunctionIndex 的 call graph（反向索引：callee → {callers}），
    通过 _get_direct_callees() 正向遍历。

    返回顺序：入口→深度1→深度2→...
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(entry_func_name, 0)])
    chain: list[tuple[str, SourceFunction, int]] = []

    while queue and len(chain) < max_nodes:
        name, depth = queue.popleft()
        if name in visited or depth > max_depth:
            continue
        visited.add(name)

        # 从 FunctionIndex 获取函数定义
        fns = function_index.lookup(name)
        if fns:
            fn = fns[0]  # 同名的取第一个
            chain.append((name, fn, depth))

        # BFS 下一层：查找此函数调用了谁
        callees = function_index._get_direct_callees(name)
        for callee in sorted(callees):
            if callee not in visited:
                queue.append((callee, depth + 1))

    return chain
```

### EntryAnalysisCard 的 functions_involved 作为种子

Card 已经包含 `functions_involved: list[NodeMetadata]`（入口调用的直接函数列表），可作为 BFS 的起点种子：

```python
# 用 card.functions_involved 中的名字 + card.entry 本身作为 BFS 入口点
seed_names = {card.entry} | {fn.name for fn in card.functions_involved}
```

但 BFS 仍然往下展开——因为 `functions_involved` 只有第一层，更深层的 callee 要由 call graph 遍历发现。

---

## Gap 2: 链级 Prompt 模板

### 位置
`agies/engine/analysis/prompts.py` 末尾新增

### 新增模板

```python
CHAIN_ANALYSIS_SYSTEM = _RED_TEAM_STANCE + """

You are a security-focused code reviewer. You are given an **entry point** and its **entire call chain** — every function that gets executed when this entry is invoked, from the entry point down to the deepest callees.

Your job is to perform a **cross-function security analysis** of the entire call chain.

For each vulnerability you find:
1. **Trace the full data flow** from entry point parameters to the vulnerable sink
2. **Identify which function introduces the taint**, which functions propagate it, and where it reaches a dangerous sink
3. **Assess exploitability** — can an attacker actually reach this sink with controlled input?

Key rules:
- Analyze the CHAIN, not individual functions in isolation
- A function that is safe alone may be dangerous when reachable from a specific entry point
- Report the full attack path: entry → intermediate → sink
- Return the JSON object only"""

CHAIN_ANALYSIS_USER = """{context}

## Entry Point
**{entry_name}** ({entry_type})
File: {entry_file}:{entry_line}

## Call Chain ({chain_length} functions, depth {chain_depth})

{chain_functions}

## Analysis Instructions
- Trace how data flows from the entry point's parameters down the call chain
- Identify dangerous sinks and whether attacker-controlled data can reach them
- Report each vulnerability with its full attack path

Return JSON:
```json
{{
  "vulnerabilities": [
    {{
      "entry": "{entry_name}",
      "type": "...",
      "severity": "critical|high|medium|low",
      "sink_function": "function_name",
      "sink_file": "path/to/file.py",
      "sink_line": 0,
      "attack_path": "entry → func_a → func_b → sink",
      "reason": "...",
      "invariant": "...",
      "confidence": "high|medium|low"
    }}
  ]
}}
```"""

### 与原 prompt 的关键区别

| | 逐函数 prompt | 链级 prompt |
|--|--------------|-------------|
| 输入单位 | 1 个函数 | 入口 + 整个调用链 |
| 跨函数关系 | 不可见 | 源码全部在一起，LLM 可以推演 |
| 输出 | `(sinks, vulns)` per function | 攻击路径：entry→...→sink |
| max_tokens 建议 | 512 | 1024-2048 |

---

## Gap 3: 链级 Bulk 分析入口

### 位置
`agies/engine/analysis/bulk.py` 末尾新增

### 新增函数

```python
def analyze_entry_chains(
    cards: list[EntryAnalysisCard],
    function_index: FunctionIndex,
    llm: Any,
    project_path: str,
    max_workers: int = 5,
    max_functions_per_chain: int = 10,
) -> BulkAnalysisOutput:
    """Run chain-level analysis over Director cards.

    For each card:
    1. Expand the call chain via expand_call_chain() (BFS)
    2. Build a chain prompt with all function sources
    3. Call LLM once per chain
    4. Parse results into CandidateFindings

    Returns BulkAnalysisOutput with candidates from all chains.
    """
```

### 设计细节

1. **链去重** — 不同 card 可能共享中间函数，但每个 card 独立分析
2. **链截断** — `max_functions_per_chain=10`，超过则截断但保留入口和 sink 函数
3. **上下文注入** — 复用现有 `function_context` 逻辑
4. **回退** — FunctionIndex 无 call graph 时，降级为只分析 card 的 `functions_involved`（不展开 BFS）

### 链函数格式化

```python
def _format_chain_for_prompt(
    chain: list[tuple[str, SourceFunction, int]]
) -> str:
    """将调用链格式化为 LLM 可读的文本。"""
    blocks = []
    for name, fn, depth in chain:
        indent = "  " * depth
        arrow = "→ " if depth > 0 else ""
        blocks.append(
            f"{indent}{arrow}Function: {name} (depth={depth})\n"
            f"{indent}  File: {fn.file_path}:{fn.line_start}\n"
            f"{indent}  Signature: {fn.signature}\n"
            f"{indent}  Body:\n"
            f"{indent}  ```\n"
            f"{indent}  {fn.body}\n"
            f"{indent}  ```"
        )
    return "\n\n".join(blocks)
```

---

## Gap 4: Brain 分发接入

### 位置
`agies/engine/brain.py` — `_build_calls("bulk_analysis")` 分支

### 改动

当前 `_build_calls("bulk_analysis")` 只返回一个 AgentCall（逐函数模式）。
新增路径：Director cards 存在时，改为提交**链级分析**。

伪代码：

```python
if name == "bulk_analysis":
    # -- 新增：链级模式 （Director cards + FunctionIndex 可用时） --
    if state.analysis_cards and state.function_index and \
       state.function_index.call_graph:
        return [
            AgentCall(
                agent_name="bulk_analysis",
                agent=agent,
                params={
                    "mode": "chain",  # 新增模式标记
                    "cards": state.analysis_cards[:10],  # top 10 cards
                    "function_index": state.function_index,
                    "project_path": state.project_path,
                },
            )
        ]

    # -- 回退：逐函数模式（原有逻辑） --
    ...
```

### BulkAnalysisAgent 扩展

`bulk_analysis_agent.py` 新增 `mode=="chain"` 路径：

```python
def run(self, params, llm, **llm_kwargs):
    mode = params.get("mode", "single")

    if mode == "chain":
        from agies.engine.analysis.bulk import analyze_entry_chains
        result = analyze_entry_chains(
            cards=params["cards"],
            function_index=params["function_index"],
            llm=llm,
            project_path=params["project_path"],
        )
    else:
        result = analyze_single_functions(...)
```

---

## 实施顺序

```
Day 1:
  Step 1: expand_call_chain()          → aggregator.py  +60行
  Step 2: 链级 prompt 模板              → prompts.py     +60行
  Step 3: _format_chain_for_prompt()   → bulk.py         +30行
          _parse_chain_response()      → bulk.py         +50行
          analyze_entry_chains()        → bulk.py         +70行

Day 2:
  Step 4: Brain 分发 + Agent 适配       → brain.py + bulk_analysis_agent.py  +50行
  Step 5: 验证：setuptools CVE-2024-27309
          agies audit setuptools --new-pipeline
          → 检查是否产出 process_line → _download_url → urlopen 链的 candidate
```

---

## 验证标准

| 检查项 | 通过条件 |
|--------|---------|
| setuptools 跨函数链 | bulk analysis 产出包含 `process_line/_download_url/urlopen` 链的 candidate |
| zipp ReDoS 链 | `glob.match→_compile_pattern→translate_core` 作为单次 LLM 输入 |
| 回归 | 现有 587 测试全部通过 |
| gunicorn 假阳性 | 链级分析不增加 gunicorn 假阳性（12→12 以下） |
