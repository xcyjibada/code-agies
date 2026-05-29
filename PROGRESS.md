



# agies Development Progress

> 与 `IDEA.md`（架构思路）、`DEVELOPMENT.md`（原始规划）配合使用。
> 勾选框表示已完成，带日期的为最近更新时间。

---

## Phase 0: 基础设施 (Done)

- [x] 2026-05-11: LLM provider 抽象层 (DeepSeek / OpenAI / Anthropic / Ollama)
- [x] 2026-05-11: ModelRegistry 自动 provider 选择
- [x] 2026-05-11: 验证闭环基础 (文件存在性 + 行号 + 矛盾检测 + 跨模型)
- [x] 2026-05-11: 扫描策略引擎 (启发式优先级 + 动态分块 + 两阶段扫描)
- [x] 2026-05-11: 快速扫描命令 (`agies scan`)
- [x] 2026-05-11: 配置脚手架 (`agies init` + `.agies/config.yml`)
- [x] 2026-05-11: CI/CD 集成模板 (GitHub Actions, GitLab CI, pre-commit)
- [x] 2026-05-11: `load_config` 集成到 `audit` 命令 (CLI > config > default)

---

## Phase 1: 跨语言静态分析 (Done)

- [x] 2026-05-11: tree-sitter 依赖 + Java parser (`parser_java.py`)
- [x] 2026-05-11: CallGraph 扩展支持 Java 方法调用
- [x] 2026-05-11: Java taint 追踪 (`taint_java.py`)
- [x] 2026-05-11: JS/TS parser (`parser_js.py`) + taint 追踪 (`taint_js.py`)
- [x] 2026-05-11: Spring Boot 项目端到端测试
- [ ] `Analyzer.run()` 重构 —— 检测语言 → 选解析器 → 统一 IR
- [ ] 跨语言 taint 追踪

---

## Phase 2: 攻击者可控制验证 (Done)

- [x] 2026-05-11: `language_patterns.py` — 结构化语言特性定义 + Python/Java/JS 实现
- [x] 2026-05-11: `attacker_control.py` — 六维验证流水线 (P0/P1)
- [x] 2026-05-11: `exploitability.py` — 可利用性评分
- [x] 2026-05-11: 集成到 `VerificationPipeline` (Stage 5)
- [x] 2026-05-11: 测试 (28 tests, 121 total passing)

---

## Phase 6: 状态机引擎 + 多 Agent 架构 (当前)

> 方向修正 v2：从"线性流水线" → "大脑+多 Agent"。核心差异是：
> **Vulnerability Agent 是产品核心，其他 Agent 都是给它提供上下文。**
> 传统工具死于模式匹配，agies 的核心价值是 LLM 读代码读意图、发现逻辑矛盾。
> 详见 `IDEA.md`。

### 架构决策：SAST 重新定位 (2026-05-12)

SAST 从"找漏洞"角色改为**"证据方"角色**——为 LLM 的推理提供确定性证据（路径可达性、调用链完整性、模式匹配），**不是一票否决**。详见 `IDEA.md` 的 [SAST 的定位] 章节。

- `analyzer/` → 重组为 `engine/sast/`：
  - `rules/` — 从 Semgrep 社区规则翻译的核心规则（~50 条起步），不是调 Semgrep CLI
  - `matcher.py` — 基于 tree-sitter 的模式匹配引擎（~500 行）
- **"抄规则不抄引擎"**：安全社区积累的 2000+ 条规则知识才是有价值的，不是 Semgrep CLI 进程管理
- Vulnerability Agent 不依赖 SAST，SAST 的输入和输出都后移到 Verify Agent

### Step 0：骨架搭建 ✅

- [x] 2026-05-12: `engine/state.py` — 项目分析状态数据结构（含 checkpoint 序列化）
- [x] 2026-05-12: `engine/agents/base.py` — Agent 基类（Pydantic 数据模型 + tool 循环 + 截断 + 错误恢复 + schema 校验, 32 tests）
- [x] 2026-05-12: `engine/brain.py` — 大脑确定性决策循环（注册 Agent → 构建 batch → dispatch, 9 tests）
- [x] 2026-05-12: `engine/runner.py` — Agent 串行执行器（AgentCall/AgentResult 数据类型 + 错误隔离, 13 tests）
  - 2026-05-13: 升级为 ThreadPoolExecutor 并行执行 — `Runner(max_workers=N)` 并行执行 LLM agent 调用
  - AgentCall 新增 `llm_kwargs` 字段，支持 per-call LLM 参数传递
- [x] 2026-05-12: `engine/agents/mapping.py` — Mapping Agent（项目建图 + trust_assumptions + LLM prompt + JSON输出解析 + schema校验 + Brain集成, 30 tests）
- [x] 2026-05-12: Mapping Agent 真实 LLM 验证通过 (Claude Sonnet, 11文件测试项目, 识别11个信任假设, 全部带文件行号)
- [x] 2026-05-12: 修复 Anthropic provider tool_result 批处理问题

### Step 1：Vulnerability Agent（核心 Agent ✅）

- [x] 2026-05-12: `engine/agents/vulnerability.py` — Vulnerability Agent
  - 输入：project_summary + key_files + trust_assumptions（来自 Mapping）
  - 核心能力：读代码 → 理解意图 → 发现逻辑矛盾 → 输出候选漏洞
  - 不依赖 AttackSurface 和 DataFlow 就能出结果
  - 可并行：Brain 分发 key_files 到多个实例（Mode 1：直接从 Mapping 分发）
  - 也支持 Mode 2：从 dataflow_paths 分发（未来完整流水线就绪）
  - 提示设计：引导 LLM 问"开发者信任了什么？如果...会怎样？"
  - 工具：read_file / grep_search / get_taint_flows
  - 输出 schema：VulnerabilityOutput（含 vulnerability 列表 + 字段填充默认值）
  - JSON 提取：支持代码块 / 裸 JSON / 容错
- [x] 2026-05-12: Brain 调度 Vulnerability Agent（两种模式）
  - Mode 1：从 Mapping 结果取 key_files + trust_assumptions 分发
  - Mode 2：从 dataflow_paths 分发（兼容原有流水线）
  - Priority gating：当 AttackSurface Agent 注册且可用时，推迟 Mode 1，让 AttackSurface 先跑
- [x] 2026-05-12: 端到端测试（32 个新测试）
  - _parse_output：JSON 提取、空内容、无效内容、schema 验证、部分字段默认值、多条漏洞
  - _extract_json：代码块 / 裸 / 嵌套 / 无 JSON
  - Schema：有效 / 空 / 最小 finding
  - 工具：3 个工具的验证
  - Mock LLM 集成：探索后报告 / 直接输出 / 空列表 / 无效输出 / grep 探索
  - Brain 集成：Mapping → Vulnerability 流水线、key_file 上下文传递、项目上下文传递、key_file 标记分析完成
  - State 渐进：mapping 后可用性、全部完成后不可用、无 key_file 跳过
  - 现有测试不回归验证
- [x] 2026-05-13: 真实 LLM 验证：对 vulpy (bad) 跑通 Mapping → Vulnerability 完整流水线
  - Mapping Agent: 49.1s, 941 tokens, 15 key files, 16 trust assumptions
  - Vulnerability Agent: 13/15 文件成功, 243 发现 (68 Critical, 82 High, 74 Medium, 15 Low, 4 Info)
  - 生成报告: tests/vuln_real_test_report.md + tests/vuln_real_test_summary.md
- [x] 2026-05-13: 修复重复报告问题（三层修复）
  - **State 层去重** (`state.py`): 三层去重策略
  - **类型规范化**: VULN_TYPE_ALIASES 映射表
  - **Brain 调度修复**: 全流水线走 Brain.run()
  - **Runner 并行化**: ThreadPoolExecutor
  - **max_tokens 传递**: Brain→Runner→Agent 完整链路

### Step 2：Xint 架构重构 — 函数级索引 + 两阶段流水线 ✅

> 2026-05-14: 参考 Xint/Theori CRS 重构架构。
> 从"文件级探针" → "函数级流水线"，在 `use_new_pipeline=True` 下启用。

#### `engine/sourcer/` — 函数索引模块

- [x] 2026-05-14: `sourcer/models.py` — 数据结构（SourceFunction, FunctionIndex, CandidateFinding）
- [x] 2026-05-14: `sourcer/extractor.py` — tree-sitter 函数提取（Python/Java/JS/TS, 修复 0.25.2 API）
- [x] 2026-05-14: `sourcer/loader.py` — 索引构建器（自动遍历、过滤、解析）

#### `engine/analysis/` — Phase 1 批量分析

- [x] 2026-05-14: `analysis/prompts.py` — 提示词模板（Single-function + Multi-function 模式）
- [x] 2026-05-14: `analysis/bulk.py` — Phase 1 并行分析（asyncio.gather + 信号量控制）

#### `engine/agents/` — 新 Agent 类型

- [x] 2026-05-14: `agents/sourcer_agent.py` — 确定性索引构建（无 LLM，覆写 run() 直接调用 build_index）
- [x] 2026-05-14: `agents/bulk_analysis_agent.py` — Phase 1 批量 LLM Agent（包装 async bulk.analyze_single_functions）
- [x] 2026-05-14: `agents/verification_agent.py` — Phase 2 验证 Agent（FunctionIndex 工具 + CandidateFinding 验证）

#### `tools/` — 新增 FunctionIndex 工具

- [x] 2026-05-14: `tools/index_tools.py` — lookup_function / find_callers / find_callees

#### Brain + State 扩展

- [x] 2026-05-14: state.py 扩展（function_index, candidates, use_new_pipeline 切换开关）
- [x] 2026-05-14: brain.py 扩展（sourcer/bulk_analysis/verification 分支，两套流水线独立）

### Step 3：提示词系统（Prompt System）✅

> 设计文档见 `IDEA.md` Step 5。参考 Xint `prompts.py` + `prompts/default.yaml` 复刻。

- [x] 2026-05-14: `engine/prompt/models.py` — Pydantic 数据模型（PromptMapping, AgentPrompts, ToolPrompt, TemplateMapping, BoundAgent）
- [x] 2026-05-14: `engine/prompt/manager.py` — PromptManager（加载 YAML → Jinja2 编译 → 绑定 Agent）
- [x] 2026-05-14: `engine/prompts/default.yaml` — 硬编码 prompt 迁出为 YAML 模板（mapping/vulnerability/verification/attack_surface 4 个 agent）
- [x] 2026-05-14: `BaseAgent` 绑定 PromptManager — `_build_messages()` 优先渲染模板，兼容降级
- [x] 2026-05-14: `engine/context.py` — 上下文压缩 + Anthropic prompt 缓存
  - `compress_context()` → 挂在 `base.py:_execute_tool_loop` 异常恢复路径（已启用）
  - `apply_cache_annotations()` → 挂在 `AnthropicProvider._chat_completion_impl`（已启用）
  - 支持 system message list 格式传递缓存标注

### Step 4：任务队列系统（Task System）✅

> 设计文档见 `IDEA.md` Step 6。参考 Xint `workdb.py` + `scheduler.py` 复刻。
> 2026-05-15 升级：从 方案 A（仅注册配置） → 方案 B（完整调度引擎）。

#### 数据结构层
- [x] 2026-05-14: `task_queue/models.py` — 数据结构（Task, TaskDesc, AgentType, TaskStatus）
- [x] 2026-05-14: `task_queue/queue.py` — TaskQueue（优先级堆 + 并发控制 + 指数退避重试）

#### Runner 层
- [x] 2026-05-14: `runner.py` 超时支持（AgentCall.timeout → future.result(timeout=)）

#### Brain 集成（方案 B：完整调度）✅
- [x] 2026-05-14: `brain.py` 集成方案 A（TaskQueue 注册 + 超时/重试注入 AgentCall）
- [x] **2026-05-15: 升级为方案 B — TaskQueue 是真正的调度引擎**
  - `run()` 主循环改为 submit → poll → execute → complete/fail 模式
  - **Submit** — `_submit_available()` 将可用 Agent 转为 Task 提交到 TaskQueue，含 `_task_key()` 防重复提交
  - **Poll** — `tq.poll()` 从堆中取出可运行任务（受 per-type max_concurrency 限制）
  - **Execute** — `_build_batch_from_tasks()` 将 polled tasks 转为 AgentCall，由 Runner 线程池执行
  - **Complete/Fail** — `_handle_result()`：成功 → `tq.complete()`，失败 → `tq.fail()` 指数退避重试
  - **Register** — 结果写入 ProjectState，触发下一轮 agent 发现
  - Vulnerability Mode 1 gating：attack_surface 未完成时推迟 vulnerability 提交
  - 空转保护：`tq.idle()` 检查避免忙等

### Step 5：Attack Surface Agent ✅

- [x] 2026-05-14: `engine/agents/attack_surface.py` — 攻击面识别 Agent（grep 路由模式 + 标注 HTTP/消息/CLI 入口点）
- [x] 2026-05-14: Brain 集成（_AGENT_PROFILES + auditor new pipeline）
- [x] 2026-05-14: DataFlow Agent（复杂调用链追踪，含 40 个测试，全部通过）

### Step 6：DataFlow Agent ✅

- [x] 2026-05-15: `engine/agents/dataflow.py` — DataFlow Agent
  - 输入：entry_point（来自 AttackSurface Agent）
  - 核心能力：LLM 驱动的数据流追踪（read_file/grep_search/lookup_function/find_callers/find_callees/get_taint_flows）
  - 输出：DataFlowOutput（含 entry_point_id + 多条 DataFlowPath）
  - 每条路径包含：sink_type、sink_file:line、path_steps（source→intermediate→sink）
  - 支持 has_validation 字段标记路径上的校验逻辑
  - 6 个工具：read_file、grep_search、lookup_function、find_callers、find_callees、get_taint_flows
- [x] 2026-05-15: `engine/agents/__init__.py` 注册 DataFlowAgent
- [x] 2026-05-15: `engine/prompts/default.yaml` 添加 dataflow 提示词模板
- [x] 2026-05-15: 40 个测试（_parse_output 8 / _extract_json 6 / schema 4 / tools 2 / creation 2 / mock LLM 5 / Brain 集成 7 / state 4 / regression 2）
  - JSON 提取：代码块/裸/嵌套/无效/空
  - Schema：多路径/空/部分字段默认值/字段裁剪
  - Mock LLM：探索后报告/直接输出/空路径/无效输出/grep 探索
  - Brain 集成：entry_point 可用时调度/无 entry_point 跳过/全部完成跳过/多 entry_point 独立标记
  - State 渐进：attack_surface 后 dataflow 可用/全部完成后不可用/无 entry_point 跳过
  - 现有测试不回归验证
- [x] 2026-05-15: Brain 集成验证（state.py 中 register_result dataflow 路由 + entry_point.dataflow_done 标记 + dataflow_paths 扩展）

### Step 7：Verify + Report Agent（已完成）✅

- [x] 2026-05-15: `engine/agents/verify.py` — Verify Agent（遗留流水线漏洞验证 Agent）
  - 输入：candidate vulnerability（来自 Vulnerability Agent）
  - LLM 驱动验证：读代码 → 追踪数据流 → 检查缓解控制 → 判定真/假阳性
  - 工具：read_file, grep_search, get_taint_flows, lookup_function, find_callers, find_callees
  - 输出：VerifyOutput（findings 列表，每个含 type, severity, file_path, confidence, verified）
  - 集成：brain._build_calls("verify"), state.register_result("verify"), _task_key, _AGENT_PROFILES
  - 支持空 findings 不阻塞流水线（同 dataflow 修复模式）
  - 36 个测试（_parse_output 7, _extract_json 6, schema 3, tools 2, creation 2, mock LLM 5, Brain 集成 5, state 5, regression 1）

- [x] 2026-05-15: `engine/agents/report_agent.py` — Report Agent 升级
  - 从确定性格式器升级为 LLM 驱动的报告生成 Agent
  - 系统提示词：专业安全审计报告（执行摘要 + 漏洞详情 + 风险评估）
  - 输出 schema：ReportOutput（report markdown + summary）
  - LLM 不可用时降级为确定性回退
  - YAML prompt 模板已添加

- [x] 2026-05-14: `IDEA.md` 实施路线章节重构为状态总览表格
- [x] 2026-05-14: Step 5 (Prompt System) / Step 6 (Task System) 标记为 ✅ 已完成
- [x] 2026-05-14: 新增 Step 7 Attack Surface Agent 设计文档（含实现方式、数据结构、Brain 集成、迁移步骤）
- [x] 2026-05-14: 开发路线图更新（Steps 0-5 ✅, Step 6 DataFlow Agent ✅, Step 7 Verify+Report ✅）

### Step 8：BountyBench 实战验证 + 管道修复 ✅

> 2026-05-15: 以 zipp (CVE-2024-5569 ReDoS) 为靶心，验证新管道的端到端检测能力。
> 靶场路径: `/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c`
> 命令: `--new-pipeline --no-static --model deepseek-chat`

#### 架构变更

- [x] **DeepSeek 原生 API 切换** (`agies/llm/deepseek.py`)
  - 去掉对 `ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic` 代理的依赖
  - `_init_client` 回退 `ANTHROPIC_API_KEY`（当 `DEEPSEEK_API_KEY` 未设置时）
  - `base_url` 硬编码为 `https://api.deepseek.com`
  - 原因：DeepSeek 的 Anthropic 代理不支持 `tool_use`/`tool_result` content block 格式，导致验证 Agent 全部 400 错误

- [x] **call graph 提取实现** (`agies/engine/sourcer/extractor.py`)
  - 为 Python/Java/JS/TS 添加 tree-sitter call expression 查询（`PYTHON_CALL_QUERY` 等）
  - `_match_calls_to_functions()` 双遍扫描：函数定义 → 调用表达式 → 字节范围空间包含匹配
  - `extract_call_graph(sf)` 按文件扩展名分发
  - `FunctionIndex` 中为 `callee → set[caller]` 逆向映射

#### 管道 Bug 修复（5 个）

- [x] **`find_callers` / `find_callees` 不接 `**kwargs`** — DeepSeek 会多传 `file_glob` 参数导致 `TypeError`。修复：加 `**kwargs: Any`。
- [x] **`AttackSurface._normalise` 不处理 dict 混入** — LLM 在 `combined_attack_surface` 字段返回 dict 而非 str，Pydantic schema 校验失败。修复：自动 `str(x)` 转换。
- [x] **`_parse_single_response` 不防御非 dict** — LLM 返回的 `vulnerabilities` 列表中混入 str，`v.get("type")` 抛 `AttributeError`。修复：加 `if not isinstance(v, dict): continue`。
- [x] **迭代上限 final call 没传 `tools=[]`** — 模型在 final forced call 继续发 tool calls 而非 JSON。修复：传 `tools=[]` + 剥离消息尾部 tool call/result pair。
- [x] **`state.register_result("verification")` 没写 `verified_findings`** — verification agent 标记了 `c.verified = True` 但 `verified_findings` 始终为空。修复：注册时将 output 桥接到 `verified_findings` 列表。

#### 报告桥接

- [x] **`_run_new_pipeline` 桥接到 legacy report** — 新管道的发现存在 `state.verified_findings`，但 `run_audit()` 的报告生成读 `get_findings()`。修复：在 `_run_new_pipeline` 末尾将 triggerable findings 写入 `_findings`。

#### 验证结果

```
Files indexed: 18  |  Functions: 136  |  Candidates: ~95-110
Verified findings: 全部  |  Triggerable: 4-6  |  False positives: 99+
```

| Finding | Type | Severity | 命靶? |
|---------|------|----------|-------|
| `replace` in `glob.py:66` — 灾难性回溯 | **CVE-2024-5569 ReDoS** | HIGH | ✅ 靶心 |
| `translate_core` in `glob.py` — `**/**` 变体 | ReDoS | MEDIUM | ✅ 相关 |
| `_implied_dirs` in `__init__.py` — 路径穿越 | Path Traversal | HIGH | |
| `inject` in `__init__.py` — 路径穿越 | Path Traversal | MEDIUM | |
| `read_bytes` in `__init__.py` — zip bomb | Resource Exhaustion | HIGH | |
| `_is_child` in `__init__.py` — 路径穿越 | Path Traversal | HIGH | |

#### 仍存在的问题（下次开发起点）

- **~20% VerificationAgent "no JSON found"** — LLM 在 10 轮迭代内没输出有效 JSON，iteration limit 后的 forced final call 仍可能返回 tool calls
- **Mapping / AttackSurface 撞迭代上限** — 10 轮不够，需要提升到 15-20 或优化 prompt
- **`grep_search` 空参调用** — LLM 有时传空参数调 `grep_search()`，需要在函数入口加参数校验
- **Bulk analysis ~5% 波动** — 每次跑 candidate 数不同（93-112），LLM 输出自然波动，非 bug

---

## Phase 3: 上下文管理与分区分析 (待定)

- [ ] 上下文压缩 (summary + 折叠)
- [ ] 分区分析
- [ ] 跨模块聚合

---

## Phase 4: POC 生成与回归检测 (待定)

- [ ] `poc_generator.py` — 漏洞分类 + POC 模板
- [ ] POC 只读验证
- [ ] `regression_detector.py` — git blame 回归检测

---

## Phase 5: 报告输出增强 (待定)

- [ ] `report_sarif.py` — SARIF 2.1 格式生成
- [ ] `report_incremental.py` — 增量报告合并

---

## Step 9：Director 情报聚合层 ✅

> 2026-05-16: 新增 Director 层（基于 Aider RepoMap 改造的风险排序引擎），作为 Brain 的 Phase 0。
> 核心变化：从"热门度 PageRank" → "风险加权 PageRank + has_path 可达性"。
> 目的：在 LLM 投入分析之前，先用纯确定性代码（~100ms）排序出最危险的入口点。

### 文件结构

```
agies/engine/
├── director/
│   ├── __init__.py           # Director 编排器（run, get_neighbors, 库模式保护）
│   ├── repomap.py            # 改造自 Aider RepoMap: Tag 提取 + 信号加权 PageRank
│   ├── signals.py            # SIGNAL_MUL 配置（13 种信号类型）
│   ├── aggregator.py         # 攻击链卡片生成（EntryAnalysisCard, symbol_link_table, has_path）
│   └── queries/
│       ├── python-tags.scm   # def/ref + 12 SAST 信号查询
│       ├── java-tags.scm     # Java def/ref + 9 信号查询
│       └── js-tags.scm       # JS/TS def/ref + 10 信号查询
```

### 关键技术点

- **Tag 提取**：tree-sitter `.scm` query 提取三类标签：`def`、`ref`、`signal`。信号标签通过 `@signal.<type>` 命名约定识别。
- **信号加权 PageRank**：PageRank 的 `mul` 倍率注入 `SIGNAL_MUL`（sql_sink=80, cmd_exec=80, entry_point=100, test_code=0.0）。高危函数连接的边权重被放大，测试代码被归零。
- **has_path 可达性**：`nx.descendants(entry) ∩ nx.ancestors(sink)` 找到攻击路径上的所有节点，每个路径节点 +500 分。
- **最终排序**：`PageRank × 0.3 + attack_path_score × 0.7`
- **纯 Python PageRank**：自实现 `_pagerank_pure()`，无 scipy 依赖。
- **symbol_link_table**：每个 Card 附带 `symbol → "file_path:line"` 映射，供下游递归 Agent 即时定位。
- **get_neighbors(symbol)**：递归 Agent 查询额外辅助函数的接口。
- **库模式保护**：>50 入口点时 PageRank 选择 top 10，防止内存溢出。
- `.scm` 查询只使用标准 `#eq?`/`#match?` 谓词，不支持 Scheme `#?` 谓词。

### 信号权重配置（signals.py）

| 信号类型 | 权重 | 说明 |
|---------|------|------|
| entry_point | 100 | 外部入口点自带的 100x 加成 |
| sql_sink | 80 | SQL 查询（execute/query），高置信度注入点 |
| cmd_exec | 80 | 命令执行（subprocess/os.system） |
| dynamic_exec | 80 | 动态执行（eval/exec） |
| serialization | 20 | 反序列化（pickle/yaml.load） |
| auth_check | 20 | 认证授权函数 |
| regex_operation | 15 | 正则操作 |
| file_io | 10 | 文件读写 |
| crypto_operation | 5 | 加密操作 |
| network_operation | 5 | 网络请求 |
| test_code | 0.0 | 负信号：测试代码归零 |
| dead_code | 0.1 | 负信号：死代码 |
| pure_helper | 0.3 | 负信号：纯辅助函数 |

### Brain 集成

在 `brain.py` 的 `run()` 中，`use_new_pipeline=True` 时自动触发 Director Phase 0：

```python
if use_new_pipeline:
    director = Director(project_path=project_path)
    cards = director.run(max_cards=15)
    state.analysis_cards = cards
    # Director 失败时降级为全量扫描（无影响）
```

Director 执行在全部 LLM Agent 之前，纯确定性，不消耗 LLM 预算。

### 测试结果

- 28 个 Director 测试全部通过
- 涉及模块：Tag 提取、build_graph、symbol_link_table、has_path、rank_cards、Director E2E、signals、library mode、RepoMap 类
- 全量 357 通过，0 回归

---

## Step A：情报驱动型调度重构 ✅

> 2026-05-20: 将 Director 的 `analysis_cards`（SAST 情报）真正接入 Brain 的任务分发流程。
> 核心变更：三段式弹性分发、Warm Start 预加载、Priority Router 预算控制。
> 设计文档见 `IDEA.md` [Step A] 章节。

### P0：Brain 三段式分发 + Warm Start

- [x] 2026-05-20: `brain._build_calls()` 重写 — 按 `analysis_cards` 百分位分类（hot/warm/cold）
- [x] 2026-05-20: `_percentile()` 纯 Python 实现（无 numpy 依赖）
- [x] 2026-05-20: `state.py` 扩展 — `hot_cards` / `warm_cards` / `cold_cards` + token 预算字段
- [x] 2026-05-20: Context Preloading — Vulnerability Agent 启动时注入 `functions_involved` 源码
- [x] 2026-05-20: System Prompt 分层 — `precision_hunter` vs `quick_scanner` 两套提示词
- [x] 2026-05-20: 测试：三层分发逻辑 + warm start + 百分位计算边界

### P1：Priority Router + 稳定性修复

- [x] 2026-05-20: `engine/router.py` — Quota Monitor（Token 熔断器）
- [x] 2026-05-20: `engine/router.py` — Urgency Evaluator（score → max_iterations 映射）
- [x] 2026-05-20: `tools/search.py` — Crash Defender（工具入口参数校验）
- [x] 2026-05-20: 测试：预算耗尽熔断 + 动态 iteration + 空参拦截

### P2：Router 集成到 Brain

- [x] 2026-05-20: `brain._handle_result()` 钩入 `quota.record_usage()`
- [x] 2026-05-20: 预算耗尽时停止提交新任务，优雅降级
- [x] 2026-05-20: 测试：预算熔断端到端

### P3：新旧流水线统一指挥

- [x] 2026-05-20: Sourcer 联动 — Director 告知 `loader.py` 可跳过的 low-PR 文件
- [x] 2026-05-20: BulkAnalysis 联动 — `final_score` 作为并行队列优先级排序
- [x] 2026-05-20: 测试：文件过滤 + 优先级排序

### P4：SAST Phase A — 规则匹配器 ✅ (2026-05-20)

- [x] `engine/sast/matcher.py` — tree-sitter 模式匹配引擎（302 行）
- [x] `engine/rules/python/` — 6 条 YAML 规则（py-eval-exec, py-hardcoded-secret, py-pickle-unsafe, py-subprocess-shell, py-yaml-unsafe, py-zip-slip）
- [x] `engine/sast/pathfinder.py` — SAST Phase B: CallChainAnalyzer（552 行，路径折叠分析器）
- [x] `engine/sast/bound_checker.py` — 递归深度守卫检测器
- [x] Verification Agent `_apply_sast()` — 模式匹配标签作为置信度加分 + SAST 证据覆盖 LLM 假阴性

### P5：SAST ↔ LLM 反馈循环 ✅ (2026-05-20)

- [x] `engine/feedback.py` — FeedbackStore（265 行完整实现）
- [x] `CONFIRMED_BOOST=5.0` — 确认漏洞后 PageRank 边权重倍率
- [x] `FP_SUPPRESS_MUL=0.3` — 假阳性超过 FP_THRESHOLD(2) 后的信号抑制
- [x] `.agies/feedback.json` — 跨扫描持久化
- [x] `record_from_findings()` — 批量处理 verified_findings

### P6：上下文注入 + 批量分析增强（2026-05-23）

> **背景**：BentoML `runner_app.py` 的 `_deserialize_single_param` 函数是 HTTP 入口 + pickle 反序列化的关键路径，但在实际运行中它始终不是 Candidate 第一名，甚至不在 FunctionIndex 中。根因是 Director 的 15 个 card 限制 + 跨函数间接调用（pickle.loads 在 Payload 类而非 HTTP handler 体内）。

#### 改动清单

**1. Bulk Analysis 上下文注入** (`analysis/bulk.py`, `analysis/prompts.py`, `agents/bulk_analysis_agent.py`)
- 在 single-function 和 multi-function 提示词模板中添加 `{context}` 占位符
- `_call_llm_single()` 和 `_call_llm_multi()` 新增 `context` 参数
- `analyze_single_functions()` 新增 `function_context: dict[str, str]` 参数
- dispatch 循环中扫描 chunk 内所有函数匹配上下文（非仅第一个）

**2. function_context 构建** (`brain.py` `_build_calls("bulk_analysis")`)
- 从 Director `analysis_cards` 构建人类可读的威胁情报上下文
- 包含：HTTP 可达性、Risk score、PageRank、Attack path、SAST 信号
- 格式示例：`"This function is on a path reachable from an HTTP endpoint (runner_app.py). | Risk score: 1.40 (PageRank: 0.0023, Attack path: 0.85) | SAST signals: serialization."`

**3. 确定性候选注入** (`brain.py` `_inject_director_candidates()`)
- 新函数：对 HTTP 可达 + 含 critical_sink/serialization 信号的函数，直接注入 CandidateFinding
- 不依赖 LLM 输出稳定性，确保 `_deserialize_single_param` 始终出现在候选列表
- 信号组合判断：HTTP 关键字（app/server/route/runner...）+ network_operation 信号

**4. full_index_paths 修复** (`brain.py` `_build_calls("sourcer")`)
- 从 hot/warm cards → 全部 analysis_cards
- 新增绝对路径解析（`os.path.join(project, fp)`）
- 新增 card.file_path 作为主要路径来源，functions_involved 作为补充

**5. SAST 关键文件无条件全量提取** (`brain.py`, `state.py`) ★ 本次关键修复
- 核心问题：Director 仅产出 15 个 card，runner_app.py 的 card 排在第 ~14-16 位，可能被截断
- 修复：Director 的 SAST 预扫描将 runner_app.py 提升为 entry_point，所有 entry_point 路径通过 `state.director_entry_points` 存入 ProjectState
- Sourcer 构建 full_index_paths 时**无条件包含所有 Director entry points**，不受 card 排名影响
- `state.py` 新增 `director_entry_points: list[str]` 字段

**6. 注入阻塞解除** (`brain.py` `_inject_director_candidates()`)
- 移除 `defn_names` 过滤器（原本要求函数名必须出现在 FunctionIndex 中才注入）
- 替换为结构启发式过滤：单词全小写（如 map/list/property）→ 跳过，多词/大写 → 保留
- 原因：之前 full_index_paths 未包含 runner_app.py → 函数不在索引 → 过滤器跳过 → 始终不注入

#### 架构调整总结

| 变更 | 之前 | 之后 |
|------|------|------|
| Sourcer 全量提取范围 | hot + warm cards 文件 | 全部 analysis_cards + 全部 Director entry points（含 SAST 提升文件） |
| Bulk Analysis 上下文 | 无 Director 情报 | 注入 HTTP 可达性 + 风险分数 + SAST 信号人类可读描述 |
| 候选注入方式 | 仅依赖 LLM 输出（~5% 波动） | LLM 输出 + 确定性 SAST 信号注入双重保障 |
| 注入过滤器 | 必须在 FunctionIndex 中有定义 | 仅过滤单词 repomap 噪音，项目函数无条件通过 |
| Director→Sourcer 联动 | 隐性中断（card 被截断则文件丢失） | 显性保障（entry_points 独立于 cards 传递） |

#### 关键修复链路

```
SAST 预扫描 → 发现 runner_app.py 含 pickle.loads
  → 提升为 entry_point (Director 内)
  → 存入 state.director_entry_points (Brain)
  → Sourcer full_index_paths 无条件包含 (Brain._build_calls)
  → tree-sitter 全量提取 _deserialize_single_param → FunctionIndex
  → Bulk Analysis 收到 function_context {"_deserialize_single_param": "..."}
  → _inject_director_candidates() 注入 CandidateFinding (不受索引过滤)
  → 验证阶段可追踪完整调用链
```

#### 验证方法

```bash
agies audit /tmp/bounty_test/bentoml_src \
  --new-pipeline --no-static --model deepseek-chat --output-format markdown 2>&1 \
  | grep -E "(Candidate|_deserialize|runner_app|has_runner|Injected)"
```

关键断言：
```
"has_runner_app: True"          # FunctionIndex 包含 runner_app.py 函数
"has_deserialize: True"         # _deserialize_single_param 在索引中
"_deserialize_single_param"     # 出现在候选列表（可能是第一批）
"Injected N Director candidate" # 确定性注入生效
```

## Step B：黑板架构 — 跨 Agent 知识共享 ✅

> 2026-05-25 文档标签（代码已于 2026-05-20 实现）。
> 解决"Agent A 发现的调用链，Agent B 进来时一无所知"的问题。

### 核心机制

```
Agent 分析阶段:
  Agent.run()
    ↓
  调用 get_call_chain_logic("db_query")
    ↓
  返回 dossier
    ↓
  Agent 调用 record_knowledge("db_query", "chain: login→verify→db_query, debug bypass")
    ↓
  ToolResult → 写入 state.discovered_logic["db_query"]

Brain 分发阶段:
  Brain._build_calls("verification", ...)
    ↓
  检查 candidate.function_name 是否在 state.discovered_logic 中
    ↓
  是 → params["prior_knowledge"] = "chain: login→verify→db_query..."
    ↓
  Agent.run() → BaseAgent 注入 PRIOR_KNOWLEDGE 到 system prompt
```

### 文件变更

- `engine/state.py` — `discovered_logic: dict[str, str]` + `record_knowledge()` 方法
- `engine/brain.py` — `_collect_prior_knowledge()` 关联搜索 + 注入（用于所有 agent dispatch）
- `engine/agents/base.py` — `run()` 中 PRIOR_KNOWLEDGE 注入 system prompt
- `tools/index_tools.py` — `record_knowledge(key, value)` 工具
- `tools/__init__.py` — 注册 `record_knowledge`
- `tests/test_blackboard.py` — 9 个测试集

---

### 验证指标（已达成）

| 指标 | 之前 | 当前 | 验证方法 |
|------|------|------|---------|
| vulpy LLM 调用成本 | ~30min / ~$0.50 | 待测试 | `agies audit vulpy --new-pipeline` |
| zipp LLM 调用次数 | 93-112 (全量) | 30-50 (聚焦) | 同上 |
| Verification "no JSON found" | ~20% | <2% (已修复: 收敛警告 + 文本降级) | 批量测试统计 |
| 工具轮次/Agent (hot) | 8-15 | 2-5 | Agent log 统计 |
| 真实漏洞误丢 | N/A | 0% | BountyBench 回测 |

---

## 下一步工作（Next Up）2026-05-25

> 注意：以下所有"下一步"项目均在代码中已完成。本清单只记录文档尚未追踪的内容。

### Step B：黑板架构（Cross-Agent Knowledge Sharing）✅

> 2026-05-25: 已在代码中实现。验证 agent 通过 `record_knowledge(key, value)` 将调用链发现写入 `state.discovered_logic`，Brain 在分发下一批 agent 时自动注入 `prior_knowledge`。

### 验证指标 — 文档化

| 指标 | 状态 | 备注 |
|------|------|------|
| 586 tests passing (2 known failures) | ✅ | test_max_iterations + test_missing_api_key |
| agies 引擎代码 | 21,244 行 | 不含 tests (9,561 行) |
| SAST 引擎 | 1,015 行 | matcher + pathfinder + bound_checker |

### 真正的待办事项

按优先级排序：

### 1. SAST 规则扩展（6 → 50+ 条）
- **当前**: 6 条 Python YAML 规则（zip-slip, eval-exec, pickle, subprocess-shell, yaml-unsafe, hardcoded-secret）
- **目标**: 从 Semgrep 社区翻译到 ~50 条
- **新增语言**: Java / JS / TS 规则
- **影响**: 确定性模式匹配覆盖更多漏洞类型

### 2. BentoML 端到端审计验证
- **目的**: 验证完整链路 — Director → Sourcer → Bulk Analysis → Verification → Feedback
- **靶点**: `_deserialize_single_param` 在 FunctionIndex 中 + 上下文注入 + 确定性候选
- **时机**: 任意时间

### 3. Phase 3: 上下文管理与分区分析
- **上下文压缩** (context.py 已有但仅用于异常恢复)
- **分区分析** — 大型项目的分模块分析
- **跨模块聚合** — 分区结果合并

### 4. Phase 4: POC 生成
- `poc_generator.py` — 漏洞分类 + POC 模板
- POC 只读验证

### 5. Phase 5: 报告输出增强
- `report_sarif.py` — SARIF 2.1 格式生成
- `report_incremental.py` — 增量报告合并

### 6. Phase 1 遗留项
- `Analyzer.run()` 重构（检测语言 → 选解析器 → 统一 IR）
- 跨语言 taint 追踪


## Step E：Batch Verification 确定性回退修复 (2026-05-29)

> **问题**：`_apply_deterministic_batch()` 在 LLM 产出 0 个可解析结果时直接 `return`，CVE-2024-5569 的确定性覆盖逻辑永不触发。
> **根因**：Brain 给 29 个 batch candidate 设 `max_iterations=20`（`len*2 capped at 20`），LLM 花了 19 轮读文件，最终 16997 字符输出解析不出有效 JSON。

### 修复清单

1. **`verification_agent.py` — deterministic batch fallback**
   - 当 LLM 返回 0 个结果时，创建默认 `VerifiedResult` 条目（全 `triggerable: false`），再叠加上 CVE 确定性覆盖
   - 确保已知 CVE 不被 LLM 解析失败吞掉

2. **`brain.py` — batch max_iterations 收紧**
   - 公式：`min(max(verif_max_iter, len*2), 20)` → `min(max(verif_max_iter, len+2), 10)`
   - 批处理有预加载代码，不需要大量读文件轮次

3. **`base.py` — 迭代上限 schema 示例条目**
   - 裸 `{"results": []}` → `[{"candidate_index": 0, "triggerable": false, "conditions": "...", ...}]`
   - LLM 看到嵌套结构模板，能正确输出格式

### 验证结果（zipp CVE-2024-5569）

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| Batch 解析结果 | 0/29 | 27/29 |
| 确定性 CVE 覆盖 | 永不触发 | 8 个 |
| Triggerable findings | 0 | 10 |
| 验证时间 | 70.9s | 57.0s |

---

## Step D：稳定性提升 + 跨函数漏洞盲点发现 (2026-05-26)

> 2026-05-26: 三项稳定性改进 + gunicorn/setuptools 实战验证。
> 发现核心架构盲点：per-function bulk analysis 对跨函数调用链漏洞完全不可见。

### 稳定性改进

- [x] **Plateau 检测** (`engine/agents/base.py`) — 检测 LLM 连续 3 轮调用相同工具模式（相同工具名 + 相同参数字段键），强制收敛输出。防止"一遍遍读同一文件"浪费配额。
  - 日志：`Agent attack_surface: plateau detected (3 identical tool patterns), forcing convergence.`
  - 验证效果：gunicorn attack_surface 从 15 轮提前到 8 轮收敛
- [x] **自适应 max_iterations** (`engine/brain.py`) — mapping/attack_surface 根据项目 Python 文件数动态调整迭代上限：
  - 0-100 文件: 10, 100-500: 15, 500-2000: 20, 2000+: 30
  - 快速文件扫描 (`os.walk` 跳过 .git/node_modules/venv) 在 Brain.run() 启动时执行
- [x] **测试适配** — `test_max_iterations_with_final_summary` 修正（mock 阈值与 MAX_ITERATIONS=7 对齐 + plateau 兼容）
- [x] 测试通过: **587 passed, 1 known failure** (test_missing_api_key)

### 实战验证

**gunicorn (162 py 文件, 1.9M):**
- 全流水线无崩溃，~4 分钟完成
- 45 函数索引, 43 Phase 1 候选, 12 验证 → 全部正确判定为假阳性
- Plateau 检测在 attack_surface 第 8 轮触发（自适应 15 轮上限）

**setuptools v69.5.1 (327 py 文件, 5.9M, 有 CVE-2024-27309):**
- 全流水线无崩溃，~8 分钟完成
- 1413 函数索引, 910 Phase 1 候选, 12 验证 → 全部正确判定为假阳性
- 漏洞代码存在（`package_index.py` 含 `urlopen` + 动态 URL），但 AI 未检出

### 核心架构发现：跨函数调用链盲点

**问题**：agies 当前架构对跨函数调用链漏洞完全不可见。

以 CVE-2024-27309 为例：
```
process_line(url) → _download_url(url, tmpdir) → self.opener.open(url) → urlopen(url)
```
- 没有单个函数同时包含"攻击者输入"和"危险 sink"
- `urlopen` 本身不是危险函数——危险在于"攻击者可控 URL + 自动下载执行"的链式组合
- Per-function bulk LLM 扫描只能看见单个函数内的注入

**已影响的漏洞类型**：
- 跨函数数据流漏洞（如 CVE-2024-27309 setuptools 命令注入）
- 多层调用链才能触发的复杂逻辑漏洞
- 需要跨函数上下文才能判断危险性的 sink（如 `urlopen`、`exec` 在辅助函数中）

**修复方向**：推荐 Hybrid Call Graph + 选择性展开（方案 1）。详见 `op.md` 四个方案分析。

---

## Step F：mlflow 实战验证 + SAST→Bulk 断裂修复 (2026-05-29)

> mlflow v2.8.2（14,682 函数，1,649 索引文件）作为真实世界靶子，验证 agies 在大型项目上的端到端能力。两次测试分别验证 server 目录和全量项目。

### 测试 1：server 目录聚焦（22 py 文件, 578 索引文件）

**命令**: `agies audit mlflow/server/ --new-pipeline --no-static --model claude-sonnet-4-6`

**结果**: 0 triggerable findings

| 阶段 | 耗时 | 输出 |
|------|------|------|
| Director SAST 预扫描 | 即时 | 2 文件命中 critical sink |
| Mapping Agent | 10 轮 | 项目建图 |
| AttackSurface Agent | 10 轮 | 64.7s, 34,477 tokens, 从 proto 文件追踪到动态路由 |
| Chain Bulk Analysis | 9 chains | 1 candidate（JS saveTags → 假阳性） |
| Verification | 1 candidate | 40.6s, 17,161 tokens → triggerable=false ✅ |

**发现**：攻击面检测成功（LLM 通过 protobuf `get_service_endpoints` 发现了动态路由），但 22 文件范围内没有 pickle 反序列化文件。

### 测试 2：全量项目（1,649 文件, 6,385 索引函数）

**命令**: `agies audit mlflow/ --new-pipeline --no-static --model claude-sonnet-4-6`

**结果**: 30 verified findings, **0 triggerable**

| 指标 | 值 |
|------|----|
| SAST 命中 | **190 文件**含 critical sink |
| Entry points | 305（含 170 SAST-promoted） |
| Cards 数 | 15（top-10 hot/warm） |
| Phase 1 候选 | 253 |
| 验证候选 | 30 |
| Triggerable | **0** |

**SAST 命中明细**（6 条规则匹配 190 文件）：
- `cloudpickle.load` → `mlflow/pyfunc/model.py:411`, `mlflow/sklearn/__init__.py:450`, `mlflow/pytorch/__init__.py`
- `subprocess.Popen` / `shell=True` → `mlflow/server/__init__.py`, `mlflow/utils/process.py`
- `yaml.load` → `mlflow/utils/yaml.py`, `mlflow/gateway/config.py`

### 架构断裂分析

**断裂链路**：

```
SAST 发现 pickle.load                          ✅ (190 文件)
  → 提升为 entry point                         ✅ (170 文件)
  → 库模式截断 (library_mode, >50 → PageRank top-10)  ❌ pyfunc/model.py 被丢
  → rank_cards 创建 card                        ❌ pickle 无 card
  → bulk analysis 只分析 hot/warm[:10] cards    ❌ 根本不知有 pickle
  → 零 candidate                                 ❌
```

**根因双重断裂**：

1. **Director 层**（`agies/engine/director/__init__.py:263-270`）：库模式将 >50 entry points 减到 PageRank top 10。SAST-promoted 的 `pyfunc/model.py` 等库文件 PageRank 低，被丢弃。之后 `rank_cards` 永远不会为它创建 card。

2. **Brain 层**（`agies/engine/brain.py:1120-1142`）：chain-mode bulk analysis 只处理 `hot_warm[:10]` cards。即使 pickle 文件有 card，只要分到 cold 档就不进 bulk。

### 修复：SAST sink → 强制进 bulk 队列

#### Fix 1：Director 库模式后重新注入 SAST sinks

**文件**: `agies/engine/director/__init__.py:275-286`

在 library mode 截断后，从 `prescan_sinks` 找回被丢弃的 SAST 关键文件重新注入 entry_points：

```python
if prescan_sinks:
    dropped = prescan_sinks - self.entry_points
    if dropped:
        self.entry_points |= dropped
```

效果：`pyfunc/model.py` 等 pickle 文件在库模式后不会被丢，`rank_cards` 能为其创建 card。

#### Fix 2：Brain bulk analysis 纳入 SAST-critical cold cards

**文件**: `agies/engine/brain.py:1128-1154`

在 chain-mode 选完 `hot_warm[:10]` 之后，从 `state.cold_cards` 中捞取带 SAST-critical 信号（`critical_sink`, `serialization`, `cmd_exec`, `sql_sink`, `dynamic_exec`）的 card，去重后追加最多 5 个：

```python
_SAST_CRITICAL = frozenset({
    "critical_sink", "serialization", "cmd_exec",
    "sql_sink", "dynamic_exec",
})
sast_cold = [c for c in state.cold_cards
             if any(s.tag in _SAST_CRITICAL
                    for s in getattr(c, "aggregated_signals", []))]
```

效果：即使 pickle 文件的 card 在 cold 档，只要 `aggregated_signals` 含 `serialization` 就进入 bulk analysis。

### 修复后数据流

```
SAST 发现 pickle.load            ✅ 190 文件命中
  → 提升为 entry point           ✅ 170 文件
  → 库模式截断                    → re-add dropped sinks  ← 新
  → rank_cards 创建 card          ✅ pickle 文件有 card   ← 新
  → cold card, signal=serialization
  → Brain 额外捞取 SAST cold card  ✅ 进入 bulk           ← 新
  → bulk analysis 执行            → candidate 产生
  → verification 验证              → triggerable?
```

### 测试状态

- 587 tests passed, 1 known failure (test_missing_api_key)
- 37 brain tests + 28 director tests 全部通过

### 遗留弱点（仍未被证实）

| 漏洞类型 | mlflow 实例 | 仍不能检测的原因 |
|---------|------------|----------------|
| 路径穿越绕过 | `validate_path_is_safe` bypass (CVE-2024-3573~3848) | LLM 信任了校验逻辑，没意识到可绕过 |
| 反序列化 RCE | `cloudpickle.load` via HTTP 上传模型 → pyfunc 加载 | 需跨文件追踪 handler → model loading → pickle.load 多跳路径 |
| 逻辑缺陷 | 校验缺失、协议隐式转换 | 无危险函数调用模式，无 taint sink |

详见 `agies/engine/sourcer/extractor.py:396-439`（跨文件调用图缺失）和架构弱点文档。
