# Theori CRS 架构深度分析

> 分析基于 Theori AIxCC 决赛提交代码（2024.08 - 2025.06）。
> 对比参考：agies 项目架构。

---

## 一、顶层系统架构

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                         Competition API (外部)                                  │
└──────────────┬──────────────────────────────────────┬──────────────────────────┘
               │ REST API                             │ REST API
               ▼                                      ▼
┌─────────────────────────────┐    ┌─────────────────────────────┐
│       Task API Server       │    │       Submitter             │
│  (接收 SARIF 广播 / 任务)    │    │  (提交 POV/Patch/评估)      │
└──────────┬──────────────────┘    └──────────────┬──────────────┘
           │                                      │
           ▼                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                            CRS 事件循环                                     │
│                                                                          │
│  ┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐      │
│  │   TaskDB 轮询   │───▶│  WorkDB 调度引擎 │───▶│   回调分发        │      │
│  │  (每 0.1 秒)    │    │  SQLite 持久化    │    │   25+ WorkType   │      │
│  └─────────────────┘    └───────┬──────────┘    └──────────────────┘      │
│                                 │                                         │
│                  ┌──────────────┼──────────────┐                          │
│                  ▼              ▼              ▼                          │
│          ┌──────────┐  ┌──────────────┐  ┌──────────┐                    │
│          │ 静态分析  │  │  动态分析    │  │ Agent    │                    │
│          │ Infer    │  │  模糊测试    │  │ LLM 编排  │                    │
│          │ AInalyse │  │  Coverage   │  │          │                    │
│          │ SARIF    │  │  BranchFlip │  │          │                    │
│          └──────────┘  └──────────────┘  └──────────┘                    │
│                                 │                                         │
│                                 ▼                                         │
│                     ┌──────────────────────┐                             │
│                     │   ProductsDB          │                             │
│                     │   (漏洞/POV/补丁/包)   │                             │
│                     └──────────────────────┘                             │
└──────────────────────────────────────────────────────────────────────────┘
```

### 核心差异：agies vs CRS

| 维度 | agies | Theori CRS |
|------|-------|-----------|
| **调度引擎** | Brain LLM 决策循环 | 程序化事件循环 + WorkDB |
| **任务队列** | `task_queue/` 内存堆 | WorkDB (SQLite 持久化) |
| **静态分析** | Director PageRank + SAST 规则 | Infer + LLM "ainalysis" |
| **动态分析** | 无 | Fuzzing + Coverage + Branch Flip |
| **代码索引** | 函数级 (tree-sitter) | 文件级 + Infer IR |
| **漏洞验证** | LLM 验证 Agent | POV 生成 + 实际执行 |
| **补丁生成** | 无 | LLM Patch Agent + 构建验证 |
| **去重** | LLM 去重 + 三层哈希 | LLM 去重 + stacktrace 匹配 |
| **Agent 数量** | 11 个 | 12 个 |
| **问题定位** | 审计报告 | 完整 PoV + Patch + SARIF |

---

## 二、WorkDB 任务调度引擎

CRS 的核心是 WorkDB。这不是简单队列，而是有状态的 SQLite 持久化任务调度引擎。

```
                    ┌─────────────────────────────┐
                    │          WorkDB              │
                    │   (SQLite + 内存调度)         │
                    │                              │
                    │  ┌───────────────────────┐   │
                    │  │   jobs 表 (SQLite)    │   │
                    │  │  - id                │   │
                    │  │  - task_id           │   │
                    │  │  - status (SUBMITTED │   │
                    │  │    /RUNNING/DONE/     │   │
                    │  │    FAILED/EXPIRED/    │   │
                    │  │    CANCELLED)         │   │
                    │  │  - worktype          │   │
                    │  │  - priority          │   │
                    │  │  - task_desc (JSONB) │   │
                    │  │  - failure_count     │   │
                    │  │  - expiration        │   │
                    │  └───────────────────────┘   │
                    │                              │
                    │  ┌───────────────────────┐   │
                    │  │  内存调度器            │   │
                    │  │  - per-type 优先级堆   │   │
                    │  │  - per-type 并发限制   │   │
                    │  │  - per-task 批处理     │   │
                    │  │  - 指数退避重试        │   │
                    │  │  - Scheduler 公平调度  │   │
                    │  └───────────────────────┘   │
                    └─────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  WorkType NB  │  │  WorkType B  │  │  WorkType A  │
    │  并发限制: 64 │  │  并发限制: 10 │  │  并发限制: 4  │
    │  超时: ∞     │  │  超时: 2h    │  │  超时: ∞     │
    │  重试: ∞     │  │  重试: 1 次  │  │  重试: 3 次  │
    │  批处理: 500  │  │              │  │              │
    └──────────────┘  └──────────────┘  └──────────────┘
```

### WorkDesc 配置（精选）

```python
WorkType.LAUNCH_TASK:      limit=64,   timeout=∞,    attempts=∞
WorkType.LAUNCH_FUZZERS:   limit=64,   timeout=∞,    attempts=∞
WorkType.ANALYZE_VULN:     limit=1000, timeout=∞,    attempts=3
WorkType.PRODUCE_POV:      limit=50,   timeout=2h,   attempts=3
WorkType.PATCH_VULN:       limit=32,   timeout=2h,   attempts=5
WorkType.FLIP_BRANCH:      limit=10,   timeout=2h,   attempts=1
WorkType.PRE_FLIP_BRANCH:  limit=2000, timeout=2h,   attempts=3
WorkType.PROCESS_COVERAGE: limit=3000, timeout=1h,   attempts=3, batchsize=500
WorkType.TRIAGE_FUZZ_CRASH:limit=500,  timeout=1h,   attempts=3, batchsize=100
```

### Schedule Step 流程

```
schedule_step(tg):
  for each WorkType:
    while not at limit:
      scheduler.schedule()    → 选择下一个要运行的任务
      pop from heap           → 取最高优先级任务
      check expiration        → 过期则标记 EXPIRED
      check cancellation      → 已取消则标记 CANCELLED
      kickoff(tg, callback)   → asyncio.TaskGroup 中启动回调

task_entry(callback):
  指数退避等待 (2^failure_count 秒, 上限 60s)
  执行回调 (带 timeout = min(work_desc.timeout, expires_in))
  成功 → status = DONE
  失败 → failure_count++
    if failure_count >= attempts:
      status = FAILED
    else:
      status = SUBMITTED (重新入队)
```

**核心设计亮点**：
- **SQLite 持久化**：进程重启后从上次中断点恢复，RUNNING → SUBMITTED
- **自增 id**：`itertools.count` + `SELECT max(id)`，高性能无竞争
- **BulkTaskWorker**：PROCESS_COVERAGE 和 TRIAGE_FUZZ_CRASH 用批量处理，30 秒延迟窗口收集最多 500 项
- **Scheduler 公平调度**：每个 task 在每个 WorkType 上有公平调度轮次，防止一个 task 饿死其他 task

---

## 三、任务启动流程

```
Competition API
    │
    ▼
TaskDB (轮询每 0.1 秒)
    │
    ├── get_tasks(after=last_task_id)
    │   └── LAUNCH_TASK ──► launch_task()
    │         │
    │         ├── LAUNCH_TASK_SCOPE  (保持退出栈)
    │         ├── LAUNCH_BUILDS ──► launch_builds()
    │         │     ├── build_bear_tar()
    │         │     ├── init_harness_info()
    │         │     ├── Debug build
    │         │     ├── Coverage build
    │         │     └── ANALYZE_HARNESS (每个 harness)
    │         │           ├── GENERATE_ENCODER
    │         │           ├── GENERATE_DECODER (Python)
    │         │           └── GENERATE_ENCODER (Python)
    │         │
    │         ├── [DeltaTask] ANALYZE_DIFF ──► DiffAgent
    │         │
    │         ├── [FullTask] LAUNCH_INFER ──► Infer 静态分析
    │         │     └── Infer 报告 → SCORE_VULN → ANALYZE_VULN
    │         │
    │         ├── [FullTask] LAUNCH_AINALYSIS
    │         │     ├── 单模型分析 ──► LLM 扫描源码
    │         │     └── 多模型分析 ──► LLM 批量扫描
    │         │         └── 报告 → SCORE_VULN → ANALYZE_VULN
    │         │
    │         ├── LAUNCH_SARIF (外部 SARIF 广播)
    │         │     └── SARIF → ANALYZE_VULN (直接跳过评分)
    │         │
    │         └── LAUNCH_BGWORKERS ──► 后台工作者
    │               ├── FuzzManager (模糊测试引擎)
    │               │     ├── seed_callback → PROCESS_COVERAGE
    │               │     ├── crash_callback → TRIAGE_POV
    │               │     └── triage_callback → TRIAGE_FUZZ_CRASH
    │               ├── BulkCoverageWorker (批量覆盖)
    │               │     └── frontier_callback → PRE_FLIP_BRANCH
    │               └── BulkCrashWorker (批量崩溃)
    │
    └── get_sarifs() → LAUNCH_SARIF
```

---

## 四、漏洞分析管线（核心增值链）

```
                        ┌──────────────────┐
                        │  漏洞报告源       │
                        │                  │
                        │ ① Infer          │
                        │ ② AInalysis     │
                        │ ③ SARIF 广播    │
                        │ ④ DiffAnalyzer  │
                        │ ⑤ 模糊测试崩溃   │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │   SCORE_VULN     │
                        │  LLM 打分        │
                        │  阈值 = 80% 分位 │
                        └────────┬─────────┘
                                 │ score > GLOBAL_SCORE_THRESHOLD(0.1)?
                                 │ AND score > task quantile 80%?
                                 ▼
                        ┌──────────────────┐
                        │   ANALYZE_VULN   │
                        │  LLM 深度分析    │
                        │  ± SpendLimit    │
                        │  (max $666/次)   │
                        └────────┬─────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │ 拒绝      │ │ 接受     │ │ SARIF    │
              │ (negative)│ │ (positive)│ │ 评估     │
              │ 不处理    │ │ 继续     │ │ 提交初判  │
              └──────────┘ └────┬─────┘ └──────────┘
                                │
                                ▼
                       ┌────────────────┐
                       │   LLM 去重     │
                       │  dedupe_vuln() │
                       │  stacktrace    │
                       │  匹配 + LLM    │
                       └────────┬───────┘
                                │ 是新漏洞?
                                ▼
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
             ┌──────────────┐       ┌──────────────┐
             │  PRODUCE_POV │       │  PATCH_VULN  │
             │  LLM 生成    │       │  LLM 生成    │
             │  利用验证     │       │  补丁        │
             │  ± Spend     │       │  ± Spend     │
             │  (max $666)  │       │  (max $666)  │
             └──────┬───────┘       └──────┬───────┘
                    │                       │
                    ▼                       ▼
             ┌──────────────┐       ┌──────────────┐
             │  TRIAGE_POV  │       │  BUNDLE_PATCH │
             │  确定漏洞归属 │       │  补丁矩阵     │
             │  stacktrace  │       │  测试所有 POV │
             │  或 LLM      │       │  安排新补丁   │
             └──────┬───────┘       └──────┬───────┘
                    │                       │
                    └────────┬──────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │  BUNDLE_POV   │
                    │  补丁矩阵     │
                    │  (POV vs 补丁)│
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │ SUBMIT_BUNDLE │
                    │  提交给竞赛 API │
                    │  POV+补丁+评估  │
                    └────────────────┘
```

### SpendLimiter 预算控制

CRS 每个 task 有独立 SpendLimiter（基于 CounterDB），控制 LLM 花销：

| 操作 | 最大花费 | 每次存入 |
|------|---------|---------|
| analyze_vuln | $666 | $1 |
| patch_vuln | $666 | $1 |
| produce_pov | $666 | $5 |
| triage_pov | $500 | $1 |

```
SpendLimiter 机制：
  每次执行前检查 balance >= max
  执行后扣除实际花费
  每次 submit_job 时 deposit 金额累加
  → 等价于"每笔款项用完才能再申请"
```

---

## 五、12 个 LLM Agent 详细

| # | Agent | 文件 | 职责 | 输入 | 输出 |
|---|-------|------|------|------|------|
| 1 | **CRSVuln** | `vuln_analyzer.py` | 分析漏洞报告，判断真假 | VulnReport | VulnAnalysis (+/-) |
| 2 | **CRSDiff** | `diff_analyzer.py` | 分析代码 diff 找漏洞 | 项目 diff (原始/压缩) | 漏洞列表 |
| 3 | **CRSPovProducer** | `pov_producer.py` | 生成 PoV (利用代码) | 漏洞描述 | POV Python code |
| 4 | **CRSPatcher** | `produce_patch.py` | 生成漏洞补丁 | 漏洞 + PoV | Patch diff |
| 5 | **CRSTriage** | `triage.py` | 崩溃去重/分类 | 解码后的 PoV 输入 | 漏洞分析 |
| 6 | **CRSBranchFlipper** | `branch_flipper.py` | 分支翻转（覆盖新路径） | Frontier 目标 | 新 seed |
| 7 | **CRSGenerateKaitai** | `generate_kaitai.py` | Kaitai Struct 解码器生成 | 种子样本 | Kaitai 模式 |
| 8 | **CRSHarnessInputDecoder** | `harness_input_decoder.py` | Python 输入解码器生成 | 种子样本 | Python 解码器 |
| 9 | **CRSClassifier** | `classifier.py` | 漏洞分类 | 漏洞描述 | 分类标签 |
| 10 | **FuncSummarizer** | `func_summarizer.py` | 函数摘要（辅助） | 函数源码 | 摘要 |
| 11 | **SourceQuestions** | `source_questions.py` | 源码问答（辅助） | 源码 + 问题 | 回答 |
| 12 | **XMLAgent** | `xml_agent.py` | XML 格式处理 | XML 数据 | 处理结果 |

### Agent 基类 (`agent.py`)

```
Agent (CRSBase)
  │
  ├── 生命周期:
  │     __init__ → from_task() → 实际方法
  │     (stateless, 每次新建实例)
  │
  ├── LLM 调用:
  │     llm = model_manager.get_model(name)
  │     llm.chat([sys_msg, user_msg], tools=...)
  │
  ├── 工具系统:
  │     ToolDescription
  │       └── name, description, parameters
  │     通过 @tool 装饰器注册
  │     自动注入到 prompt
  │
  ├── 回退模型:
  │     主模型失败 → 回退到次模型
  │     次模型失败 → 回退到最终模型
  │
  ├── 序列化:
  │     pickle/unpickle 支持进程间迁移
  │     LLM 调用可被中断/恢复
  │
  └── 上下文管理:
       tool_history 自动展开/压缩
       迭代上限检测
```

### Agent 使用模式

```python
# 典型用法（以 POV Producer 为例）
class CRSPovProducer(CRSBase):
    async def produce_pov(self, vuln, model_idx=0, ...):
        # 1. 构建上下文（漏洞描述、源码、解码器）
        context = self.build_context(vuln, ...)

        # 2. LLM 生成 PoV Python 代码
        result = await self.llm.chat(
            [SYSTEM_PROMPT, context],
            tools=[COMPILE_AND_RUN, READ_FILE, ...]
        )

        # 3. 工具执行循环
        while result.has_tool_calls and not self.is_done:
            tool_results = await self.execute_tools(result.tool_calls)
            result = await self.llm.chat(tool_results)

        # 4. 返回结果
        return POVProducerResult(pov_python=result.text, ...)
```

---

## 六、模糊测试管线

CRS 集成了完整的基于 LibFuzzer / AFL 的模糊测试引擎：

```
                    ┌──────────────┐
                    │  FuzzManager │
                    │  每个任务一个 │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
      ┌────────────┐ ┌────────────┐ ┌────────────┐
      │ Seed 回调   │ │ Crash 回调  │ │ Triage 回调 │
      │ add_seed   │ │ 注册 crash │ │ 处理崩溃   │
      │ → Coverage │ │ → TRIAGE   │ │ → Bulk     │
      │   处理     │ │   POV     │ │   Crash    │
      └────────────┘ └────────────┘ └────────────┘
                           │
                           ▼
                    ┌────────────────┐
                    │  Coverage DB   │
                    │  Seed → 覆盖图 │
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  Frontier 分析  │
                    │  找"最近但未覆盖"│
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  Branch Flip   │
                    │  LLM 翻转分支   │
                    │  生成新 seed   │
                    └───────┬────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  添加 seed     │
                    │  到 corpus    │
                    └────────────────┘
```

### Branch Flipper 工作原理

```
PRE_FLIP_BRANCH:
  - 输入: frontier (目标函数/文件 + 最近命中点)
  - 确定性检查: 是否值得 flip (过期时间、翻倍预算)
  - 输出: True/False → 值得则提交 FLIP_BRANCH

FLIP_BRANCH:
  - 输入: frontier 详细数据
  - 步骤:
    1. 获取到达最近点的 seed
    2. 解码 seed (使用 Kaitai / Python decoder)
    3. 获取对应的 encoder (种子生成器)
    4. LLM 分析 seed，修改输入试图到达目标函数
    5. 编译修改后的 Python PoV → 实际执行
    6. 如果成功 → 添加 seed 到 corpus
  - 并发限制: 10 (高成本操作)
  - 每个任务最多: 100 次
```

---

## 七、POV 生产管线

```
漏洞描述 (函数名 + 文件 + 描述)
    │
    ▼
┌──────────────────────────────────────────────────┐
│              POV Producer                        │
│                                                  │
│  1. 构建上下文:                                   │
│     - 读取漏洞源码                                │
│     - 读取相关文件 (搜索 import/include)          │
│     - 获取解码器 + 编码器                         │
│                                                  │
│  2. LLM 生成验证脚本 (Python):                    │
│     - 导入解码器                                  │
│     - 构造触发漏洞的输入                          │
│     - 编码为 harness 可用的格式                    │
│                                                  │
│  3. 工具循环:                                     │
│     - compile_and_run (编译 + 执行验证)           │
│     - read_file (读更多源码)                      │
│     - run_pov_with_encoder (编码执行)             │
│     - debug_pov (调试失败)                       │
│                                                  │
│  4. 结果:                                        │
│     ConfirmedPOVProducerResult → TRIGGERABLE     │
│     其他 → 重试或放弃                            │
└──────────────────────────────────────────────────┘
```

### POV 多路并行

```python
# produce_pov 启动 3-6 路并行尝试
params = [
    (PythonHarnessInputDecoder, False),  # 用 Python 解码器
    (None, False),                        # 不用解码器
    (None, False),                        # 不用解码器
    (PythonHarnessInputDecoder, True),   # Delta: 原始 diff
    (None, True),
    (None, True),
]
# 任一成功即停止 (stop_condition)
```

---

## 八、补丁生成管线

```
漏洞描述 + PoV 实例
    │
    ▼
┌──────────────────────────────────────────────────┐
│                 CRSPatcher                        │
│                                                  │
│  在两种模式下并行:                                │
│  ┌─────────────────┐  ┌──────────────────────┐   │
│  │ 常规            │  │ rawdiff (压缩 diff)   │   │
│  │ 直接在源码上修改  │  │ LLM 生成补丁文本      │   │
│  └────────┬────────┘  └──────────┬───────────┘   │
│           │                      │               │
│           ▼                      ▼               │
│    ┌─────────────────────────────────────┐       │
│    │  编译验证                             │      │
│    │  1. apply patch                     │      │
│    │  2. build (make/ninja)              │      │
│    │  3. 如果失败 → LLM 重新生成          │     │
│    └─────────────────────────────────────┘       │
│                                                  │
│  结果:                                           │
│    ConfirmedPatchResult → 带编译产物             │
│     → BUNDLE_PATCH (用已有 POV 测试补丁矩阵)    │
│    None → PATCH_VULN 重新调度 (最多 5 次)       │
└──────────────────────────────────────────────────┘
```

### 补丁矩阵测试

```

  Patch ↓ \ POV →  │  POV_1  │  POV_2  │  POV_3  │
  ─────────────────┼────────┼────────┼────────┤
  Patch_A          │   ✅   │   ✅   │   ❌   │
  Patch_B          │   ❌   │   ✅   │   ❌   │
  Patch_C          │   ✅   │   ✅   │   ✅   │ ← 最终选择的补丁

  BUNDLE_PATCH: 测试每个补丁是否修复所有 POV
  BUNDLE_POV: 测试每个 POV 是否被当前补丁修复
  maybe_update_bundle(): 选择覆盖全部 POV 的补丁
```

---

## 九、包提交管线

```
漏洞 N
    │
    ▼
┌──────────────────────────────────────────┐
│             Bundle                       │
│                                          │
│  ┌───────────┐ ┌────────┐ ┌──────────┐  │
│  │  POV_ID   │ │补丁_ID │ │ SARIF_ID │  │
│  │  利用代码  │ │  diff  │ │  评估    │  │
│  └───────────┘ └────────┘ └──────────┘  │
│                                          │
│  提交策略:                               │
│  - 3 项中有 2 项就可以提交               │
│  - 无 POV 的补丁等 45 分钟观察           │
│  - 已验证/未验证补丁比例 2:1             │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│              Submitter                    │
│                                          │
│  1. submit_patch → Competition API       │
│  2. submit_pov   → Competition API       │
│  3. submit_sarif_assessment → API        │
│  4. submit_bundle → API                  │
│  5. poll_patch (等待评分结果)             │
│  6. poll_pov   (等待评分结果)             │
│  7. 失败/错误 → 重置提交状态，重新打包    │
│  8. bundle_submission 状态追踪            │
│     (pending/accepted/rejected/failed)   │
└──────────────────────────────────────────┘
```

---

## 十、存储系统

```
┌──────────────────────────────────────────────────────────────────┐
│                          DB 层                                    │
│                                                                  │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐        │
│  │  TaskDB   │ │  WorkDB   │ │ProductsDB │ │ CounterDB │        │
│  │           │ │           │ │           │ │           │        │
│  │ 任务源    │ │ 任务调度   │ │ 产物仓库   │ │ 计数器    │        │
│  │           │ │           │ │           │ │           │        │
│  │ tasks     │ │ jobs      │ │ reports   │ │ kv counter│        │
│  │ sarifs    │ │           │ │ vulns     │ │           │        │
│  │ cancelled │ │           │ │ povs      │ │ 用于:     │        │
│  │           │ │           │ │ patches   │ │ - 预算追踪 │        │
│  │           │ │           │ │ bundles   │ │ - 翻倍次数 │        │
│  │           │ │           │ │ decoders  │ │ - 提交数   │        │
│  │           │ │           │ │ encoders  │ │          │        │
│  │           │ │           │ │ submissions│ │          │        │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘        │
│                                                                  │
│  所有 DB: SQLite + aiosqlite 异步接口                             │
│  持久化: 存在 DATA_DIR，进程重启不丢失                             │
└──────────────────────────────────────────────────────────────────┘
```

### ProductsDB 核心 Schema

```
reports:   id, task_id, function, file, description, source, sarif_id, score
vulns:     id, task_id, source, function, file, description, conditions
povs:      id, task_id, vuln_id, harness, input, output, stack, python
patches:   id, task_id, vuln_id, diff, artifacts
bundles:   id, task_id, vuln_id, patch_id, pov_id, sarif_id
decoders:  id, task_id, harness_num, cls, blob (pickle)
encoders:  id, task_id, harness_num, cls, blob (pickle)
```

---

## 十一、Rust 性能层

CRS 将性能关键路径下放到 Rust：

```
┌─────────────────────────────────────────────┐
│              crs_rust (PyO3)                │
│                                             │
│  lib.rs         → Python 绑定入口           │
│  log.rs         → 高性能文件日志             │
│  patch.rs       → 补丁应用 (比 Python 快)   │
│  http.rs        → HTTP 请求 (tokio)         │
│  metrics.rs     → InfluxDB 指标上报         │
│  path_suffix.rs → 路径后缀树 (覆盖分析)     │
└─────────────────────────────────────────────┘
```

---

## 十二、关键设计模式总结

### 1. 分层抽象

```
CRS (事件循环)          ← 业务编排
  └── WorkDB (调度)     ← 任务调度
        └── SQLite      ← 持久化
              └── asyncio ← 并发
```

### 2. BulkTaskWorker 批量处理

覆盖率处理 (PROCESS_COVERAGE) 和崩溃处理 (TRIAGE_FUZZ_CRASH) 用批量模式：

```
收到第一项 → 等待 30 秒 → 收集更多项 → 最多 500 项 → 批量处理
```

### 3. 代码解码/编码链

```
Kaitai Struct 模式
  → LLM 生成 Kaitai 解码器
  → 解码模糊测试的二进制输入
  → LLM 阅读解码后的结构化输入
  → 编码器重新编码为二进制格式
  → 传给 fuzzer harness
```

### 4. 多模型回退

每个 Agent 可配置 3 层模型（主/次/最终），逐层降级。

### 5. 确定性优先

不是所有步骤都用 LLM：
- stacktrace 匹配 → 确定性子系统（无需 LLM）
- patch 结果矩阵 → 确定性执行（编译 + 测试）
- coverage 分析 → 确定性（覆盖率跟踪）
- score quantile → 确定性（分位数计算）

---

## 十三、agies 可以学习的点

| 学到什么 | 描述 | 优先级 |
|----------|------|--------|
| **确定性调度 > LLM 调度** | WorkDB 方案 B 的确定性重试/超时/并发控制，远比"Brain LLM 决策"可靠 | ⭐⭐⭐ |
| **SQLite 持久化** | 任务队列持久化 → 进程崩溃不丢任务状态 | ⭐⭐⭐ |
| **BulkTaskWorker 模式** | 覆盖率/崩溃处理等高频事件用批量+延时窗口 | ⭐⭐⭐ |
| **SpendLimiter 预算控制** | 基于 CounterDB 的精确 LLM 花费追踪 | ⭐⭐ |
| **PoV 实际执行** | 生成 PoV 后通过 harness 实际执行验证，比 LLM 空判"可触发"可靠 | ⭐⭐ |
| **分层重试** | 指数退避 + per-type attempts + 超时链 | ⭐⭐ |
| **公平调度 (Scheduler)** | 多任务间防止单个 task 饿死 | ⭐⭐ |
| **Rust 性能关键路径** | 日志/补丁/HTTP → PyO3 | ⭐ |
| **代码解码器自动生成** | Kaitai/Python decoder 自动从种子生成 | ⭐ |

### 根本性差异

```
agies 定位: 审计工具
  - 产出: 安全报告（漏洞列表 + 分析推理）
  - 核心竞争力: LLM 读代码理解意图
  - 不做: PoV 生成、补丁、模糊测试

Theori CRS 定位: 竞赛系统
  - 产出: PoV（利用代码）+ Patch（补丁）+ SARIF 评估
  - 核心竞争力: 端到端自动利用+修复
  - 不做: 审计报告（竞赛不需要）
```

> 这意味着 agies 不应该盲目照搬 CRS 架构。有价值的是调度机制、确定性工具层设计、budget 控制思路，而非 PoV/Patch 管线。
