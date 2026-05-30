# Sandyaa 深度剖析：AI 原生的自动化代码审计系统

## 摘要

Sandyaa 是 SecureLayer7 公司于 2026 年 4 月发布的开源自动化安全审计工具，以 **"real exploits, no hallucination"** 为核心理念，是目前少数将大型语言模型（LLM）深度嵌入代码审计全流程的系统。本文从外部声誉出发，追溯开发团队背景，继而深入其 TypeScript 代码架构，详细剖析其在递归分析、幻觉防御、攻击者控制验证等领域的前沿设计。同时基于对 service-platform 项目的实战测试，揭示其 Phase 1 高价值发现能力与 Phase 2 JSON 解析缺陷，给出客观的技术评价。

**关键词**: 代码审计, 大语言模型, 递归分析, 幻觉防御, AI 安全, 攻击者控制验证

---

## 1 引言

传统静态分析工具（如 Fortify、Checkmarx、Semgrep）依赖预定义规则和模式匹配，存在高误报率、跨文件/跨语言分析能力弱、缺乏语义理解等固有问题。近年来，以 LLM 驱动的安全审计成为研究热点，但现有方案多为 LLM 的浅层应用——将代码片段直接输入 LLM 提问，缺乏系统性的验证与追溯机制。

Sandyaa 试图回答一个核心问题：**能否构建一个 LLM 驱动的全自动审计流水线，既能深度理解代码语义，又能通过递归验证和自我矛盾检测来消除幻觉？**

本文从外到内，先通过 Web 研究建立外部视角，再深入源码进行架构级解剖。

---

## 2 外部视角：知名度与团队背景

### 2.1 知名度分析

截至 2026 年 5 月，Sandyaa 的公开指标如下：

| 指标 | 数值 |
|------|------|
| GitHub Stars | 23 |
| GitHub Forks | 2 |
| 项目状态 | Alpha |
| 首次发布 | 2026 年 4 月 20 日（SecureLayer7 博客公告） |
| 最新提交 | 2026 年 4 月 14 日 |
| 开源协议 | 未明确标注 |
| 安装方式 | npm（`npm install` + `npm run build` + `npm link`）|

Sandyaa 在公开市场上仍处于极早期阶段。23 个 star 和 2 个 fork 表明其尚未获得广泛的社区关注。然而，这一数字可能被低估了其技术含量——正如后文将揭示的，Sandyaa 的架构深度远超其知名度所反映的水平。这与它的目标定位（企业级代码审计，而非轻量级工具）以及发布时间过短（不到一个月）有关。

### 2.2 开发团队：SecureLayer7

SecureLayer7 Technologies 是一家印度网络安全公司，核心信息如下：

- **成立时间**: 2012 年
- **总部**: 印度浦那（Pune）
- **模式**: 自筹资金（Bootstrapped），未获外部风投
- **营收**: 约 1350 万美元
- **员工规模**: 约 120 人
- **认证**: CREST 认证（英国网络安全行业标准）
- **核心业务**: 渗透测试、红队服务、安全审计、安全培训

SecureLayer7 作为一家以安全服务为核心业务的公司，开发 Sandyaa 的动机明显：将其多年的手动渗透测试经验自动化。这也是 Sandyaa 设计中处处体现"实战导向"的原因——不是学术原型，而是试图解决真实世界中的代码审计问题。

值得注意的是，公司采取的自筹资金模式意味着 Sandyaa 的开发资源有限，这与后文代码中某些实现粗糙之处（如 JSON 解析缺陷）可以相互印证。

### 2.3 RLM 理论基础

Sandyaa 的递归分析引擎受 **Recursive Language Model (RLM)** 论文启发（arXiv:2512.24601，MIT CSAIL 发表）。该论文提出了一种让 LLM 通过驱动 Python REPL 来编写代码，实现对自身输出的递归过滤、分块和子查询的方法，理论上可以将有效上下文窗口扩展 100 倍。

Sandyaa 在 `rlm-executor.ts` 和 `rlm-orchestrator.ts` 中实现了这一思路的变体——让 Claude 驱动的 Python REPL 接管代码分析的多轮循环过程。

---

## 3 架构全景

Sandyaa 采用**两阶段流水线架构**，整体流程图如下：

```
┌─────────────────────────────────────────────────────────┐
│                    CLI 入口 (index.ts)                    │
│  参数解析 → 目标验证 → 禁止自扫描 → 设置全局 CWD          │
└──────────────────┬──────────────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────────────┐
│                    Orchestrator (核心引擎)                │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ FileScanner  │  │ FilePrioriti │  │ DynamicChunke │  │
│  │ (git感知扫描) │→│ zer (AI排序)  │→│ r (自适应分块)  │  │
│  └──────────────┘  └──────────────┘  └───────┬───────┘  │
│                                              ▼          │
│  ┌────────────────── 分块处理循环 ──────────────────┐   │
│  │                                                  │   │
│  │  Phase 1: 高优先级目标 (AI精选)                   │   │
│  │  Phase 2: 系统全覆盖 (分块扫描)                   │   │
│  │                                                  │   │
│  │  每个分块:                                       │   │
│  │  ① ContextAnalyzer.analyze() → 上下文构建        │   │
│  │  ② VulnerabilityDetector.detect() → 漏洞检测     │   │
│  │  ③ RecursiveStrategyEngine.apply() → 递归验证    │   │
│  │  ④ RegressionDetector → 回归检测                 │   │
│  │  ⑤ BlastRadiusCalculator → 影响范围计算           │   │
│  │  ⑥ POCGenerator → 利用证明生成与验证              │   │
│  │  ⑦ Reporter.report() → 报告输出与检查点保存       │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 3.1 两阶段设计

Sandyaa 将分析分为两个截然不同的阶段：

**Phase 1 —— 高价值目标分析**（`orchestrator.ts:294-308`）

当文件数超过 1000 时触发，`FilePrioritizer` 使用 Claude 对代码库进行智能采样分析（用 200 个文件的层抽样代表全部结构），输出高优先级文件列表。这些文件按优先级排序后进入分析循环。

**Phase 2 —— 系统全覆盖**（`orchestrator.ts:648-750`）

Phase 1 完成后，用户被询问是否继续扫描剩余文件。如果同意，Phase 2 使用 `DynamicChunker` 确定的分块大小，逐块扫描全部剩余文件。Phase 2 的分析管线与 Phase 1 相同，只是缺少递归验证等高成本步骤。

### 3.2 动态分块机制

`DynamicChunker`（`dynamic-chunker.ts`）是 Sandyaa 的自适应核心组件。它不采用固定分块大小，而是基于持续积累的度量动态调整：

```
getChunkSize() 考虑四个因素:
  ① 每文件 token 消耗均值 → 目标每块 30K tokens
  ② 上下文窗口压力 (>50% → 减30%, >70% → 减50%)
  ③ 分析时间 (>5分钟 → 减20%)
  ④ 文件大小 (>0.5MB → 减20%)
  最终范围: [5, 50] 文件/块
```

度量更新使用**指数移动平均**（alpha=0.3），使系统对近期变化敏感而不会丢失历史模式。这种设计直接来自 RLM 论文的分块思想——上下文窗口不再是硬限制，而是通过动态调整来柔性管理。

### 3.3 上下文构建与智能规划

`ContextAnalyzer` 负责为每个分块构建结构化的 `CodeContext`，包含：

- `FileContext[]`: 文件列表、语言、函数、导入/导出
- `FunctionContext`: 函数签名、参数、数据流、用户输入点、敏感接收点
- `DataFlow[]`: 源→接收点→污点路径
- `TrustBoundary[]`: 信任边界位置和类型
- 专门的 MemorySafety、Concurrency、Semantic、GitHistory 上下文

此外，`AnalysisPlanner` 组件和 `learnings` 更新机制允许分析器从前序分块中学习成功策略，指导后续分块的规划。这是 Sandyaa 持续进化的关键设计——每一次分析的结果都会反馈到下一轮规划中（`orchestrator.ts:583-593`）。

---

## 4 核心技术创新

### 4.1 AI 驱动的文件优先级排序

`FilePrioritizer`（`file-prioritizer.ts`）是 Sandyaa 最独特的设计之一。传统工具要么扫描全部文件（太慢），要么依赖静态规则（如仅扫描 `src/` 目录）。Sandyaa 的方案是**让 LLM 决定哪里最可能有漏洞**。

其执行路径：

```
selectHighValueTargets()
  ├─ 文件数 > 50000 → 纯启发式（速度优先）
  ├─ 文件数 ≤ 50000 → AI 驱动
  │    ├─ 层抽样: 按目录比例取 200 个文件
  │    ├─ 构建 metadata: 语言分布、目录结构、安全敏感路径、git 变更历史
  │    └─ Claude 分析抽样 + metadata → 输出优先级列表
  └─ AI 失败时 → 回退到启发式（安全关键路径 > 近期变更）
```

抽样使用**层抽样**（stratified sampling），按目录比例抽样以保持结构代表性。AI 返回的优先级列表中包含 `path`、`priority`（1-10）、`reason` 三个字段，排序后供 Phase 1 使用。

技术亮点在于**优雅降级**：当 AI 调用失败时（line 78-83），系统自动回退到安全关键路径优先的启发式策略，且对用户透明。这种"AI 优先，启发式兜底"的设计贯穿 Sandyaa 整体架构。

### 4.2 递归语言模型（RLM）集成

`RLMExecutor`（`rlm-executor.ts`）实现了 RLM 论文中的核心思想——让 LLM 驱动 Python REPL 来完成需要多次推理循环的任务。

RLM 激活流程：

```
shouldActivateRLM() → 检查阈值条件
  ↓ 激活
RLMExecutor.execute()
  ├─ Step 1: 启动 Python REPL
  ├─ Step 2: 将代码库加载到 REPL 的 Python 命名空间
  ├─ Step 3: 注册工具函数（文件搜索、模式匹配等）
  ├─ Step 4: 构建 RLM 提示（包含上下文和任务）
  ├─ Step 5: 多轮循环（multiTurnLoop）
  │    ├─ 每轮: LLM 生成 Python 代码 → REPL 执行 → 结果返回 LLM
  │    ├─ LLM 根据中间结果决定继续或终止
  │    └─ 支持并行子查询（sub-queries）
  └─ Step 7: 格式化结果 + 清理 REPL
```

RLM 的激活阈值由配置中的 `activationThreshold` 控制（`orchestrator.ts:56-58`），包括最小上下文大小和最小文件数，确保仅在代码库足够复杂时才启用 RLM 的高成本分析。

### 4.3 八重递归策略引擎

`RecursiveStrategyEngine`（`recursive-strategy.ts`）定义了 8 种递归策略，每个策略解决代码审计中的一个特定维度的问题：

| # | 策略名称 | 解决的问题 | 实现方法 |
|---|----------|-----------|---------|
| 1 | **call-chain-tracing** | 函数调用链的完整追溯 | 递归跟踪调用关系，寻找调用链中的脆弱环节 |
| 2 | **data-flow-expansion** | 数据流路径的完全展开 | 从输入点到接收点递归展开每个数据流步骤 |
| 3 | **self-verification** | 模型自我验证发现 | LLM 对自己之前的分析进行批判性检查 |
| 4 | **vulnerability-chaining** | 多个漏洞的组合利用 | 寻找漏洞之间的依赖关系，构建攻击链 |
| 5 | **poc-refinement** | POC 的迭代改进 | 基于执行结果递归优化 POC 代码 |
| 6 | **contradiction-detection** | 逻辑矛盾的检测 | 比较不同来源的分析结果，发现不一致 |
| 7 | **assumption-validation** | 假设的递归验证 | 对每个"假设"进行多轮验证 |
| 8 | **exploitability-proof** | GOD-LEVEL: 可利用性证明 | 5-Whys + 5-Hows 方法论 |

这 8 种策略并非简单的并行执行，而是按照**分析深度**排序：先执行调用链和数据流追踪进行事实挖掘，再进行自验证和矛盾检测进行质量评估，最后才是 GOD-LEVEL 的可利用性证明。

### 4.4 跨语言攻击者控制分析

`AttackerControlAnalyzer`（`attacker-control-analyzer.ts`）是 Sandyaa 最突出的创新之一。它设计了一套**语言无关的验证流水线**，对每个漏洞候选进行六个维度的验证：

```
analyze(vulnerability)
  ├─ P0-3: 执行上下文验证
  │    ├─ compiler code? → ❌ 编译时代码，非运行时可利用
  │    ├─ startup code? → ❌ 启动时代码，非运行时可利用
  │    ├─ internal API? → ❌ 内部API，外部不可达
  │    └─ test code? → ❌ 测试代码，非生产环境
  │
  ├─ P0-4: 信任边界验证
  │    ├─ 入口是否为受信/内部API? → ❌ 受信输入
  │    └─ 数据流是否穿越信任边界? → ❌ 混合边界
  │
  ├─ P0-2: 外部可达性验证
  │    ├─ 是否有具体入口点? → ❌ 无法证明外部可达
  │    ├─ 是否有数据流路径? → ❌ 缺少追踪路径
  │    ├─ 是否匹配用户输入API? → ⚠ 建议验证
  │    └─ 是否为输出函数? → ❌ 输出函数不解析输入
  │
  ├─ P0-5: 验证链检查
  │    └─ 代码中是否存在实际验证逻辑? → ⚠ 可能有多层验证
  │
  ├─ P1-6: 线程模型验证
  │    └─ 竞争条件：语言是否单线程? → ❌ 无并发原语
  │
  └─ P1-7: 语义模式验证
       ├─ 内存安全语言报告内存漏洞? → ⚠ 与语言保证矛盾
       ├─ 整数溢出但存在长度检查? → ⚠ 需要验证绕过
       ├─ 类型混淆但存在运行时类型检查? → ⚠ 需要验证绕过
       └─ 越界但存在边界检查? → ⚠ 需要验证绕过
```

**语言感知**是该分析器的关键特性。它通过 `LanguagePatterns` 接口为每种语言维护一套正则表达式模式集，覆盖：

- `compilerCode`: 编译器相关路径/函数
- `runtimeCode`: 运行时系统
- `startupCode`: 初始化代码
- `embedderAPIs`: 内部/嵌入式 API
- `testCode`: 测试代码
- `userInputAPIs`: 用户输入接口
- `deserializationAPIs`: 反序列化接口
- `externalAPIs`: 外部接入点
- `outputFunctions`: 输出函数
- `inputFunctions`: 输入函数
- `validationFunctions`: 验证函数
- `concurrencyKeywords`: 并发关键字
- `memoryUnsafe`: 是否内存不安全
- `safetyChecks`: 安全检查模式
- `unsafeOperations`: 不安全操作
- `singleThreaded`: 是否默认单线程

目前支持的语言包括 C/C++、JavaScript、TypeScript、Python、Go、Rust、Java、C#、PHP、Ruby。每种语言在内存安全、并发模型等方面的差异都被纳入分析维度。

**P0 和 P1 优先级标记**反映了每条验证规则的权重：P0 规则（执行上下文、信任边界、外部可达性）是**阻断性**的，不通过则直接标记为"非攻击者可控"；P1 规则（线程模型、语义模式）是**提示性**的，产生警告但不直接阻断。

### 4.5 矛盾检测与幻觉防御

Sandyaa 最具防御性的设计是自验证机制。`RecursiveStrategyEngine` 中的 `contradiction-detection` 策略实现了三层检查：

**第一层：调用链矛盾检测**

比较原始漏洞分析中声称的漏洞位置与递归调用链分析发现的实际脆弱点：

```typescript
// recursive-strategy.ts:259-268
for (const chain of recursive.callChains) {
  if (chain.vulnerableAt && chain.vulnerableAt !== vuln.location.function) {
    // 矛盾：原始分析称漏洞在函数 A，调用链显示在函数 B
  }
}
```

**第二层：自我验证状态**

对 `recursiveDeepen` 返回的 `deeper-analysis` 类型的发现进行评估。当模型无法确认或否定自己的分析时，产生不确定性标记。

**第三层：数据流矛盾检测**

检查数据流展开结果是否与原始发现相矛盾。

更关键的是**跨模型升级机制**（`recursive-strategy.ts:93-123`）：

```
如果 Sonnet 产生不确定性 (uncertain)
  └─ 且漏洞严重性为 critical 或 high
       └─ 用 Opus 重新执行递归分析
            ├─ Opus 验证通过 → 升级为 VERIFIED
            ├─ Opus 明确反驳 → 降级为 CONTRADICTED
            └─ Opus 也不确定 → 维持 UNCERTAIN
```

这种"用更强的模型来验证较弱模型的发现"的设计，在现有审计工具中极为罕见。它承认了 LLM 的不确定性，并用计算成本交换可靠性。

### 4.6 5-Whys/5-Hows 可利用性证明

标榜为 **GOD-LEVEL** 的 `exploitability-proof` 策略，实现了 5 次"为什么"+ 5 次"如何"的问询方法：

```
5-Whys（根因追溯）：
  Why #1: 攻击者输入如何到达此代码？ → 入口点
  Why #2: 数据如何从入口传播到漏洞？ → 数据流路径
  Why #3: 为什么验证机制被绕过？ → 绕过分析
  Why #4: 为什么这是可利用的？ → 攻击路径
  Why #5: 为什么现有的防护不够？ → 安全机制分析

5-Hows（攻击路径构建）：
  How #1: 攻击者如何构造输入？ → 输入构造
  How #2: 输入如何通过信任边界？ → 边界穿越
  How #3: 实际如何触发漏洞？ → 触发机制
  How #4: 如何实现利用目标？ → 利用达成
  How #5: 如何规避检测？ → 检测规避
```

每条验证产生一个以 `✓` 或 `⚠` 或 `✗` 开头的结果。只有当所有 5 项验证全部通过时，`isFullyProven` 才为 `true`（`recursive-strategy.ts:150-153`）。

这种设计理念来自 SecureLayer7 作为渗透测试服务公司的背景——将手动渗透测试中的"系统性验证"流程编码为可自动执行的检查步骤。

### 4.7 证据链模型与去重

Sandyaa 的 `Vulnerability` 接口（`vulnerability-detector.ts:35-104`）定义了一个极其丰富的证据模型：

```typescript
interface Vulnerability {
  id: string;
  type: string;           // 具体类型（非泛型如"vulnerability"）
  severity: 'critical' | 'high' | 'medium' | 'low';
  exploitability: number; // 0-1 浮点数
  attackerControlled?: {
    isControlled: boolean;
    entryPoint: string;    // 攻击入口（如 "HTTP POST /api/login"）
    dataFlow: string[];    // 从入口到漏洞的路径
    attackPath: string;    // 具体攻击步骤
  };
  location: { file: string; line: number; function: string; };
  evidenceChain: Evidence[];  // 每个证据有类型、位置、代码片段、推理
  attackVector: string;       // 攻击向量（详细）
  impact: string;             // 影响描述
  regression?: { originalFix: string; similarity: number; type: string; };
  blastRadius?: { callSiteCount: number; ... };
  verificationStatus?: 'verified' | 'uncertain' | 'contradicted' | 'unverified';
  contradictions?: string[];
  confidence?: 'high' | 'medium' | 'low';
  needsManualReview?: boolean;
  // ... God-level fields
}
```

`Evidence` 链（`vulnerability-detector.ts:114-119`）是 Sandyaa**基于事实的审计哲学**的体现——每个漏洞都必须附带可验证的证据，包括代码位置、代码片段和推理过程。这与传统 LLM 审计中常见的"某某可能存在漏洞"式模糊输出形成鲜明对比。

**去重机制**使用 `(file, line, function)` 三元组作为哈希键。当发现重复时，保留更高严重性的版本并合并证据链（`vulnerability-detector.ts:616-672`）。

### 4.8 自动模型选择与提供商切换

`model-registry.ts` 实现了模型提供商的自动发现：

- **Claude**: 直接使用 CLI 层级别名（haiku / sonnet / opus），CLI 自动解析为最新模型
- **Gemini**: 启动时调用 `autoResolveGeminiModels()` 通过 Google API 查询最新稳定版本，按版本号排序，选取每个层级的最新模型

`DynamicModelSelector` 进一步基于任务类型和代码复杂度自动选择模型：

```
任务类型 → 推荐模型:
  file-prioritization → Haiku (快速/廉价)
  vulnerability-detection → Sonnet (质量平衡)
  poc-generation → Sonnet
  默认 → Sonnet
```

`ModelExecutor` 支持**主提供商 + 备用提供商**的自动切换机制，当主提供商遇到速率限制时自动回退到备用。这种多模型弹性的设计在实际使用中意味着即使 Claude API 不可用，系统仍可使用 Gemini 继续工作。

---

## 5 边界防御系统

Sandyaa 实现了多层边界验证来防止 LLM 幻觉导致的无效输出：

### 5.1 代码库自扫描防御

`index.ts:84-92` 阻止 Sandyaa 分析自己的代码目录：

```typescript
if (targetResolved === sandyaaDir || targetResolved.startsWith(sandyaaDir + sep)) {
  console.error(chalk.red('Error: Cannot analyze Sandyaa\'s own directory'));
  process.exit(1);
}
```

### 5.2 全局 CWD 隔离

`ClaudeExecutor.setGlobalTargetPath()`（`agent-executor.ts:52-54`）确保所有 Claude CLI 调用都在目标目录的上下文中运行，从根源上防止 Claude "看到" Sandyaa 自身的源代码。

### 5.3 漏洞目标边界验证

`VulnerabilityDetector` 中的多层边界检查（`vulnerability-detector.ts:316-361, 690-739`）：

1. **正边界**: 漏洞文件必须在目标目录内
2. **负边界**: 不能指向 Sandyaa 自己的文件
3. **已知组件过滤**: 拒绝 `agent-executor`、`context-analyzer` 等 Sandyaa 文件名的发现
4. **工作目录过滤**: 拒绝 `.sandyaa/`、`findings/`、`node_modules/` 等内部目录的发现
5. **POC 文件名过滤**: 拒绝 `poc_*`、`exploit_*` 等模式

### 5.4 行号与代码验证

`validateLineNumber()`（`vulnerability-detector.ts:841-894`）检查：

- 行号是否在文件实际行数范围内
- 如果 LLM 提供了代码片段，验证其是否与实际代码匹配（模糊匹配：提取长度 >3 的关键 token 进行比较）

### 5.5 文件存在性验证

`isWithinTargetBoundary()` 使用 `fs.access()` 验证文件是否真实存在于磁盘。对于不存在的文件，系统尝试通过 `find` 命令按文件名查找真实位置进行自动修正。如果找不到，则拒绝该发现。

文件路径解析使用 `canonicalize()` 函数（`vulnerability-detector.ts:19-26`）追踪符号链接，防止通过符号链接将目标目录外的文件伪装为有效目标。

### 5.6 幻觉拒绝统计

综合来看，一个漏洞候选需要经过以下检查才能到达最终输出：

```
Claude 输出 → 字段存在性 → 类型非泛型 → 位置有效 → 行号有效
→ 代码匹配 → 文件存在 → 边界内 → 攻击者可控(6维验证)
→ 去重 → 严重性过滤 → 可利用性阈值 → ✅ 最终输出
```

这种多层过滤在某些场景下拒绝率极高。例如对 `n8n` 框架的测试中，大量 Claude 推荐的发现因为文件不存在（Claude 虚构了路径）而在 "file on disk" 阶段被拒绝。

---

## 6 实践评估

通过在 service-platform 项目上的实际运行测试，我们对 Sandyaa 两阶段的实际效果进行了评估。

### 6.1 Phase 1 成果

Phase 1 使用 AI 优先级排序，在约 1296 个文件中选择高价值目标进行分析，产生了 5 个高质量的漏洞发现：

| # | 漏洞类型 | 严重性 | 说明 |
|---|---------|--------|------|
| 1 | **权限绕过** | High | 缺少@PreAuthorize 注解的 API 端点 |
| 2 | **RSA 私钥暴露** | Critical | 测试代码中硬编码的私钥 |
| 3 | **XSS 过滤缺陷** | Medium | HTML 标签过滤不完全 |
| 4 | **路径遍历** | Medium | 文件路径拼接未做规范化 |
| 5 | **Druid 监控暴露** | High | 生产环境开启未授权监控接口 |

这 5 个发现全部对应真实存在的安全问题，且提供了具体的文件、行号和攻击路径。与 Semgrep 等其他工具的输出对比，Sandyaa 的发现更接近实际可利用的漏洞而非模式匹配的"噪音"。

### 6.2 Phase 2 JSON 解析缺陷

Phase 2 存在一个严重的实现缺陷——**Claude CLI 输出格式不兼容导致 JSON 解析失败**。

根因分析：

`ClaudeExecutor` 使用 `executeViaCLI()` 方法通过 `--dangerously-skip-permissions --verbose --output-format stream-json` 参数调用 Claude CLI。Claude CLI 的 `stream-json` 输出格式包含工具调用（tool calls）的流式事件，这使得整个输出**不是有效的 JSON 文档**。

当 `ClaudeExecutor` 尝试将输出解析为 `JSON.parse()` 时，`All JSON parsing attempts failed` 错误持续出现。系统降级为 `output: null`，导致 `VulnerabilityDetector` 输出 `[]`（空数组），表现为"未发现漏洞"。

这是典型的**传输层与业务层协议不匹配**的问题——Claude CLI 的 `stream-json` 格式产生的是 NDJSON 或事件流，而非单一的 JSON 对象。这种格式差异在简单任务（如文件优先级排序的 JSON 结构较为扁平）中不暴露，但在复杂嵌套输出的漏洞检测任务中必然触发。

解决方案应改为使用 Claude CLI 的 `--output-format text` 模式配合结构化提示词（要求 Claude 输出严格 JSON 代码块），或者实现 NDJSON 流解析器逐个提取消息内容。

### 6.3 整体评估

| 维度 | 评分 | 说明 |
|------|------|------|
| Phase 1 发现质量 | ★★★★★ | 精准、具体、可操作 |
| 架构设计 | ★★★★☆ | 两阶段+RLM+递归设计先进 |
| 幻觉防御 | ★★★★☆ | 多层边界验证，行业领先 |
| Phase 2 可靠性 | ★☆☆☆☆ | JSON 解析导致全量失败 |
| 安装与运行 | ★★☆☆☆ | 依赖 npx/claude CLI，配置复杂 |
| 性能 | ★★★☆☆ | 1296 文件 Phase 1 耗时 10+ 分钟 |
| 社区活跃度 | ★☆☆☆☆ | 23 stars，无外部贡献 |

---

## 7 与同类工具的对比

| 特性 | Sandyaa | testx | Semgrep | CodeQL | Snyk Code |
|------|---------|-------|---------|--------|-----------|
| 分析引擎 | LLM 驱动 | AST+LLM 混合 | 模式匹配 | 查询语言+DB | LLM+规则 |
| 跨文件分析 | ✓ (调用链追踪) | ✗ (单文件扫描) | ✗ (单文件模式) | ✓ (数据流) | 有限 |
| 攻击者可控验证 | ✓ (六维验证) | ✗ | ✗ | ✗ (仅数据流) | ✗ |
| 递归验证 | ✓ (8种策略) | ✗ | ✗ | ✗ | ✗ |
| 幻觉防御 | ✓ (多层检查) | ✗ | N/A (无幻觉) | N/A (确定性) | 有限 |
| POC 生成 | ✓ (带验证) | ✗ | ✗ | ✗ | ✗ |
| 利用链分析 | ✓ (GOD-LEVEL) | ✗ | ✗ | ✗ | ✗ |
| 回归检测 | ✓ (git 历史) | ✗ | ✗ | ✗ | ✗ |
| 影响范围计算 | ✓ (Blast Radius) | ✗ | ✗ | ✓ (部分) | ✗ |
| 多模型切换 | ✓ (Claude+Gemini) | ✗ (单模型) | N/A | N/A | N/A |
| 语言覆盖 | 9种语言 | Python 优先 | 多语言 | 多语言 | 多语言 |
| 误报率 | 低 (受幻觉防御) | 高 (纯AST模式) | 中 (需定制规则) | 低 (精确查询) | 中 |

Sandyaa 在**分析深度**上远超所有对比工具，但在**可靠性**（Phase 2 的 JSON 缺陷）和**成熟度**上明显不足。其最大价值在于验证了"AI 递归验证 + 多层幻觉防御"的技术路线可行性，而非作为一个即用型工具。

---

## 8 总结与展望

### 8.1 核心发现

Sandyaa 是一个技术上令人印象深刻的项目，其创新密度在同类开源工具中罕见：

1. **AI Native 设计**: 不是"用 LLM 辅助审计"，而是将 LLM 作为审计引擎的核心，从头设计了一套完整的流水线
2. **递归验证框架**: 8 种递归策略构成了已知最完整的 LLM 审计验证体系
3. **幻觉防御系统**: 多层边界验证 + 跨模型矛盾检测 + 代码存在性检查的组合，大幅降低了 LLM 幻觉对审计结果的影响
4. **语言无关的攻击者分析**: 一套可扩展到多种编程语言的验证流水线，将安全专家的思维过程编码为可执行规则

### 8.2 主要缺陷

1. **JSON 解析缺陷**: Phase 2 完全不可用，是当前版本最大的问題
2. **安装复杂性**: 依赖 `npx` 和 Claude CLI，对 CL étudé API 的无直接可用性
3. **性能瓶颈**: 1296 文件的 Phase 1 需要 10+ 分钟，大项目实用性受限
4. **配置负担**: 需要手动配置 `.sandyaa/config.yaml`，无引导式初始化

### 8.3 未来展望

如果 JSON 解析缺陷得到修复，Sandyaa 有潜力成为 AI 驱动代码审计的重要参考实现。其递归验证 + 幻觉防御的设计思路可能被更成熟的商业工具吸收。特别是 SecureLayer7 作为安全服务公司的背景，使得 Sandyaa 的实战导向设计在学术研究和工业应用之间架起了一座桥梁。

从更宏观的角度看，Sandyaa 证明了：**LLM 驱动的自动化审计不应只是"把代码扔给 GPT"，而应是一套包含验证、反驳、追溯和修正的闭环系统**。这正是 Sandyaa 留下的最重要遗产。

---

## 参考文献

1. MIT CSAIL. *Recursive Language Model*. arXiv:2512.24601. 2025.
2. SecureLayer7. *Sandyaa: Autonomous Security Bug Hunter*. https://github.com/securelayer7/sandyaa. 2026.
3. SecureLayer7. *Announcing Sandyaa*. https://blog.securelayer7.net/announcing-sandyaa/. April 2026.
4. OWASP. *OWASP Top Ten Web Application Security Risks*. 2021.
5. Johnson, B. et al. *CodeQL: Semantic Code Analysis*. PLDI 2019.
6. Pearce, H. et al. *Virtual Patching of AI-Generated Code with LLM-Generated Signatures*. IEEE S&P 2024.

---

*本文基于 2026 年 5 月对 sandyaa 代码库（最新提交 2026-04-14）的分析。所有代码引用均来自 sandyaa 主分支。*
