# agies v3 — 基于静态调用链的漏洞发现（修订版）

> 规划日期：2026-06-02（修订）
> 原版：2026-05-30（基于 Joern 数据流图 + 三层剪枝）
> 修订版核心变化：
>   - 废弃 Joern 全量数据流图（PDG/DDG）方案 — RAM 消耗 GB 级，对漏洞发现增益有限
>   - 改用 **CodeQL source→sink 查询** 生成精确调用路径
>   - 新增 **切片排序引擎** — 路径按风险评分排序，Top K 喂 LLM
>   - 引入 **VulnHuntr 风格专项 prompt** — 每种漏洞类型有独立分析指引 + bypass 示例
>   - **并行 LLM Agent** — 多条路径同时分析，复用 agies 现有 runner
>
> ### op.md 驱动的修订记录（2026-06-03）
>
> 以下修订源自对 op.md（Huntr 实战策略文档）的技术批评分析：
>
> | 意见来源 | 意见 | 修订位置 | 修正确认 |
> |---------|------|---------|---------|
> | op.md 第 1 轮 | 编译屏障 — Java 建库成功率低 | 发现 6 | ✅ 第一阶段聚焦 Python/JS/TS |
> | op.md 第 1 轮 | Sanitizer 降权 (`score *= 0.5`) 漏掉高价值 bypass | 排序指标 | ✅ 改为 `score += 0.2` + 标记 [BYPASS_TARGET] |
> | op.md 第 1 轮 | 动态类型断流导致 CodeQL 路径为 0 | 回退方案 | ✅ 增加 tree-sitter 局部后向追踪 |
> | op.md 第 1 轮 | 缺乏动态 PoC 沙箱验证 | Phase F.5 | ✅ 新增 `--sandbox-verify` 可选步骤 |
> | 架构讨论 | 评分模型确认偏误 — 非标准 sink 被结构性过滤 | Top K 策略 | ✅ Explore/Exploit 分离（25+5 槽位） |
> | op.md 第 2 轮 | CPRVul 结构化推理 — 4 步推理链提升跨函数逻辑审查 | Phase D prompt | ✅ 替换 build_agent_prompt 为 Structured Reasoning |
> | 架构讨论 | LLM 发现项目特有 sink → 动态追加 CodeQL 查询 | Phase A' | ✅ 新增 Phase A'（非标准 sink 自动发现） |
> | 架构讨论 | 并行 Intent Agent + Merge + Logic Agent 替代单 Agent | Phase D | ✅ 三阶段 Agent 池（注意力隔离 + 矛盾检测） |
> | op.md 第 2 轮 | 验证 v3 架构方向与学术界 SOTA 一致 | 整体 | ✅ 方向确认，无需修改 |
>
> 详见 `docs/v3/revisions_from_op.md`。

---

## 背景

### v2 做了什么

v2 完成了图生成层的可插拔架构（Joern CPG / tree-sitter）和 xint 风格的批量分析管线，在 zipp CVE-2024-5569 上验证了有效性。

### 原 v3 方案的问题

原方案（2026-05-30）计划用 Joern 的数据流图（PDG/DDG）做全量数据流分析，实际测试发现：

| 工具 | 产物 | 大小 | RAM |
|------|------|------|-----|
| joern-parse | CPG（调用图） | 几 MB | 低 |
| joern-export --repr=all | PDG + DDG + AST 全图层 | **几 GB** | **极高** |

问题本质：Joern 的数据流图是做程序全量 def-use 传递闭包，对漏洞发现来说，95% 的数据流边与安全无关。为 5% 的有用路径付出 GB 级代价不划算。

### 新方案的核心思路

用 **CodeQL source→sink 查询** 替代 Joern 全量数据流图：

```
CodeQL 查询: "从 HTTP 请求参数到 exec/eval/pickle 等危险 sink 的所有路径"
         ↓
    只返回有安全含义的路径，而不是全量数据流
         ↓
    但路径数仍然可能达到几百上千条（取决于项目规模和查询精度）
         ↓
    需要切片引擎做二次筛选排序
```

关键区别：Joern 的问题是"图大到没法处理"（GB 级），CodeQL 的问题是"路径太多需要排序挑选"（MB 级但可能有几百条）。**两者都需要剪枝，但剪枝的粒度不同。**

---

## 分析发现与确定性结论

### 发现 1：Joern 数据流图不适合漏洞发现

Joern 的 PDG/DDG（`joern-export --repr=all`）生成的是程序全量 def-use 传递闭包。在一个中等 Java 项目上：

- CPG（调用图）：几 MB，可用
- PDG/DDG（数据流图）：**几 GB**，解析耗时数分钟
- 其中 95%+ 的数据流边与安全分析无关（局部变量赋值、中间结果传递等）

**结论**：Joern CPG 适合做精确调用链解析（保留），但 PDG/DDG 不适合做安全分析的数据流基准。改用 CodeQL source→sink 查询，只返回有安全含义的路径。

### 发现 2：CodeQL 路径是"剪枝后的正确粒度"

CodeQL source→sink 查询在这个场景下有三个优点：

1. **只返回安全相关的路径** — 不是全量数据流，只匹配 source→sink 模式
2. **路径是跨函数的完整链路** — 比 tree-sitter 单函数 SAST 更完整，比 Joern PDG 更轻量
3. **每条路径是独立分析单元** — 天然可并行

一个关键认知修正：**原版 plan.md 说"CodeQL 不需要剪枝"是错误的。** CodeQL 路径仍然需要筛选排序（几百条压缩到 Top 15-30），但剪枝的对象从"全量图节点"变成了"source→sink 路径列表"。

### 发现 3：vulnhuntr 的竞争力不在架构而在 prompt

vulnhuntr（~900 行）能挖到多个 0day，核心原因不是架构设计，而是：

| vulnhuntr 真正强的地方 | 可移植性 |
|------------------------|---------|
| 7 类漏洞专项 prompt + bypass 示例 | **直接复制文本，零成本** |
| LLM 自主引导上下文获取 | 可以学习思路但不必须（CodeQL 替 LLM 找路径） |
| README 总结 → 注入上下文 | 1 次 LLM 调用 |
| 置信度评分自动过滤 | 设计简单，直接复制 |

**结论**：vulnhuntr 的核心资产是 prompt 文本，直接移植。架构层面 agies v3 的设计（CodeQL 穷举 + 并行 LLM + 验证）理论上更优。

### 发现 4：并行路径分析在架构上没有障碍

每一条 CodeQL source→sink 路径是自包含的分析单元：

- 路径上的函数代码可以独立打包，不需要看其他路径的信息
- 多条路径之间没有共享状态（不需要加锁、不需要同步）
- LLM 对每条路径的分析互不影响

因此天然可并行，只需要控制 API 速率。复用 agies 现有的 `runner.py`（ThreadPoolExecutor）即可，`--workers N` 控制并发数。

### 发现 5：函数提取已有现成基础设施

agies 的 `engine/v2/sourcer/extractor.py` 已经能实现：
- 给定文件路径 + 行号 → 用 tree-sitter 定位该行所在的函数
- 提取函数名、起始行、结束行、完整 body

CodeQL 路径的每个节点包含 `(file_path, line_number)`，正好是 extractor 的输入。

**结论**：不需要造"提取函数"的轮子。需要新增的是**组装层**——把 CodeQL 输出的坐标列表转成 extractor 的输入，再把拿到的函数代码拼接成 LLM 的 prompt。

### 发现 6：编译屏障 — CodeQL 自动化的实际死穴

CodeQL `database create` 在编译型语言上存在严重的成功率问题：

| 语言 | 建库方式 | 实战成功率 | 原因 |
|------|---------|-----------|------|
| Python/JS/TS | 纯静态解析，零依赖 | ~100% | 不需要编译 |
| Go | `go build` 拦截 | 高 | 依赖模型简单 |
| Java | `mvn`/`gradle` 拦截 | **中低** | JDK 版本、私有仓库、奇葩插件 |
| C++/C# | `make`/`dotnet build` 拦截 | **低** | 环境依赖极其复杂 |

**实战决策**：第一阶段 100% 聚焦 Python/JS/TS。Java/C++ 项目作为理论支持目标，在 CodeQL 基础设施成熟后再扩展。

---

## 整体架构

```
源码
  │
  ▼
CodeQL 数据库构建（codeql database create）
  │
  ▼
Phase A: CodeQL 路径生成 ─── 预定义的 7 类 source→sink 查询
  │    输出: 基础路径列表（已知 sink 模式）
  │
  ▼
Phase A': 动态 Sink 发现 ─── LLM 读项目代码，发现项目特有、非标准的 sink
  │  Step 1: 快速扫描项目 import + 核心 API
  │  Step 2: LLM 推断可能构成 sink 的函数
  │  Step 3: 追加到 CodeQL 查询定义，重新查询
  │    输出: 新增路径（非标准 sink 的路径，7 类查询找不到的）
  │
  ▼
Phase B: 路径切片与混合筛选
  │  Step 1: 静态粗筛（sink权重 × 长度 × 文件排除）→ Top 50
  │  Step 2: LLM 微选（可选，看路径摘要做语义过滤）→ Top 15-30
  │    输出: 排序后的路径切片列表
  │
  ▼
Phase C: README 理解 ─── 1 次 LLM 调用，注入项目上下文
  │
  ▼
Phase D: 并行意图提取 + 矛盾检测（全新设计）
  │  Step 1: PathCodeLoader 将路径上的函数分组
  │  Step 2: N 个 Intent Agent 并行，每个分析 4-5 个函数
  │          输出: 每个函数的"开发者意图"伪代码
  │  Step 3: Merge Agent（确定性排列，轻量检查）
  │          输出: 完整伪代码链（原始代码的 10-20% token 量）
  │  Step 4: Logic Agent 读伪代码链 → 发现意图与实现之间的矛盾
  │  Step 5: 黑板缓存（同一函数多次出现只 Intent 一次）
  │
  ▼
Phase E: 黑板聚合 ─── 并行 agent 的知识交叉注入
  │
  ▼
Phase F: 验证与报告 ─── Verification Agent + Report
```

与 vulnhuntr 的核心差异：

```
vulnhuntr: LLM 自己找路径（可能有遗漏）→ 迭代获取上下文
v3:       CodeQL 穷举所有路径 → 切片排序 → LLM 只做判断
           ↑ 确定性覆盖        ↑ 聚焦高价值    ↑ token 更省、更快

### v2 黑板记忆为什么没出现在 v3 架构中

v2 有一个关键设计：**黑板记忆**（`state.discovered_logic`）。

```
Agent A 分析 function X → 发现 "X 调用了 exec，且没有输入校验"
                         → 调用 record_knowledge("X", "调用了 exec，无校验")
                            ↓
Agent B 分析 function X → Brain 检测到 X 有黑板记录
                         → 在 Agent B 的 prompt 注入 [PRIOR_KNOWLEDGE]
```

作用：跨 agent 知识共享——不同 agent 在分析过程中发现的关于同一个函数/文件的信息，可以被后续 agent 复用。

**为什么没出现在 v3 架构中**：v2 的 agent 是**串行执行**的（mapping → attack_surface → dataflow → vulnerability → verify），Brain 在调度下一个 agent 前检查黑板并注入，天然适合。v3 的 Phase D 是**并行执行**的，agent 同时跑，没有"前一个 agent 写、后一个 agent 读"的时序保证。

**但这不代表黑板记忆在 v3 没用，而是需要换一个位置放。**
```

---

## Phase A: CodeQL 路径生成

### 取代什么

| 原 v3 方案 | 新 v3 方案 |
|-----------|-----------|
| Joern PDG/DDG 全量导出（GB 级） | CodeQL source→sink 查询（MB 级） |
| 三层图剪枝（FileLevel + Origin + Reachability） | 切片排序（Phase B）— 作用对象从"图"变成"路径列表" |
| DataFlowTracer 符号执行 | CodeQL 数据流引擎（生产级精度） |

### CodeQL 查询设计

每种漏洞类型对应一个 QL 查询：

```ql
/**
 * @name RCE via user input
 * @kind pathProblem
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.ExecutionSink

class RceConfig extends TaintTracking::Configuration {
  RceConfig() { this = "RceConfig" }
  override predicate isSource(RemoteFlowSource source) { source instanceof RemoteFlowSource }
  override predicate isSink(Node sink) { sink instanceof ExecCallSink }
}

from RceConfig cfg, RemoteFlowSource source, ExecCallSink sink
select cfg, source, sink
```

预定义 7 类查询（对应 vulnhuntr 的 7 种漏洞类型）：

| 漏洞类型 | Source | Sink |
|---------|--------|------|
| RCE | RemoteFlowSource | exec/eval/subprocess/ProcessBuilder |
| LFI | RemoteFlowSource | FileOpen/FileRead/FileAccess |
| SSRF | RemoteFlowSource | HttpRequest/UrlConnection |
| SQLI | RemoteFlowSource | QueryExecution/DatabaseAccess |
| XSS | RemoteFlowSource | ResponseWrite/Output |
| AFO | RemoteFlowSource | FileWrite/FileCreate |
| IDOR | RemoteFlowSource | DirectObjectReference |

### 多语言支持

| 语言 | CodeQL 支持 | 状态 |
|------|------------|------|
| Java/Kotlin | 官方包 `java/` `java/ql/lib/semmle/code/java/dataflow/FlowSources` | ✅ 正式 |
| JavaScript/TypeScript | 官方包 `javascript/` | ✅ 正式 |
| Python | 官方包 `python/` | ✅ 正式 |
| C/C++ | 官方包 `cpp/` | ✅ 正式 |
| Go | 官方包 `go/` | ✅ 正式 |
| Ruby | 官方包 `ruby/` | ✅ 正式 |
| C# | 官方包 `csharp/` | ✅ 正式 |

### 回退方案：tree-sitter SAST

当 CodeQL 不可用时，回退到 v2 的 tree-sitter SAST + 函数索引：

| 回退触发条件 | 回退路径 |
|------------|---------|
| CodeQL 未安装/无数据库 | v2 完整管线（SAST → bulk → verification） |
| CodeQL 路径数为 0（动态类型断流） | **局部后向追踪**：tree-sitter 定位所有危险 sink → LLM 局部向后检索补全调用路径 |
| CodeQL 路径数 < 阈值 | v3 管线降级（不切片，全部送分析） |

动态类型断流的典型场景：

```python
# Python: getattr 动态调用 — CodeQL 无法追踪
method = getattr(obj, user_input)
method()  # CodeQL 看不到这里调用了什么

# JS: 动态属性读取 — CodeQL 断流
const handler = obj[key]  # key 来自用户输入
handler(data)
```

回退路径示意：

```
tree-sitter SAST (13 信号) → Director 打分 → 单函数 bulk → verification
```

---

## Phase A': 动态 Sink 发现（LLM 驱动的非标准 sink 检测）

### 为什么要这一层

7 类预定义 CodeQL 查询只能覆盖已知的 sink 模式。但真实世界的大量漏洞来自**项目特有的、非标准库的自定义函数**：

```python
# 7 类查询找不到这个 sink:
class DataExporter:
    def export(self, data, filename):
        # data 是用户传入的，filename 也是
        # 内部调用了 subprocess.call 或 os.system
        # 但 CodeQL 不认识 DataExporter.export 是 sink
        pass

# 或者这个:
class ModelEvaluator:
    def score(self, model_path, samples):
        # model_path 来自用户上传
        result = subprocess.check_output(f"python score.py {model_path}", shell=True)
        return result
```

`DataExporter.export` 和 `ModelEvaluator.score` 函数名里不包含 `exec`/`eval`/`subprocess`，但内部调用了危险操作。**LLM 读代码能识别出这是 sink，但 CodeQL 不认识。**

### 设计

```
Phase A 基础查询（7 类已知 sink）
  │  输出: 基础路径
  │
  ▼
Phase A' — 动态 Sink 发现

  Step 1: 项目快速扫描（1 次 LLM 调用）
    Input: 项目 import 列表 + 前 20 个最常被调用的函数签名
    Task: "识别项目中所有可能构成安全 sink 的自定义函数"
    Output:
      [
        {"function": "DataExporter.export", "reason": "内部调用了 subprocess"},
        {"function": "ModelEvaluator.score", "reason": "shell=True + 用户输入"},
        {"function": "ConfigLoader.load", "reason": "yaml.load + 用户上传"}
      ]

  Step 2: 动态追加 CodeQL 查询
    把 Step 1 的输出转为 QL 查询定义:
      sink DataExporter.export  → 追加到 RCE sink
      sink ModelEvaluator.score → 追加到 RCE sink
      sink ConfigLoader.load    → 追加到反序列化 sink

  Step 3: 增量查询
    只跑新增的 sink 查询（不需要重建 database）
    Output: 新增路径列表

  Step 4: 合并
    基础路径 + 新增路径 → 送 Phase B 统一排序
```

### 不是让 LLM 写 QL，是让 LLM 定义 sink

关键区别：

| 方案 | LLM 的任务 | 技术难度 | 可靠性 |
|------|-----------|---------|--------|
| ❌ LLM 写完整 QL 查询 | 生成 Datalog 代码 | 高（QL 语法复杂） | 低 |
| ✅ LLM 发现 sink + 参数 | 读代码发现可疑函数签名 | 低（LLM 擅长这个） | 高 |

LLM 的输出不是 QL 代码，而是一个 sink 定义列表：

```json
[
  {
    "sink_name": "DataExporter.export",
    "file_path": "src/exporters/data_exporter.py",
    "vuln_type": "RCE",
    "sink_param": "command",
    "reason": "内部调用了 subprocess.call(command, shell=True) 且 command 是用户可控的"
  }
]
```

这个结构可以直接映射到 CodeQL 查询模板，不需要 LLM 懂 QL 语法。

### 与 v3 现有设计的关系

```
Phase A → Phase A' → Phase B → Phase C → Phase D → Phase E → Phase F

不冲突:
  Phase A 跑基础 7 类 → 覆盖已知模式
  Phase A' 跑新增 sink → 覆盖项目特有模式
  两者合并送 Phase B → 统一排序

代价:
  1 次 LLM 调用（项目扫描）+ 1 次 CodeQL 增量查询
  ~2000 tokens + 几秒到几分钟
  几乎可忽略
```

### 与黑板的关系

Phase A' 发现的 sink 定义也写入黑板。如果后续其他路径经过这些 sink，Logic Agent 可以直接引用"这是一个动态发现的 sink"。

### 成本

```
1 次 LLM 调用（扫描项目 import + 核心函数）:
  ~2000 tokens input
  ~500 tokens output
  DeepSeek: ~$0.001

1 次 CodeQL 增量查询:
  几秒到几十秒（取决于新增 sink 的路径数）
  无 token 成本
```

---

## Phase B: 路径切片与排序

### 问题

CodeQL 可能返回大量路径。一个中等 Java 项目可能有数百到数千条 source→sink 路径，全部送 LLM 成本太高且大部分是误报。

### 选择策略：静态 + LLM 混合筛选

路径选择是整个管线中唯一需要做"剪枝决策"的地方。有三种选择：

| 方式 | 做法 | 成本 | 覆盖完整性 |
|------|------|------|-----------|
| **纯静态打分** | 规则打分取 Top K | 零（毫秒级） | 可能漏"危险但得分不高"的 |
| **纯 LLM 选择** | 给 LLM 看路径摘要让它挑 | 1 次 LLM 调用 | 依赖 LLM 判断力，可能漏 |
| **混合（推荐）** | 静态粗筛 → LLM 微选 | 几乎零 + 1 次简短 LLM | 双重保障 |

推荐混合方式：

```
CodeQL 路径 (几百条)
  │
  ▼ Step 1: 静态粗筛
  │   sink 权重 × 长度惩罚 × 文件排除 (test/gen) → 排序
  │
  Top 50（规则保底，不依赖 LLM）
  │
  ▼ Step 2: LLM 语义过滤（可选）
  │   LLM 看每条路径的一句话摘要:
  │   "RCE: request.getParameter → Helper.parse → exec (路径完整, 无校验)"
  │   "LFI: request.getParameter → FileReader.read (路径完整, 但经过 PathValidation.sanitize)"
  │   LLM 选出最可疑的 Top K
  │
  Top 30 分析配额
  │
  ├── Exploit 25 条 ← 按 score_path() 排序
  │    目的: 确认已知 sink 模式的漏洞（高概率中）
  │
  └── Explore 5 条 ← is_anomalous() 筛选
       目的: 发现非标准 sink 的漏洞（低概率高回报）
       选入条件: sink 不在预定义列表 / 路径包含非常见命名函数 /
                跨模块边界多 / 平均函数行数大
       配额不足时从 Exploit 候选池补满
  │
  ▼ Step 3: 全量分析
  │   每条路径的完整代码 + 对应漏洞 prompt + bypass → LLM Agent
```

为什么两步筛选 + Explore/Exploit 分离：

- **静态粗筛**保证不遗漏——即使 LLM 判断失误，规则层的 Top 50 已经保留了最有价值的路径
- **LLM 微选**用一次简短调用（几百 token 的路径摘要，不需要看代码）做语义判断，省掉的是几十条误报路径的全量分析（几千 token × N 条）
- **默认情况下可以先跳过 LLM 微选**（直接静态 Top K），只有在路径数超阈值时启用
- **Explore/Exploit 分离**解决"确认偏误"问题：Exploit 槽最大化已知模式的命中率，Explore 槽专门筛选"反常路径"让 LLM 发现非标准 sink

### 排序指标

```python
def score_path(path: CodeQlPath) -> float:
    """
    路径风险评分 (0-1)，用于排序和 Top K 选择。
    """
    score = 0.0

    # 1. Sink 危险度权重
    sink_weights = {
        "exec": 1.0, "eval": 1.0,
        "subprocess.call": 1.0, "subprocess.Popen": 1.0,
        "Runtime.exec": 1.0, "ProcessBuilder": 0.9,
        "pickle.loads": 0.9, "yaml.load": 0.9,
        "os.system": 1.0, "os.popen": 1.0,
        "open": 0.6, "file": 0.5,
        "requests.get": 0.5, "urllib.request": 0.5,
        "executeQuery": 0.8, "executeUpdate": 0.8,
    }
    score += sink_weights.get(path.sink_name, 0.3) * 0.4

    # 2. 路径长度惩罚 — 太长的路径利用性降低
    length_penalty = 1.0 / (1.0 + 0.1 * max(0, len(path.nodes) - 3))
    score += length_penalty * 0.2

    # 3. 校验函数标记 — 路径经过 sanitize/validate 不降权，反而标记为高 bypass 潜力
    #    高价值 0-day 往往是"写了校验但写错了"（sanitizer bypass），不是"没写校验"
    has_validation = any("sanitize" in n or "validate" in n or "escape" in n
                         for n in path.nodes)
    if has_validation:
        score += 0.2  # bypass 潜力加分

    # 4. 路径完整性奖励 — 完整路径（无断点）加分
    if path.is_full_path:
        score += 0.15

    return min(score, 1.0)
```

### Top K 选择策略

```
Step 1: 静态粗筛
  排除: 路径在 test/gen 目录 → 直接丢弃
  打分: 按排序指标算分排序
  标记: 经过 sanitize/validate/escape 函数的路径 → 标记为 [BYPASS_TARGET]
       这些路径不降权，优先进入 Top K
  结果: Top 50 = Exploit 候选池（硬限制，CLI 参数 --max-path-candidates）

Step 2: LLM 微选（可选，默认关闭）
  触发条件: Top 50 中同一 sink 类型超过 5 条时启用
  做法: LLM 看每条路径的一句话摘要，选出 Top 15-30
  跳过: 如果 Top 50 中已经少于 30 条，直接跳过此步

Step 3: Explore/Exploit 分离
  分配规则:
    Exploit 25 条 ← 按 score_path() 在候选池中排序取前 25
    Explore 5 条  ← 从候选池中按 is_anomalous() 筛选
                    若反常路径不足 5 条，从 Exploit 候选区补满

  这样确保:
    - 已知高危模式（高评分热门路径）不会漏
    - 非标准 sink（低评分但可能高危）不会被评分模型过滤掉
```

K 值可配：`--max-paths`（默认 30），Explore 槽位 `--explore-slots`（默认 5）。

### Explore 筛选逻辑

提交给 LLM 的 Explore 槽路径使用与 Exploit 相同的 prompt 模板，但 LLM 在分析时会被显式要求先评估"这条路径上的函数是否构成非标准 sink"，再做漏洞确认。

```python
def is_anomalous(path: CodeQlPath) -> list[str]:
    """
    判断一条路径是否"反常"——反常 = 值得 LLM 看一眼。
    返回反常原因列表，空列表 = 不反常。
    """
    reasons = []

    # 1. 最终 sink 不在预定义 sink 列表中（非标准 sink）
    if path.sink_name not in KNOWN_SINKS:
        reasons.append("non_std_sink")

    # 2. 路径上的函数平均体量异常大（复杂自研逻辑）
    if avg_function_lines(path) > 100:
        reasons.append("complex_custom_logic")

    # 3. 路径上的函数名不常见（不是 get/set/parse/validate 等）
    if has_unusual_function_names(path):
        reasons.append("unusual_naming")

    # 4. 路径跨越了异常多的模块边界
    if cross_module_count(path) > 3:
        reasons.append("multi_module_flow")

    return reasons


def select_explore_slots(candidates: list[CodeQlPath], slots: int = 5) -> list[CodeQlPath]:
    """从候选池中选出最反常的路径。"""
    scored = []
    for path in candidates:
        reasons = is_anomalous(path)
        if reasons:
            scored.append((len(reasons), path))
    scored.sort(key=lambda x: -x[0])
    selected = [p for _, p in scored[:slots]]
    return selected
```

### 切片格式

```python
@dataclass
class PathSlice:
    """一条待分析的 source→sink 路径切片。"""
    id: str                                  # "rce-001"
    vuln_type: VulnType                      # RCE / LFI / SSRF / ...
    source: str                              # "request.getParameter"
    source_file: str                         # "Controller.java:42"
    sink: str                                # "exec"
    sink_file: str                           # "Util.java:120"
    nodes: list[PathNode]                    # 路径上的所有函数
    code_block: str                          # 路径上所有函数的代码（打包）
    confidence: float                        # 排序评分
    is_full_path: bool                       # CodeQL 是否找到完整路径
```

---

## Phase C: README 理解（VulnHuntr 借鉴）

在送路径给 LLM 之前，先花 1 次 LLM 调用总结项目 README：

```
读取 README.md → LLM 总结：项目做什么、有哪些网络入口、认证方式
                → 注入 system prompt → 后续所有路径分析共享这个上下文
```

效果：LLM 知道这是一个 API 服务器还是 CLI 工具，判断路径利用性时更有依据。

成本：1 次 LLM 调用。

---

## Phase D: 并行意图提取 + 矛盾检测（全新设计）

### 设计哲学

v3 plan 原有 Phase D 设计是"一条路径 → 一个 LLM Agent → 分析结果"。这个设计有两个未解决的根本问题：

**问题 1 — 注意力稀释**：一条 10-20 跳的路径，把所有函数代码拼接后可能 4000-8000 tokens。LLM 需要同时做三件事——理解每个函数的意图、追踪数据流、判断逻辑错误——注意力在长上下文中被稀释，核心细节被模板代码和日志淹没。

**问题 2 — 确认偏误**：prompt 引导 LLM 做"确认已知漏洞类型"的判断，它不会主动发现非标准 sink 或逻辑矛盾。

**新设计的核心洞察**：安全研究员的工作方式不是一次性读完整条调用链。而是：
1. 先快速翻阅每个函数的意图（"这个函数在做什么？"）
2. 再回到调用链上找矛盾（"这里说的和做的不一样"）

将这个过程拆成两个可并行的步骤——**Intent Agent（读代码→转意图）** 和 **Logic Agent（找矛盾）**——各自只做 LLM 最擅长的事。

### 设计优势

| 维度 | 旧设计（单 Agent 分析路径） | 新设计（并行 Intent + Logic） |
|------|-------------------------|-----------------------------|
| 注意力 | 1 个 LLM 处理整条路径（~4000 tokens） | 每个 Intent Agent 只处理 4-5 个函数（~800 tokens） |
| 并行度 | 按路径并行（30 条路径 = 30 Agent） | 按路径 × 按节点并行（30 条路径 × 4 = 120 Agent） |
| LLM 任务 | 读代码 + 判断漏洞 → 做两件都不熟练的事 | 读代码转意图 → 意图 + 找矛盾 → 各做一件擅长的事 |
| token 成本 | 随路径长度线性增长 | Intent 固定成本/Agent，越长的路径节省越明显 |
| 黑板缓存 | 只能缓存最终结论 | 缓存 Intent 结果（同一函数跨路径共享） |
| 确定性 | CodeQL 提供路径骨架 | CodeQL 路径骨架 + Intent 结果 + Merge 确定性排列 |

**token 成本对比**：

| 路径长度 | 旧方案 | 新方案 | 节省 |
|---------|-------|-------|------|
| 8 函数（平均） | 1 Intent × 4000 = 4000 | 2 Intent × 1000 + Logic 500 = **2500** | **-38%** |
| 40 函数（长） | 1 Intent × 20000 = 20000 | 10 Intent × 1000 + Logic 500 = **10500** | **-48%** |
| 80 函数（极长） | 1 Intent × 40000 = 40000 | 20 Intent × 1000 + Merge 200 + Logic 500 = **20700** | **-48%** |

### 核心机制

```
PathSlice 列表（30 条）
  │
  ▼
PathCodeLoader（增强版）
  │  把路径上的函数分组，每 4-5 个函数一组
  │  检查黑板缓存：哪些函数已有 Intent 结果？
  ▼
Intent Agent 池（并行，workers=N）
  ├── Agent 1: func[0-4]  → 伪代码: "提取 file 参数，拼接路径"
  ├── Agent 2: func[5-9]  → 伪代码: "replace(\"..\",\"\") 过滤，只做一次"
  ├── Agent 3: func[10-14] → 伪代码: "检查 role 权限，拼接完整路径"
  └── Agent 4: func[15-19] → 伪代码: "open 文件，返回内容"
      │
      ↓  (每 Agent 输出 50-100 tokens 伪代码)
  ▼
黑板缓存（关键）
  │  validatePath 在 3 条路径中都出现
  │  → 只在第 1 次执行 Intent Agent
  │  → 后 2 次直接从黑板读取 Intent 结果
  ▼
Merge 层（确定性，无需 LLM）
  │  按 CodeQL 节点序号排列 Intent 输出
  │  得到完整的伪代码调用链（原始代码的 10-20% token 量）
  ▼
Logic Agent（并行，每个 PathSlice 一个）
  │  输入: 伪代码调用链（500-1000 tokens）
  │  任务: 找"意图与实现之间的矛盾"
  │  - "这里说校验了，但实际 replace 只做一次"
  │  - "这里调用了 sanitize，但校验逻辑不完整"
  │  - "默认 mode=unsafe，条件检查形同虚设"
  ▼
结果合并 → Phase E
```

### 路径代码加载器（PathCodeLoader — 增强版）

增强点：不再把所有函数等权重拼接，而是**分组**给 Intent Agent。

```python
class PathCodeLoader:
    """把 CodeQL 路径坐标分组分发给 Intent Agent 池。"""

    def __init__(self, project_path: str, blackboard: BlackboardAggregator):
        self.extractor = FunctionExtractor(project_path)
        self.blackboard = blackboard

    def prepare_intent_batch(self, path: CodeQlPath) -> tuple[list[IntentTask], list[IntentResult]]:
        """
        返回: (需要执行 Intent 的任务列表, 已缓存的 Intent 结果列表)
        """
        tasks = []
        cached = []
        for i, node in enumerate(path.nodes):
            func = self.extractor.get_function_at_line(
                node.file_path, node.line_number
            )
            cached_intent = self.blackboard.get_intent(func.name, func.file_path)
            if cached_intent:
                cached.append(IntentResult(node_id=i, intent=cached_intent))
            else:
                tasks.append(IntentTask(
                    node_id=i,
                    func_name=func.name,
                    file_path=func.file_path,
                    line_start=func.line_start,
                    line_end=func.line_end,
                    code=func.body,
                ))
        # 每 4-5 个任务合并为一个 Intent Agent 任务
        return self._group_tasks(tasks), cached
```

回退方案（extractor 找不到函数时）：用 `read_file` 工具读取前后 30 行上下文。

### Intent Agent：读代码 → 转意图

**职责**：每个 Intent Agent 只接收 4-5 个函数的代码。它不做任何安全判断，只回答问题——"这个函数在做什么？"

```python
INTENT_AGENT_PROMPT = """
项目上下文：{readme_summary}

分析以下 {count} 个函数在调用链中的角色。不要做安全判断，只描述"开发者意图"。

{functions}

对每个函数，输出格式:
```
func_{id} ({name}):
  意图: [这个函数在做什么？用一句话说清楚]
  输入: [接收什么数据？来源是谁？]
  输出: [返回什么？给谁用？]
  关键逻辑: [核心操作，特别关注: replace/regex/if-check/权限判断/数据变换]
  可疑点: [你直觉上觉得奇怪的地方，但不要下结论]
```
"""
```

**Intent Agent 的输出示例**（4-5 个函数处理后）：

```
func_2 (validatePath):
  意图: "检查路径中是否包含 .. 字符串并移除"
  输入: "BASE_DIR + 用户传入的文件名"
  输出: "清理后的路径字符串" 
  关键逻辑: "path.replace(\"..\", \"\") — 只替换一次"
  可疑点: "replace 只做一次，\"..././\" 可能绕过"

func_3 (checkPermission):
  意图: "检查用户是否有读权限"
  输入: "用户对象，目标路径"
  输出: "boolean"
  关键逻辑: "if user.role == \"admin\": return True"
  可疑点: "role 字段来自 user 对象，如果 user 是用户传入的则可控"
```

### Merge 层：确定性排列

**无需 LLM 调用。** 按 CodeQL 节点序号排列 Intent Agent 的输出即可。

```
Intent Agent 1 输出: func_0, func_1, func_2, func_3
Intent Agent 2 输出: func_4, func_5, func_6, func_7
                    ↓
Merge: 按 node_id 排列
                    ↓
func_0 → func_1 → func_2 → func_3 → func_4 → func_5 → func_6 → func_7
```

如果需要接口连贯性检查（可选），可以用一个单次 LLM 调用：

```python
MERGE_CHECK_PROMPT = """
检查以下伪代码调用链的接口连贯性：
{intent_chain}

func_x 的输出作为 func_y 的输入，类型/语义是否一致？
如不一致，标注问题但不修改。
"""
```

但默认跳过——CodeQL 路径已经保证了接口兼容（否则不会被识别为一条路径）。

### Logic Agent：找矛盾（替代原来的"漏洞分析"）

**职责**：读伪代码链，找"意图与实现之间的矛盾"。不做代码阅读——只做矛盾检测。

```python
LOGIC_AGENT_PROMPT = """
项目上下文：{readme_summary}

以下是一条 source→sink 路径的伪代码链。每个函数已提取为"开发者意图"。

调用链:
{intent_chain}

=====

分析要求：

你的任务只有一个：找"意图与实现之间的矛盾"。

对比每个函数的"关键逻辑"和它声称的"意图"：
  - 意图说"校验路径"，关键逻辑是 replace("..", "") 只做一次 → 矛盾！校验不够
  - 意图说"检查权限"，role 字段来自用户输入 → 矛盾！权限来源不可信
  - 意图说"把搜索结果返回"，参数直接拼接到 eval() → 矛盾！用户可控参数进 eval
  - 意图说"过滤危险字符"，但 filter 列表很短，不在列表中的危险字符可以通过 → 矛盾！

如果找不到矛盾 → 这条路径大概率是安全的。

输出格式：
```json
{{
  "contradictions": [
    {{
      "func": "validatePath",
      "claimed": "移除路径中的 ..",
      "actual": "replace('..', '') — 只做一次，可绕过",
      "contradiction_type": "incomplete_sanitization",
      "bypass_poc": "....// 可绕过单次 replace",
      "exploit_potential": "可读取任意文件"
    }}
  ],
  "confidence_score": 7,
  "analysis": "validatePath 声称校验路径安全，但 replace 只做一次，标准绕过技术即可绕过"
}}
```

vulnhuntr bypass 示例（参考，不强制）：
{_vuln_bypasses[slice.vuln_type]}
"""

```

**Logic Agent 不需要读原始代码。** 它只读 Intent Agent 提取的伪代码链（500-1000 tokens）。注意力 100% 集中在矛盾检测上。

### 黑板缓存

这是新设计的关键杠杆。同一个函数在多条路径中出现是常态：

```
路径 A: request → validatePath → open          # validatePath 在 node 1
路径 B: request → parseFile → validatePath → exec  # validatePath 在 node 2
路径 C: request → auth → validatePath → write   # validatePath 在 node 3
```

**旧设计**：3 条路径各自分析 validatePath → 3 次重复读取 → 3 倍 token

**新设计**：
```
第 1 条路径触发 Intent Agent 分析 validatePath:
  → "意图: 用 replace(\"..\") 移除路径中的 .. 只替换一次"
  → 写入黑板: validatePath → {intent, ..., key_logic}

第 2、3 条路径:
  → PathCodeLoader 检查黑板: validatePath 已有 Intent
  → 直接读取缓存的 Intent 结果
  → 0 token 成本
```

黑板缓存的数据结构：

```python
@dataclass
class CachedIntent:
    func_name: str
    file_path: str
    intent: str              # "用 replace(\"..\", \"\") 移除 .."
    key_logic: str           # "replace 只做一次"
    suspicious: list[str]    # ["可绕过"]
    extraction_time: float   # 时间戳，用于缓存失效判断
```

### 迭代上下文获取（Logic Agent 专用）

Logic Agent 分析伪代码链时，如果发现"关键逻辑描述不够清晰，需要看原始代码"，可以：

1. 调用 `read_code(func_name, file_path)` 工具读取原始代码
2. 将关键片段追加到当前分析上下文中
3. 重新分析（最多额外 1 轮）

与旧设计的区别：**只有 Logic Agent 在需要时才请求原始代码**，不是默认就喂全部代码。

### 置信度评分

Logic Agent 输出 `confidence_score: 0-10`：

| 分数 | 含义 | 处理 |
|------|------|------|
| 0-3 | 无明显矛盾 | 丢弃 |
| 4-6 | 有可疑点但不确定 | 保留到报告，标注低置信度 |
| 7-8 | 矛盾明确，很可能可利用 | 进入 verification |
| 9-10 | 矛盾的利用路径清晰，有 PoC | 高优先级 |

低于 7 的路径不再送 verification，节省 token。

---

## Phase E: 黑板聚合 — 跨 agent 知识交叉注入

### 为什么 v3 需要黑板

v2 的 agent 串行执行，黑板的作用是"前一个 agent 发现的写下来，后一个 agent 读"。v3 的 Phase D 是并行执行，多 agent 同时分析不同路径，但**它们可能分析到相同的函数**：

```
路径 #1:  request.getParameter → Helper.parse → Runtime.exec
                                   ↑^^^^^^^^^
路径 #2:  request.getBody → Helper.parse → File.open
                                   ↑^^^^^^^^^
路径 #3:  request.getHeader → Helper.parse → eval()
                                   ↑^^^^^^^^^
                              都被 CodeQL 识别为独立路径
                              但都经过同一个函数 Helper.parse
```

v2 的黑板机制（串行）：
```
Agent 分析路径 #1 → 发现 parse() 没有校验 → record_knowledge("Helper.parse", ...)
                                                            ↓
Agent 分析路径 #2 → 收到 [PRIOR_KNOWLEDGE: Helper.parse 无校验] → 分析更充分
```

v3 并行场景下，三个 agent 同时跑，无法互相等结果。**但黑板仍然有价值**——只是位置从"agent 之间"移到"Phase D 和 Phase F 之间"。

### 实现：聚合器模式

```
Phase D: 并行 LLM Agent
  │  Agent 1: 分析 Path #1 → 输出结果 + record_knowledge("Helper.parse", "无输入校验")
  │  Agent 2: 分析 Path #2 → 输出结果 + record_knowledge("Helper.parse", "由 Controller 调用")
  │  Agent 3: 分析 Path #3 → 输出结果 + record_knowledge("Helper.parse", "返回值传给 eval")
  │
  ▼
Phase E: 黑板聚合器
  │  Step 1: 收集所有 agent 的 record_knowledge 调用
  │  Step 2: 按 key 合并（同一 key 多条 value 拼接）
  │  Step 3: 对每条路径的 sink 函数、中间函数建立知识索引
  │  Step 4: 将黑板知识注入下阶段
  │
  ▼
Phase F: 验证与报告
  │  Verification Agent 处理 Path #1 → 收到 [PRIOR_KNOWLEDGE]:
  │    - "Helper.parse: 无输入校验" (来自 Agent 1)
  │    - "Helper.parse: 由 Controller 调用" (来自 Agent 2)
  │    - "Helper.parse: 返回值传给 eval" (来自 Agent 3)
  │  当验证 Path #1 时，Agent 2 和 Agent 3 关于 parse() 的发现
  │  让验证更全面——可能发现 Path #1 的 RCE 不仅可触发还能回显
```

### 聚合器接口

```python
class BlackboardAggregator:
    """并行 agent 的知识聚合器。
    
    1. 收集所有 agent 在运行过程中记录的 discovered_logic
    2. 按函数名/key 合并
    3. 在验证阶段注入 [PRIOR_KNOWLEDGE]
    """

    def __init__(self):
        self._knowledge: dict[str, list[str]] = {}

    def collect(self, agent_results: list[AgentResult]) -> None:
        """从所有 agent 的输出中提取黑板记录。"""
        for result in agent_results:
            for key, value in result.recorded_knowledge.items():
                if key not in self._knowledge:
                    self._knowledge[key] = []
                self._knowledge[key].append(value)

    def get_prior_knowledge(self, function_name: str) -> str:
        """为指定函数生成 [PRIOR_KNOWLEDGE] 块。"""
        entries = self._knowledge.get(function_name, [])
        if not entries:
            return ""
        block = "\n".join(f"  - {e}" for e in entries)
        return f"[PRIOR_KNOWLEDGE for {function_name}]:\n{block}"

    def get_all_prior_knowledge(self, path_nodes: list[PathNode]) -> str:
        """为一条路径上所有函数生成聚合知识。"""
        blocks = []
        for node in path_nodes:
            pk = self.get_prior_knowledge(node.function_name)
            if pk:
                blocks.append(pk)
        return "\n\n".join(blocks)
```

### 为什么这个设计比 v2 的黑板更强

| 维度 | v2 黑板 | v3 黑板聚合器 |
|------|--------|--------------|
| 数据来源 | 单个 agent 串行写入 | 多个 agent **并行**写入 |
| 使用时机 | Brain 调度时动态注入 | 验证阶段**批量注入** |
| 知识广度 | 只有前序 agent 的发现 | **全部 agent** 的交叉知识 |
| 重复处理 | 可能有重复写入 | 按 key 合并去重 |

v3 的并行场景反而让黑板更有价值：三个 agent 各自分析不同路径但经过同一函数，发现的视角互补（A 发现输入来源，B 发现处理逻辑，C 发现返回值流向），合在一起就是对这个函数的完整理解。

### 即使没有迭代上下文也值得加

vulnhuntr 没有黑板概念，它的"迭代上下文获取"虽然可以达到类似效果但成本高得多：

```
vulnhuntr 等价实现: 对同一函数分析 3 次（每次重新送全文件）
                    LLM 每次可能注意到不同东西
                    ≈ 被动地偶然发现

v3 黑板聚合器:      3 个 agent 各分析 1 次
                    结果合并 → 验证阶段受益
                    ≈ 主动地系统化知识共享
```

黑板聚合器的代码量约 100 行（数据合并 + prompt 拼接），成本极低。建议 P6 实现。

## Phase F: 验证与报告

复用 agies 现有的 Verification Agent（不必重写）：

```
黑板聚合后的知识
    │
    ▼
高置信度路径 (>= 7) → Verification Agent（tool-using LLM）
    │                   收到 [PRIOR_KNOWLEDGE] 注入
    │                   读文件、搜代码、确认 PoC
    │                   确认/误报 裁定
    ▼
Report Agent → markdown/json 报告
```

### Phase F.5: 动态沙箱验证（可选，面向 Bug Bounty）

op.md 指出的核心问题：LLM 确认不等于漏洞证实。2026 年 bounty 审核要求**实际运行 PoC 拿到回显**（DNSLog、`/etc/passwd` 等）。

仅在 `--sandbox-verify` 开启时启用：

```
高置信度路径 (>= 7) → Verification Agent → PoC 生成
                                              ↓
                                    Docker 沙箱执行
                                    Python/Node 官方镜像
                                    pip install / npm install
                                    运行 PoC 脚本
                                    捕获 stdout + 文件变更 + 网络回显
                                              ↓
                                    通过: 确认真漏洞
                                    失败: 标记为"未验证"，降低置信度
```

对于 Python/JS/TS（解释型语言），Docker 沙箱的工程门槛很低：

```python
def run_poc_in_sandbox(poc_code: str, language: str) -> SandboxResult:
    """在临时 Docker 容器中执行 PoC 脚本。"""
    image = "python:3.11-slim" if language == "python" else "node:20-slim"
    # 安全限制: 网络隔离（除 DNSLog 外）、磁盘配额 100MB、超时 30s
    # 结果捕获: stdout, stderr, 文件系统变更, 出口码
```

这个阶段是**可选**的，不影响核心管线完整性。

---

## 文件结构

```
agies/engine/
├── v2/                            # 已有，保留作为回退
│   └── ...
│
├── v3/                            # ★ NEW v3 模块
│   ├── __init__.py
│   ├── runner.py                  # 主编排器（CodeQL → 切片 → LLM → 验证）
│   │
│   ├── codeql/                    # CodeQL 集成
│   │   ├── __init__.py
│   │   ├── query.py               # 运行 CodeQL 查询、解析结果
│   │   ├── queries/               # QL 查询文件
│   │   │   ├── rce.ql
│   │   │   ├── lfi.ql
│   │   │   ├── ssrf.ql
│   │   │   ├── sqli.ql
│   │   │   ├── xss.ql
│   │   │   ├── afo.ql
│   │   │   └── idor.ql
│   │   └── models.py              # CodeQlPath, PathNode
│   │
│   ├── slicer/                    # 切片与排序
│   │   ├── __init__.py
│   │   ├── sorter.py              # score_path(), select_top_k()
│   │   └── models.py              # PathSlice
│   │
│   ├── prompts/                   # ★ 漏洞类型专项 prompt（VulnHuntr 移植）
│   │   ├── __init__.py
│   │   ├── rce.py                 # RCE prompt + bypasses
│   │   ├── lfi.py                 # LFI prompt + bypasses
│   │   ├── ssrf.py                # SSRF prompt + bypasses
│   │   ├── sqli.py                # SQLI prompt + bypasses
│   │   ├── xss.py                 # XSS prompt + bypasses
│   │   ├── afo.py                 # AFO prompt + bypasses
│   │   ├── idor.py                # IDOR prompt + bypasses
│   │   └── readme_summary.py      # README 总结 prompt
│   │
│   ├── aggregator/                # ★ 黑板聚合 + Intent 缓存（Phase D+E）
│   │   ├── __init__.py
│   │   ├── blackboard.py          # BlackboardAggregator（Intent 缓存 + 知识注入）
│   │   └── models.py              # CachedIntent, AgentResult, KnowledgeEntry
│   │
│   └── agents/                    # ★ 三阶段 Agent 池（替换原单 Agent）
│       ├── __init__.py
│       ├── path_code_loader.py    # 路径坐标 → 函数分组 + 黑板缓存查询
│       ├── intent_agent.py        # Phase D Step 2: 4-5 函数 → "开发者意图"
│       ├── logic_agent.py         # Phase D Step 4: 伪代码链 → 矛盾检测
│       ├── merge.py               # Phase D Step 3: 确定性排列 Intent 输出
│       └── aggregator.py          # 多条路径结果合并 + 排序
│
├── graph/
│   ├── codeql.py                  # ★ MOD: 从 stub 改为调用 v3/codeql/ 的入口
│   └── ...                        # 其他已有文件不变
│
└── v2/agents/                     # ★ MOD Verification Agent（复用，无需改动）
    └── verification_agent.py
```

---

## 与 vulnhuntr 的对比

| 维度 | vulnhuntr | agies v3 |
|------|-----------|----------|
| **路径发现** | LLM 自己找，可能遗漏 | CodeQL 穷举，确定性的 |
| **路径准确性** | LLM 可能误解调用关系 | CodeQL 调用图精确 |
| **分析方向** | 迭代式串行（每文件数分钟） | 并行（多条路径同时） |
| **语言支持** | 仅 Python (Jedi) | CodeQL 支持的所有语言 |
| **Prompt** | 7 类专项 + bypass 示例 | 同 vulnhuntr + 可扩展 |
| **验证** | 无 | Verification Agent |
| **成本控制** | 可能多轮迭代消耗大量 token | 按切片，每路径 1-2 次 LLM |
| **README 注入** | 有 | 有 |
| **置信度评分** | 0-10，自动过滤 | 0-10 + Verification 确认 |
| **误报率** | 未验证，LLM 输出即结果 | CodeQL 路径 + LLM 判断 + Verification 三重过滤 |
| **已知 0day** | 多个 CVE | 待验证（但路径覆盖更全） |

### vulnhuntr 唯一不可复制的优势

vulnhuntr 的 prompt 已经实战验证挖到多个 0day。但 prompt 是文本，直接移植过来即可。

### agies v3 对 vulnhuntr 的超越

1. **确定性路径覆盖** — CodeQL 穷举所有 source→sink 路径，不依赖 LLM 判断力
2. **并行分析** — 多条路径同时送 LLM，而不是串行迭代
3. **三重过滤** — CodeQL（精确路径）+ LLM（语义判断）+ Verification（工具验证）
4. **多语言** — 不只是 Python，Java/JS/TS/Go/C# 都能打
5. **成本可控** — 按切片计费，不随项目规模线性增长

---

## 实施路线

| 步骤 | 内容 | 依赖 | 预计代码量 |
|------|------|------|-----------|
| **P0** | 搭建 v3 目录结构 + pytest 骨架 | 无 | 50 行 |
| **P1** | CodeQL 集成：database create + 查询执行 + 结果解析 | CodeQL CLI 安装 | 300 行 |
| | *注：P1 实现时优先验证 Python/JS 建库成功率，Java/C++ 作为后续目标* | | |
| **P2** | 7 类 QL 查询文件（聚焦 AI/ML 特有 sink） | P1 | 200 行 |
| **P3** | 切片排序引擎：score_path + select_top_k | 无 | 150 行 |
| | *注：取消 sanitizer 降权逻辑，改为 bypass 标记加分* | | |
| **P4** | Intent Agent prompt + Logic Agent prompt（替换原单 Agent prompt） | 无 | 300 行 |
| | *注：Intent prompt 只问"在做什么"，不做安全判断；Logic prompt 只问"矛盾在哪"* | | |
| **P5** | Intent Agent 池 + 黑板缓存集成 | P4 | 200 行 |
| **P6** | Logic Agent：伪代码链矛盾检测 + vulnhuntr bypass 示例参考 | P5 | 200 行 |
| **P7** | 黑板聚合器增强：Intent 缓存 + 跨路径共享 | P6 | 150 行 |
| **P8** | 主编排器：CodeQL → 切片 → README → Intent 池 → Merge → Logic → 黑板 → 验证 | P1-P7 | 350 行 |
| | *注：P8 增加回退逻辑——CodeQL 路径数为 0 时降级到 tree-sitter 局部后向追踪* | | |
| **P9** | CLI 集成：`agies audit --v3` 开关 | P8 | 50 行 |
| **P10** | 动态沙箱验证（可选）：Docker PoC 执行 + 结果捕获 | P6 | ~300 行 |
| **P11** | 在已知 CVE 项目上验证 + 调优 + token 成本热力图 | P9 | 酌情 |

合计：~2100 行新增。

---

## 现有基础设施盘点

### 已有（不需要造轮子）

| 模块 | 文件 | 用途 | v3 中如何使用 |
|------|------|------|-------------|
| 函数提取 | `engine/v2/sourcer/extractor.py` | 按 file+line 定位函数 | 给 PathCodeLoader 用 |
| 函数索引 | `engine/v2/sourcer/loader.py` | 构建可搜索的函数索引 | 可选：快速批量定位 |
| 并行执行 | `engine/v2/runner.py` | ThreadPoolExecutor | 调度多条路径并行分析 |
| 动态并发控制 | `engine/v2/brain.py` | QuotaMonitor + Crash Defender | 控制 API 速率 |
| 去重/状态 | `engine/v2/state.py` | 结果去重 + checkpoint | 合并多条路径的分析结果 |
| Verification | `engine/v2/agents/verification_agent.py` | 工具验证 | 高置信度路径二次确认 |
| Report | `engine/v2/agents/report_agent.py` | 报告生成 | 复用（输入格式适配） |

### 需要新增

| 模块 | 文件 | 用途 | 代码量 |
|------|------|------|--------|
| CodeQL 查询执行 | `engine/v3/codeql/query.py` | 运行 CodeQL 查询、解析结果 | ~200 行 |
| CodeQL 数据模型 | `engine/v3/codeql/models.py` | CodeQlPath, PathNode | ~80 行 |
| QL 查询文件 | `engine/v3/codeql/queries/*.ql` | 7 类漏洞的 source→sink 查询 | ~200 行 |
| 切片排序 | `engine/v3/slicer/sorter.py` | score_path, select_top_k | ~150 行 |
| 切片数据模型 | `engine/v3/slicer/models.py` | PathSlice | ~60 行 |
| 路径代码加载（增强） | `engine/v3/agents/path_code_loader.py` | 路径坐标 → 分组 + 黑板查询 | ~150 行 |
| Intent Agent | `engine/v3/agents/intent_agent.py` | 4-5 函数 → "开发者意图"伪代码 | ~150 行 |
| Logic Agent | `engine/v3/agents/logic_agent.py` | 伪代码链 → 矛盾检测 | ~200 行 |
| Merge 层 | `engine/v3/agents/merge.py` | 确定性排列 Intent 输出 | ~50 行 |
| 黑板缓存 | `engine/v3/aggregator/blackboard.py` | Intent 结果缓存 + 跨路径共享 | ~150 行 |
| 主编排器 | `engine/v3/runner.py` | 全流程编排 | ~350 行 |

### 需要验证的假设

1. **CodeQL 建库成功率** — 在 20 个随机 Python/JS 开源项目上验证 `codeql database create` 成功率
2. **CodeQL 路径数可控** — 在多个真实项目上验证路径数量级，确保 Top K 策略合理
3. **extractor 定位精度** — tree-sitter 的 `get_function_at_line` 在 Java/JS/TS 上是否与 Python 一样可靠
4. **Intent Agent 意图提取准确率** — 4-5 个函数的代码压缩为伪代码，是否有信息丢失
5. **Logic Agent 矛盾检测精确率** — 伪代码链上的矛盾检测 vs 原始代码上的直接分析，效果对比
6. **黑板缓存命中率** — 实际项目中，同一函数出现在多条路径中的频率
7. **路径代码拼装后的 token 消耗** — 一条完整路径平均需要多少 token（旧方案基线，用于对比）
8. **Verification Agent token 放大器效应** — 实际测量验证阶段平均每轮 token 消耗
9. **动态类型断流频率** — 在 LangChain/Ray 等大量使用元编程的项目上，CodeQL 返回空路径的比例

---

### 成功标准

1. 在已知漏洞项目（zipp CVE-2024-5569、gpt_academic、Ragflow 等）上至少复现 vulnhuntr 发现的漏洞
2. 路径排序后 Top 10 包含真实漏洞路径（不依赖 LLM 自己去发现）
3. 全量测试回归通过（627+ tests）
4. 在 vulnhuntr 已发现的 0day 项目上不漏报
