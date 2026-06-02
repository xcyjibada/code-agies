# agies v3 — 基于静态调用链的漏洞发现（修订版）

> 规划日期：2026-06-02（修订）
> 原版：2026-05-30（基于 Joern 数据流图 + 三层剪枝）
> 修订版核心变化：
>   - 废弃 Joern 全量数据流图（PDG/DDG）方案 — RAM 消耗 GB 级，对漏洞发现增益有限
>   - 改用 **CodeQL source→sink 查询** 生成精确调用路径
>   - 新增 **切片排序引擎** — 路径按风险评分排序，Top K 喂 LLM
>   - 引入 **VulnHuntr 风格专项 prompt** — 每种漏洞类型有独立分析指引 + bypass 示例
>   - **并行 LLM Agent** — 多条路径同时分析，复用 agies 现有 runner

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

---

## 整体架构

```
源码
  │
  ▼
CodeQL 数据库构建（codeql database create）
  │
  ▼
Phase A: CodeQL 路径生成 ─── 预定义的 source→sink 查询
  │    输出: 所有 source→sink 路径（精确调用链 + 数据流）
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
Phase D: 并行 LLM Agent ─── 每条路径独立分析（复用 agies runner）
  │    每条路径携带: 路径代码 + 漏洞类型 prompt + bypass 示例
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

当 CodeQL 不可用（未安装、无数据库等）时，回退到 v2 的 tree-sitter SAST + 函数索引：

```
tree-sitter SAST (13 信号) → Director 打分 → 单函数 bulk → verification
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
  Top 15-30
  │
  ▼ Step 3: 全量分析
  │   每条路径的完整代码 + 对应漏洞 prompt + bypass → LLM Agent
```

为什么两步筛选：

- **静态粗筛**保证不遗漏——即使 LLM 判断失误，规则层的 Top 50 已经保留了最有价值的路径
- **LLM 微选**用一次简短调用（几百 token 的路径摘要，不需要看代码）做语义判断，省掉的是几十条误报路径的全量分析（几千 token × N 条）
- **默认情况下可以先跳过 LLM 微选**（直接静态 Top K），只有在路径数超阈值时启用

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

    # 3. 校验函数惩罚 — 路径经过 sanitize/validate 则降权
    has_validation = any("sanitize" in n or "validate" in n or "escape" in n
                         for n in path.nodes)
    if has_validation:
        score *= 0.5

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
  结果: Top 50（硬限制，CLI 参数 --max-path-candidates）

Step 2: LLM 微选（可选，默认关闭）
  触发条件: Top 50 中同一 sink 类型超过 5 条时启用
  做法: LLM 看每条路径的一句话摘要，选出 Top 15-30
  跳过: 如果 Top 50 中已经少于 30 条，直接跳过此步

  若 LLM 微选关闭（默认）：
    总路径数 < 30  → 全部送
    总路径数 >= 30 → Top 30（每类 sink 至少保留 1 条）
```

K 值可配：`--max-paths`（默认 30），启用 LLM 微选：`--llm-select-paths`。

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

## Phase D: 并行 LLM Agent（VulnHuntr 借鉴 + agies 优势）

### 核心机制

多条 PathSlice 提交到 agies 现有的并行执行器（`engine/v2/runner.py`）：

```
PathSlice 列表
  │  (按评分排序)
  ▼
并发队列 (workers=N, default=5)
  ├── Agent 1: 分析 PathSlice #1 (RCE)
  ├── Agent 2: 分析 PathSlice #2 (LFI)
  ├── Agent 3: 分析 PathSlice #3 (RCE)
  ├── Agent 4: 分析 PathSlice #4 (SQLI)
  └── Agent 5: 分析 PathSlice #5 (SSRF)
  │  (各自独立)
  ▼
结果合并
```

复用代码：
- `runner.py` — ThreadPoolExecutor 并行调度
- `brain.py` — QuotaMonitor + Crash Defender + 动态并发控制
- `state.py` — 结果去重 + checkpoints

### 路径代码加载（Path Code Loader）

这是 Phase D 的核心工具：把 CodeQL 路径上的函数节点转为 LLM 可读的代码块。

CodeQL 路径的原始输出是一组 `(file, line)` 坐标：

```
Path "rce-001":
  node 0: Controller.java:42    request.getParameter("cmd")
  node 1: Controller.java:45    Helper.parse(cmd)
  node 2: Helper.java:15        parse(data)
  node 3: Executor.java:88      run(command)
  node 4: Executor.java:90      Runtime.exec(command)
```

需要转换成：每个坐标对应的函数代码 + 路径上下文。

#### 实现方式

复用 agies 现有的 `engine/v2/sourcer/extractor.py`：

```python
class PathCodeLoader:
    """把 CodeQL 路径坐标转为 LLM 可读的代码块。

    依赖现有的 sourcer/extractor.py（tree-sitter 函数提取）。
    """

    def __init__(self, project_path: str):
        self.extractor = FunctionExtractor(project_path)  # 已有

    def load_path_code(self, path: CodeQlPath) -> str:
        """把一条路径上的所有函数代码打包成 LLM prompt 块。"""
        blocks = []
        for i, node in enumerate(path.nodes):
            func = self.extractor.get_function_at_line(
                node.file_path, node.line_number
            )
            blocks.append(f"""
### {i+1}. {func.name} ({func.file_path}:{func.line_start}-{func.line_end})
{func.signature}
```python
{func.body}
```
""")
        return "\n".join(blocks)
```

extractor 的输入输出：

```
输入: file_path="Controller.java", line_number=42
输出: SourceFunction(
        name="handleRequest",
        file_path="Controller.java",
        line_start=40,
        line_end=60,
        signature="def handleRequest(request):",
        body="    data = request.getParameter(\"cmd\")\n    return Helper.parse(data)"
      )
```

如果 extractor 找不到函数（如行号在类定义上），回退方案：用 `read_file` 工具读取前后 30 行上下文。

### Prompt 设计（VulnHuntr 精华移植）

每条路径分析时，根据 `PathSlice.vuln_type` 拼接对应的漏洞类型 prompt + bypass 示例：

```python
def build_agent_prompt(slice: PathSlice, readme_summary: str) -> str:
    return f"""
{readme_summary}

## 需要分析的代码路径
来源: {slice.source} ({slice.source_file})
汇点: {slice.sink} ({slice.sink_file})
路径上的函数:
{slice.code_block}

## 分析要求
{_vuln_prompts[slice.vuln_type]}

## Bypass 示例
{_vuln_bypasses[slice.vuln_type]}

## 输出格式
```json
{{{{
  "scratchpad": "逐步推理过程",
  "analysis": "最终分析结论",
  "poc": "攻击 PoC（如适用）",
  "confidence_score": 0-10,
  "vulnerability_types": ["{slice.vuln_type.value}"],
  "requires_additional_context": [...]
}}}}
```
"""
```

7 类漏洞的 prompt + bypass 直接从 vulnhuntr 移植（已验证在多个项目挖到 0day），详见 `agies/engine/v3/prompts/`.

### 迭代上下文获取（VulnHuntr 借鉴）

LLM 分析路径后，如果 `requires_additional_context` 不为空，则：

1. 用 agies 的 function index（tree-sitter）或 Jedi 解析符号定义
2. 把新代码追加到当前路径的 code_block 中
3. 重新送 LLM 分析
4. 最多 3 轮

与 vulnhuntr 最多 7 轮的区别：v3 的路径已经由 CodeQL 生成，调用链骨架已确定，LLM 只需要补全少量缺失上下文，不需要自己找路径，所以 3 轮足够。

### 置信度评分

LLM 输出 `confidence_score: 0-10`：

| 分数 | 含义 | 处理 |
|------|------|------|
| 0-3 | 误报或无利用路径 | 丢弃 |
| 4-6 | 可能但不确定 | 保留到报告，标注低置信度 |
| 7-8 | 很可能可利用 | 进入 verification |
| 9-10 | 确定可利用，有完整 PoC | 高优先级 |

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
│   ├── aggregator/                # ★ 黑板聚合（Phase E）
│   │   ├── __init__.py
│   │   ├── blackboard.py          # BlackboardAggregator（知识收集 + 合并 + 注入）
│   │   └── models.py              # AgentResult, KnowledgeEntry
│   │
│   └── agents/                    # LLM Agent 适配层
│       ├── __init__.py
│       ├── path_agent.py          # 单条路径分析 Agent（封装 prompt 拼接 + 迭代）
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
| **P2** | 7 类 QL 查询文件 | P1 | 200 行 |
| **P3** | 切片排序引擎：score_path + select_top_k | 无 | 150 行 |
| **P4** | 漏洞类型 prompt（移植 vulnhuntr） | 无 | 400 行 |
| **P5** | Path Agent：单条路径分析 + 迭代上下文 | P4 | 200 行 |
| **P6** | 黑板聚合器：BlackboardAggregator（知识收集 + 合并 + 注入） | P5 | 100 行 |
| **P7** | 主编排器：CodeQL → 切片 → README → 并行 LLM → 黑板 → 验证 | P1-P6 | 300 行 |
| **P8** | CLI 集成：`agies audit --v3` 开关 | P7 | 50 行 |
| **P9** | 在已知 CVE 项目上验证 + 调优 | P8 | 酌情 |

合计：~1600 行新增。

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
| 路径代码加载 | `engine/v3/agents/path_code_loader.py` | 路径坐标 → 代码块（调用 extractor） | ~100 行 |
| 路径分析 Agent | `engine/v3/agents/path_agent.py` | prompt 拼接 + 迭代上下文 | ~200 行 |
| 漏洞类型 prompt | `engine/v3/prompts/*.py` | 7 类 prompt + bypass 示例 | ~400 行 |
| 主编排器 | `engine/v3/runner.py` | CodeQL → 切片 → README → 并行 LLM → 验证 | ~250 行 |

### 需要验证的假设

1. **CodeQL 路径数可控** — 在多个真实项目上验证路径数量级，确保 Top K 策略合理
2. **extractor 定位精度** — tree-sitter 的 `get_function_at_line` 在 Java/JS/TS 上是否与 Python 一样可靠
3. **路径代码拼装后的 token 消耗** — 一条完整路径平均需要多少 token（参考：vulnhuntr 一个文件 5000-15000 token）

---

### 成功标准

1. 在已知漏洞项目（zipp CVE-2024-5569、gpt_academic、Ragflow 等）上至少复现 vulnhuntr 发现的漏洞
2. 路径排序后 Top 10 包含真实漏洞路径（不依赖 LLM 自己去发现）
3. 全量测试回归通过（627+ tests）
4. 在 vulnhuntr 已发现的 0day 项目上不漏报
