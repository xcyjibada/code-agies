# agies Development Roadmap

> 目标：让 agies 在核心能力上接近 Sandyaa，同时在架构设计上走出自己的路。
> 不照搬 Sandyaa 的代码，而是理解其设计意图后，用更适合 Python 生态的方式重新实现。

---

## 总体架构

```
                            agies
┌───────────────────────────────────────────────────────────────┐
│                        CLI 层 (Typer)                          │
│   audit | scan | init | (new) verify | (new) diff             │
└───────────┬───────────────────────────────────┬───────────────┘
            │                                   │
    ┌───────▼────────┐                ┌─────────▼────────┐
    │   Orchestrator  │                │  Config (YAML)   │
    │  (auditor.py)   │                │  .agies/config   │
    └───────┬────────┘                └──────────────────┘
            │
    ┌───────┼───────────────────────────────────────────┐
    │       ▼                                           │
    │  ┌──────────┐  ┌───────────┐  ┌────────────────┐  │
    │  │  Static   │  │Strategy   │  │  LLM Provider  │  │
    │  │  Analysis │  │(priority  │  │  Abstraction   │  │
    │  │  (multi-  │  │ + chunk)  │  │  (multi-model) │  │
    │  │  lang)    │  └───────────┘  └───────┬────────┘  │
    │  └────┬──────┘                         │           │
    │       ▼                                ▼           │
    │  ┌──────────────────────────────────────────────┐  │
    │  │           Agent Loop (function calling)       │  │
    │  │  ┌──────────┐  ┌──────────┐  ┌───────────┐  │  │
    │  │  │  Explore  │  │  Deep    │  │  Verify   │  │  │
    │  │  │  (grep,   │  │  Dive    │  │  Findings │  │  │
    │  │  │  list,    │  │  (read,  │  │  (cross-  │  │  │
    │  │  │  map)     │  │  trace)  │  │  check)   │  │  │
    │  │  └──────────┘  └──────────┘  └───────────┘  │  │
    │  └──────────────────────────────────────────────┘  │
    │                           │                        │
    │  ┌────────────────────────▼────────────────────┐   │
    │  │         Verification Pipeline               │   │
    │  │  File→Line→Contradiction→CrossModel→PoC     │   │
    │  └────────────────────────┬────────────────────┘   │
    │                           ▼                        │
    │  ┌──────────────────────────────────────────────┐  │
    │  │             Report Generator                  │  │
    │  │       Markdown | JSON | (new) SARIF          │  │
    │  └──────────────────────────────────────────────┘  │
    └───────────────────────────────────────────────────┘
```

---

## Phase 1：跨语言静态分析（2-3 周）

当前 agies 只有 Python 的 AST 污点追踪，这是与 Sandyaa（9 语言）最大的差距。

### 1.1 Java 污点追踪

**Sandyaa 的做法**：正则表达式 + 调用链追踪，没有用真正的 Java parser。
**agies 的做法**：用 `tree-sitter`（Python 生态的事实标准）做精确解析，不走正则。

```
agies/analyzer/
├── parser.py          # 现有：Python AST
├── parser_java.py     ★ 新增：Tree-sitter Java parser → SourceFileIR
├── parser_js.py       ★ 新增：Tree-sitter JS/TS parser
├── call_graph.py      # 现有：跨文件调用图（抽象符号层）
├── taint.py           # 现有：正向污点传播（抽象符号层）
├── taint_java.py      ★ 新增：Java 特定的 sources/sinks/sanitizers
├── findings.py        # 现有
└── config.py          # 现有：sources/sinks 配置（扩展为多语言）
```

**关键设计原则**：
- `parse_files()` → `SourceFileIR` 用 Pydantic，语言无关
- `CallGraph` 已经是跨文件的，不需要改
- `TaintEngine` 需要扩展：目前只遍历 Python AST，改为遍历抽象 IR
- 新增 `analyzer/config_java.py`：定义 Java 的 sources（`request.getParameter`、`@RequestParam`）、sinks（`exec`、`Runtime.exec`、`ProcessBuilder`）

**具体实现步骤**：

```
Week 1
  Day 1-2: 引入 tree-sitter 依赖，实现 parser_java.py
    - Python 包：tree-sitter + tree-sitter-java 语言包
    - parse_java_file(path) → SourceFileIR
    - 提取：函数定义、函数调用、变量赋值、类字段

  Day 3-4: 扩展 CallGraph 支持 Java
    - 方法调用解析（obj.method() 模式）
    - 跨文件符号解析（import 语句）
    - 测试项目：Spring Boot 典型结构

  Day 5: 扩展 TaintEngine 支持 Java
    - 新增 taint_java.py：Java sources/sinks 配置
    - 新增 taint_js.py：JavaScript sources/sinks 配置

Week 2
  Day 1-2: 集成测试 + 质量打磨
    - 对真实的 Spring Boot 项目跑通端到端
    - 对比 Semgrep 规则发现率

  Day 3-5: 补充 JavaScript/TypeScript
    - parser_js.py（tree-sitter-javascript + tree-sitter-typescript）
    - 前端 sources：window.location、fetch URL、DOM API
    - 前端 sinks：innerHTML、eval、document.write
```

### 1.2 多语言集成

修改 `analyzer/__init__.py` 中的 `Analyzer.run()`，从"全量解析 Python"变为"检测语言 → 选解析器 → 统一 IR → 分析"：

```python
class Analyzer:
    def run(self, target: str) -> AnalysisResult:
        files_by_lang = self._group_by_language(target)
        ir_files = []
        for lang, files in files_by_lang.items():
            parser = self._get_parser(lang)
            ir_files.extend(parser.parse(files))
        
        symbol_table = SymbolTable(ir_files).build()     # 跨语言
        call_graph = CallGraph(ir_files, symbol_table).build()  # 跨语言
        taint_engine = TaintEngine(ir_files, call_graph, 
                                     sources=config.get(lang),
                                     sinks=config.get(lang))
        taint_paths = taint_engine.analyze()
        return findings.augment(taint_paths)
```

### 1.3 tree-sitter 的优势

相比 Sandyaa 的正则方案，tree-sitter 提供：
- **精确 AST**：不会漏解析、不会误匹配
- **容错解析**：即使文件有语法错误也能产生 AST
- **增量解析**：未来可以做 IDE 级别的实时分析
- **语言覆盖**：Python、Java、JS/TS、Go、Rust、Ruby、C/C++ 等

---

## Phase 2：攻击者可控制验证（2 周）

Sandyaa 最值钱的创新是 `AttackerControlAnalyzer` — 六维验证流水线。我们不抄它的正则，但实现同样的验证逻辑。

### 2.1 架构

```
agies/verification/
├── __init__.py           # Phase 1 已有
├── evidence.py           
├── file_check.py         
├── contradiction.py      
├── cross_model.py        
├── pipeline.py           
├── attacker_control.py   ★ 新增：攻击者控制验证
├── language_patterns.py  ★ 新增：语言模式定义
└── exploitability.py     ★ 新增：可利用性评分
```

### 2.2 六维验证器

```python
class AttackerControlVerifier:
    """语言无关的攻击者控制验证流水线。
    
    对每个漏洞候选进行 P0/P1 优先级的六维验证。
    P0 失败 → 阻断；P1 失败 → 降置信度。
    """
    
    VALIDATORS = [
        ("execution_context", P0Validator),
        ("trust_boundary",    P0Validator),
        ("external_reachability", P0Validator),
        ("validation_chain",  P1Validator),
        ("thread_model",      P1Validator),
        ("semantic_pattern",  P1Validator),
    ]
    
    def validate(self, finding, code_context) -> AttackerControlResult:
        for name, validator_cls in self.VALIDATORS:
            validator = validator_cls(self.language_patterns)
            result = validator.check(finding, code_context)
            if result.is_blocking and not result.passed:
                return AttackerControlResult(
                    is_controlled=False,
                    blocking_reason=result.reason
                )
```

### 2.3 语言模式定义

不用正则表达式，用语言特性查询：

```python
class LanguagePatterns:
    """每种语言实现这个接口。"""
    
    def is_compiler_code(self, path: str, content: str) -> bool:
        """编译时代码？非运行时可利用。"""
        
    def is_startup_code(self, path: str, content: str) -> bool:
        """启动初始化代码？非运行时可利用。"""
        
    def is_test_code(self, path: str, content: str) -> bool:
        """测试代码？非生产环境。"""
    
    def get_user_input_apis(self) -> list[str]:
        """用户输入 API 列表。"""
        
    def get_external_entry_points(self) -> list[str]:
        """外部入口点（HTTP handler、消息队列等）。"""
```

Python 实现示例：

```python
class PythonPatterns(LanguagePatterns):
    def is_test_code(self, path, content):
        return "test_" in path or "_test" in path or "conftest" in path
    
    def get_user_input_apis(self):
        return ["sys.argv", "input()", "os.environ", "request.GET", 
                "request.POST", "request.data"]
    
    def get_external_entry_points(self):
        return ["@app.route", "@blueprint.route", "def main("]
```

**为什么比 Sandyaa 好**：Sandyaa 用正则匹配关键词。我们用结构化的语言特性查询，可测试、可扩展、可组合。

### 2.4 可利用性评分

```python
class ExploitabilityScorer:
    """基于验证结果计算可利用性分数 0-1。"""
    
    def score(self, finding, control_result, code_context) -> float:
        factors = {
            "entry_point_clarity": self._rate_entry_point(finding),
            "data_flow_completeness": self._rate_data_flow(finding),
            "auth_bypass_difficulty": self._rate_auth(finding, code_context),
            "input_validation_strength": self._rate_validation(code_context),
        }
        return weighted_average(factors)  # 0.0 ~ 1.0
```

---

## Phase 3：上下文管理与 RLM 模式（2 周）

Sandyaa 的 RLM（递归语言模型）实现让 LLM 驱动 Python REPL。我们不做 REPL，做 **结构化上下文管理 + 分治分析**。

### 3.1 滑动窗口上下文

当前问题：agent loop 积累完整消息历史，大项目很快就超上下文限制。

```python
class ContextManager:
    """智能上下文管理，替代原始的 messages 列表累积。"""
    
    def __init__(self, max_context_tokens: int = 80000):
        self.max_tokens = max_context_tokens
        self.system_prompt = ""
        self.core_messages: list[dict] = []   # 系统 + 用户初始指令
        self.recent_history: list[dict] = []   # 最近 N 轮
        self.summary: str = ""                 # 较早历史的摘要
        
    def add_turn(self, assistant_msg: dict, tool_results: list[dict]):
        """添加一轮对话，如果超限则压缩早期历史。"""
        self.recent_history.append(assistant_msg)
        self.recent_history.extend(tool_results)
        
        total = self._estimate_tokens(self.core_messages + self.recent_history)
        if total > self.max_tokens:
            self._compress_history()
    
    def _compress_history(self):
        """用 LLM 对早期历史做摘要压缩。"""
        # 取前 50% 的历史，让模型总结关键发现
        # 替换为一条 summary 消息
        pass
    
    def get_messages(self) -> list[dict]:
        """构建当前对话上下文。"""
        return self.core_messages + self.summary_messages() + self.recent_history
```

### 3.2 分区分析（替代 RLM）

不做 REPL，做**子分析任务分发**：

```python
class AnalysisOrchestrator:
    """分治分析：大项目拆成多个子分析任务，聚合结果。"""
    
    def analyze_large_project(self, files, context):
        # 1. 按模块/目录分组
        modules = self._group_by_module(files)
        
        # 2. Phase 1：高优先级文件（已有）
        priority_result = self._analyze_priority_files(modules)
        
        # 3. Phase 2：逐模块并行分析
        module_results = []
        for module in modules:
            # 每个模块用独立 agent 上下文
            result = self._analyze_module(module, priority_context)
            module_results.append(result)
        
        # 4. 跨模块聚合：发现模块间的数据流
        cross_module = self._cross_module_analysis(module_results)
        
        # 5. 去重 + 验证 + 排序
        return self._aggregate(module_results + [cross_module])
```

**为什么比 Sandyaa 的 RLM 好**：
- Sandyaa 的 RLM 是单线程 Python REPL，LLM 写代码执行，慢且不可控
- agies 是结构化分治，每个子分析是独立 agent 会话，可并行
- 子分析结果可聚合、可比较、可去重

### 3.3 渐进式发现

```python
class ProgressiveAnalyzer:
    """渐进式分析：先粗后细，每次深入都基于已有发现。"""
    
    LEVELS = [
        ("grep",           self._grep_pass),           # 毫秒级
        ("static",         self._static_analysis),      # 秒级
        ("llm_verify",     self._llm_verify),           # 秒级/发现
        ("llm_deep_dive",  self._llm_deep_dive),        # 分钟级/发现
        ("poc_generate",   self._poc_generation),       # 分钟级/发现
    ]
    
    def analyze(self):
        for level_name, level_fn in self.LEVELS:
            findings = level_fn()
            if not findings:
                continue  # 没有发现就不深入
            # 只对 critical/high 做下一级分析
```

---

## Phase 4：POC 生成与回归检测（2 周）

### 4.1 POC 生成

```python
class POCGenerator:
    """生成漏洞利用验证代码。不复制 Sandyaa 的 5-Whys 模板。"""
    
    def generate(self, finding, code_context) -> POC:
        poc_type = self._classify_vulnerability(finding)
        
        if poc_type == "sqli":
            return self._gen_sqli_poc(finding)
        elif poc_type == "xss":
            return self._gen_xss_poc(finding)
        elif poc_type == "path_traversal":
            return self._gen_path_traversal_poc(finding)
        # ...
    
    def validate(self, poc, target_dir) -> ValidationResult:
        """验证 POC 是否能在目标环境中使用。"""
        # 检查 poc 中引用的文件/路由是否存在
        # 检查 poc 不破坏目标环境（只读验证）
```

### 4.2 回归检测

```python
class RegressionDetector:
    """通过 git 历史检测修复过的漏洞是否回归。"""
    
    def check_fix(self, finding) -> RegressionResult:
        # 1. 获取文件行的 git blame 历史
        blame = self._git_blame(finding.file_path, finding.line_number)
        
        # 2. 检查最近提交信息
        recent = self._git_log(finding.file_path, max_count=10)
        
        # 3. 相似度检测：当前代码是否与已知修复相似
        similarity = self._code_similarity(finding, recent)
        
        return RegressionResult(
            is_regression=similarity > 0.8,
            original_fix_date=blame.last_fix_date,
            similarity_score=similarity,
        )
```

---

## Phase 5：报告输出增强（1 周）

### 5.1 SARIF 输出

SARIF（Static Analysis Results Interchange Format）是 GitHub Code Scanning 的标准格式。支持 SARIF 意味着可以直接在 GitHub PR 中显示 agies 的发现。

```python
class SARIFGenerator:
    """生成 SARIF 2.1 格式输出。"""
    
    def generate(self, findings, context) -> dict:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/...",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "agies", ...}},
                "results": [self._to_sarif_result(f) for f in findings],
                "artifacts": [...],
            }]
        }
```

### 5.2 增量报告

```python
class IncrementalReport:
    """支持多次运行结果合并。"""
    
    def merge(self, previous: Report, current: Report) -> Report:
        # 去重：相同 file:line:type 只保留最新
        # 对比：新增/消失/修复的发现
        # 趋势：严重性变化
        pass
```

---

## 实施路线图

| 阶段 | 内容 | 时间 | 里程碑 |
|------|------|------|--------|
| **P1** | 跨语言静态分析（Java + JS） | 2-3 周 | 非 Python 项目也能出 taint 结果 |
| **P2** | 攻击者可控制验证 | 2 周 | 验证 LLM 发现的真伪 |
| **P3** | 上下文管理 + 分区分析 | 2 周 | 5000+ 文件项目流畅运行 |
| **P4** | POC 生成 + 回归检测 | 2 周 | 发现→验证→修复→检查闭环 |
| **P5** | SARIF 输出 + 增量报告 | 1 周 | CI 集成可落地 |

---

## 性能目标

| 场景 | 当前 | 目标 | 关键措施 |
|------|------|------|---------|
| 100 文件 Python 项目 | ~30s | <10s | 分区分析、缓存 |
| 1000 文件 Java 项目 | ~10min | <3min | 渐进式发现、并行分析 |
| 5000+ 文件大项目 | 不可用 | <10min Phase 1 | 层抽样、分区、跳过 Phase 2 |
| CI 环境 (scan) | <5s | <3s | 无 LLM、纯静态、缓存 AST |

---

## 工程原则

1. **不复制 Sandyaa** — 理解其设计意图，用 Python 生态的最佳实践重新实现。Sandyaa 用 TypeScript + Claude CLI，我们用 Python + provider 抽象。

2. **每阶段可独立交付** — 不依赖后续阶段，每完成一个 Phase 就发布一个新版本。

3. **测试先行** — 每个新模块必须有对应的 `test_*.py`，覆盖率不低于 70%。

4. **性能感知** — 所有操作必须有明确的耗时预期。超过 1 秒的操作要显示进度。

5. **失败优雅** — LLM 调用失败、解析失败、配置缺失都不应导致整个审计中断。

6. **先搜再写，不闭门造车** — 遇到问题先查论文、工具、开源方案，确认没有现成解法再动手。避免重复造轮子，把精力花在真正需要创新的地方。
