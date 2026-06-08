"""Main audit orchestrator with LLM agent loop.

Hacker-mindset strategy:
1. Parse → static analysis (structured evidence)
2. Global project mapping (80/20 on controllers, configs, mappers, interceptors)
3. Phase-based deep dive (each phase until exhaustion, no artificial limits)
4. Find-and-persist protocol: every discovery written to report in real time
5. Cross-file full-chain verification: continue until every path confirmed or ruled out
"""

import json
import os
import typer
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from agies.core import collect_context, collect_files
from agies.core.report import generate_markdown
from agies.tools import get_tool_definitions
from agies.tools.report import reset_findings, get_findings, set_analyzer_result
from agies.rules import get_enabled_rulesets
from agies.analyzer import Analyzer
from agies.analyzer.router_integration import run_route_analysis

console = Console()


def _run_new_pipeline(
    target: str,
    model: str,
    verbose: bool,
    static_analysis: bool,
    static_only: bool,
) -> None:
    """Run the new Xint-inspired pipeline: sourcer → bulk → verification."""
    from agies.engine import Brain, Runner
    from agies.engine.v2.agents import (
        MappingAgent, AttackSurfaceAgent, SourcerAgent, BulkAnalysisAgent,
        VerificationAgent, VulnerabilityAgent, ReportAgent,
    )

    console.print("  [bold]New pipeline:[/bold] mapping → attack_surface → sourcer → bulk → verification → vulnerability → report")
    console.print()

    # Static analysis
    if static_analysis:
        from agies.analyzer import Analyzer
        from agies.tools.report import set_analyzer_result
        with console.status("[bold]Static analysis...[/bold]"):
            analyzer = Analyzer()
            analyzer_result = analyzer.run(target)
        console.print(f"  Static: {len(analyzer_result.taint_paths)} taint paths, "
                      f"{len(analyzer_result.findings)} findings")
        set_analyzer_result(analyzer_result)

    if static_only:
        # Just build the index, no LLM calls
        console.print("  [dim]Static-only: building FunctionIndex...[/dim]")
        with console.status("[bold]Building FunctionIndex...[/bold]"):
            from agies.engine.v2.sourcer.loader import build_index
            idx = build_index(target)
        s = idx.summary()
        console.print(f"  Files: {s['files']}, Functions: {s['functions']}, Languages: {s['languages']}")
        return

    # LLM-powered pipeline
    from agies.llm import get_model
    from agies.engine.v2.prompt.manager import init_prompts
    model_instance = get_model(model)
    if not model_instance.api_key:
        console.print(f"[red]Error: {model_instance.env_key_name} environment variable not set[/red]")
        raise typer.Exit(1)

    # Initialize prompt manager (loads prompts/default.yaml + per-model overrides)
    pm = init_prompts()

    brain = Brain(
        runner=Runner(llm=model_instance),
        agents={
            "mapping": MappingAgent(prompt_manager=pm, prompt_model_name=model),
            "attack_surface": AttackSurfaceAgent(prompt_manager=pm, prompt_model_name=model),
            "sourcer": SourcerAgent(),
            "bulk_analysis": BulkAnalysisAgent(),
            "verification": VerificationAgent(prompt_manager=pm, prompt_model_name=model),
            "report": ReportAgent(),
        },
    )

    state = brain.run(target, use_new_pipeline=True)

    summary = state.function_index.summary() if state.function_index else {}
    console.print(f"\n[bold]Pipeline complete[/bold]")
    console.print(f"  Files indexed: {summary.get('files', 0)}")
    console.print(f"  Functions indexed: {summary.get('functions', 0)}")
    console.print(f"  Phase 1 candidates: {len(state.candidates)}")
    console.print(f"  Completed agents: {len(state.completed_agents)} agents")
    import logging; log = logging.getLogger(__name__)
    log.warning("Verified findings: %d total, %d triggerable",
                len(state.verified_findings),
                sum(1 for v in state.verified_findings if v.get("triggerable")))
    for v in state.verified_findings:
        log.warning("  finding: func=%s type=%s triggerable=%s",
                    v.get("function_name"), v.get("type"), v.get("triggerable"))
    triggerable = sum(1 for v in state.verified_findings if v.get("triggerable"))
    if triggerable:
        console.print(f"  [red]Triggerable findings: {triggerable}[/red]")

    # Bridge verified findings into the legacy report system
    from agies.tools.report import _findings
    for v in state.verified_findings:
        if not v.get("triggerable"):
            continue
        _findings.append({
            "title": f"[{v.get('confidence','medium').upper()}] {v.get('type','?')} in {v.get('function_name','?')}",
            "severity": "high" if v.get("confidence") == "high" else "medium" if v.get("triggerable") else "info",
            "file_path": v.get("file_path", ""),
            "line_number": 0,
            "detail": v.get("conditions", ""),
            "confidence": "L3",
            "type": v.get("type", ""),
            "verification": {"verification_status": "verified"},
        })


def _build_system_prompt(target: str, context: dict, analyzer_result=None, route_data=None, priority_summary: str = "") -> str:
    """Build the system prompt for the audit agent (hacker-mindset strategy)."""
    rulesets = get_enabled_rulesets(context.get("languages", []))
    rules_text = "\n".join(rs.get_instructions() for rs in rulesets)

    files_scanned = context.get("file_count", 0)
    languages = ", ".join(context.get("languages", ["unknown"]))

    # Inject route analysis context (new)
    route_context = ""
    if route_data:
        route_context = route_data.get("prompt_context", "")
        vulnerable = route_data.get("vulnerable_endpoints", [])
        if vulnerable:
            route_context += f"\n## 路由分析确认的可疑端点\n以下 {len(vulnerable)} 个端点既无 @PreAuthorize 也无'公开访问'声明，重点审计：\n"
            for ep in vulnerable[:10]:
                route_context += f"- {ep.http_method} {ep.path} ({ep.controller_class})\n"
        route_context += "\n"

    prompt = f"""# ROLE — 极致黑客思维安全审计专家

你是一名具备十余年黑盒与白盒攻防经验的资深安全审计专家。
面对大规模复杂工程时，你遵循一套经过实战验证的审计战法。

## 战法一：全局测绘（优先执行）

审计开始后第一步**不是逐文件读代码**，而是做全局测绘：

1. `list_directory(项目根目录)` → 理解项目整体结构
2. `grep_search("Controller|RestController")` → 锁定所有控制器
3. `grep_search("Mapper")` / `grep_search("\\.xml")` → 锁定 MyBatis 映射器
4. `grep_search("Interceptor|Filter|Security|Auth")` → 锁定安全拦截器
5. `grep_search("application.*\\.(yml|yaml|properties)")` → 锁定核心配置文件
6. `grep_search("(key|secret|password|jdbc|redis)\\s*[:=]")` → 锁定敏感凭据

## 战法二：80/20 原则锁定高危资产

80% 的漏洞集中在 20% 的文件中，**优先深入**：
- 🎯 **Controller / RestController** — 参数入口，未授权、SQLi、RCE 的高发区
- 🎯 **MyBatis Mapper XML** — `${{}}` 动态 SQL 注入的根源
- 🎯 **SecurityInterceptor / Filter** — 权限校验逻辑的缺陷往往藏在这里
- 🎯 **application.yml / application.properties** — 硬编码密钥、数据库凭证
- 🎯 **pom.xml / build.gradle** — 依赖版本已知漏洞

## 战法三：发现即实时存证协议（CRITICAL）

这是最重要的纪律——**在上下文窗口溢出或过程意外中断时保护劳动成果**：

1. 发现**任何**漏洞或可疑点，**立即**调用 `write_report` 记录，不要等
2. 硬编码密钥/凭证：发现即记录到 severity=high
3. `${{}}` 动态 SQL 注入：发现即记录到 severity=critical
4. 未授权接口：确认即记录到 severity=high
5. 框架安全缺陷：确认即记录到 severity=critical
6. **不要等到审计结束才统一写报告**——实时写，每处发现都立即存证

## 战法四：跨文件全链路闭环验证

对于复杂的数据流和业务逻辑，保持持续推理状态：

1. 追踪用户输入从 Controller 参数 → Service → Mapper → 数据库的完整路径
2. 对每个潜在的漏洞路径，要么证实（写 report），要么排除（记录排除理由）
3. 链路过长导致上下文不足时，优先查阅中间关键文件而不是从头读起
4. **没有"看起来像但不确认"的状态**——每条路径必须有结论

## 项目信息
- 目标: {target}
- 文件数: {files_scanned}
- 语言: {languages}

{priority_summary}
{route_context}## 评级标准
- **critical**: RCE、SQL 注入（含 ${{}}）、认证绕过、反序列化
- **high**: XSS、路径遍历、任意文件读写、硬编码凭证
- **medium**: CSRF、信息泄露、SSRF
- **low**: 安全头缺失、调试接口开启
- **info**: 改进建议

## 置信度标准（重要 — 用 write_report 时必须标注 confidence）
每次调用 write_report 必须附带 confidence 参数：
- **L3（全链路确认）**: HTTP入口 → Controller → Service → 漏洞点，完整路径已追踪
- **L2（数据流确认）**: 确认用户输入流向危险函数，但未完整追踪到 HTTP 入口
- **L1（特征匹配）**: 匹配到危险模式但未验证输入可控性（可能误报）

举例：
- eval(request.getParameter("code")) 确认来自请求 → L3
- eval() 出现在某函数中但不知调用来源 → L1
- ${{param}} 在 MyBatis XML，确认参数来自请求 → L2
- ${{dataScope}} 但只来自后端安全上下文非用户输入 → 不报
- 无 @PreAuthorize 但注释标明"公开访问" → 不报（业务设计）

## 可用工具
- `read_file`: 读取文件内容
- `list_directory`: 列出目录
- `grep_search`: 用 ripgrep 搜索
- `run_command`: 执行 shell 命令（只读）
- `write_report`: **发现漏洞立即调用此工具记录**
- `get_taint_flows`: 查询污点追踪数据

{rules_text}
"""

    # Add static analysis results if available
    if analyzer_result and analyzer_result.findings:
        prompt += """## 静态分析辅助数据

以下是自动静态分析发现的潜在污点路径。这些数据可作为深挖的线索，
但需要你人工验证真伪。静态分析可能有误报。

"""
        for f in analyzer_result.findings[:30]:  # Cap at 30 to avoid prompt bloat
            chain = ""
            if f.taint_path:
                src = f.taint_path.source
                snk = f.taint_path.sink
                chain = f"  Taint: {src.file_path}:{src.line} → {snk.file_path}:{snk.line}"
            prompt += f"- [{f.severity.upper()}] {f.title}\n  File: {f.file_path}:{f.line_number}\n{chain}\n\n"

        prompt += """用 `get_taint_flows` 工具查询更详细的污点路径数据，可过滤严重级别/文件/接收器类型。

"""

    return prompt


def run_audit(
    target: str,
    model: str = "deepseek-chat",
    strong_model: str | None = None,
    sandbox: bool = False,
    verbose: bool = False,
    output: str | None = None,
    output_format: str = "markdown",
    static_analysis: bool = True,
    static_only: bool = False,
    verify: bool = True,
    new_pipeline: bool = False,
    v3: bool = False,
    project_type: str | None = None,
    consensus: bool = False,
):
    """Run the full audit pipeline."""
    target = os.path.abspath(target)

    if not os.path.exists(target):
        console.print(f"[red]Error: target does not exist: {target}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]agies[/bold] — auditing [cyan]{target}[/cyan]")
    console.print()

    # Step 1: Collect context
    with console.status("[bold]Collecting project context...[/bold]"):
        context = collect_context(target)

    if "error" in context:
        console.print(f"[red]{context['error']}[/red]")
        raise typer.Exit(1)

    console.print(f"  Languages: {', '.join(context.get('languages', ['none detected']))}")
    console.print(f"  Files: {context['file_count']}")
    console.print()

    # Step 1b: v3 CodeQL pipeline (replaces full pipeline when --v3 is used)
    if v3:
        from agies.engine.v3.runner import run_v3_pipeline
        run_v3_pipeline(
            target, model=model, verbose=verbose,
            project_type=project_type or "auto",
            consensus=consensus,
        )
        console.print()
        console.print("[bold]v3 CodeQL pipeline complete.[/bold]")
        return

    # Step 2: Route analysis (new — build frontend↔backend mapping)
    route_data = None
    if "Java" in context.get("languages", []):
        with console.status("[bold]Analyzing routes (frontend↔backend mapping)...[/bold]"):
            route_data = run_route_analysis(target)
        if route_data:
            console.print(f"  Routes: {route_data['total_endpoints']} endpoints, "
                          f"{route_data['total_frontend_calls']} frontend calls, "
                          f"{route_data['matched_routes']} matched")
            if route_data['active_common_service_endpoints']:
                console.print(f"  [yellow]  {len(route_data['active_common_service_endpoints'])} endpoints still use CommonService[/yellow]")
            if route_data['vulnerable_endpoints']:
                console.print(f"  [red]  {len(route_data['vulnerable_endpoints'])} potential vulnerable endpoints (no auth)[/red]")
    console.print()

    # Step 3: Static analysis
    analyzer_result = None
    if static_analysis and "Python" in context.get("languages", []):
        with console.status("[bold]Running static analysis (parse, call graph, taint)...[/bold]"):
            analyzer = Analyzer()
            analyzer_result = analyzer.run(target)
        console.print(f"  Static analysis: {analyzer_result.files_parsed} files, "
                      f"{len(analyzer_result.taint_paths)} taint paths, "
                      f"{len(analyzer_result.findings)} finding(s)")
        # Make analyzer result available to taint tool
        set_analyzer_result(analyzer_result)
    elif static_analysis:
        console.print("  [dim]Static analysis: Python only, skipping[/dim]")

    # Step 4: Strategy analysis — prioritize files by audit value
    priority_summary = ""
    if context.get("is_dir", True) and not static_only:
        try:
            from agies.strategy import StrategyEngine

            all_files = collect_files(target)
            strategy = StrategyEngine(target)
            strategy_result = strategy.analyze_project(all_files)
            priority_summary = strategy_result["priority_summary"]
            console.print(f"  [dim]Strategy: {len(strategy_result['high_value_files'])} high-value targets, "
                          f"{len(strategy_result['chunks']['phase2'])} coverage chunks[/dim]")
        except Exception as e:
            if verbose:
                console.print(f"  [dim]Strategy analysis skipped: {e}[/dim]")

    # Step 5: Reset findings
    reset_findings()

    # Step 6: Run agent loop
    if new_pipeline:
        _run_new_pipeline(target, model, verbose, static_analysis, static_only)
    elif static_only:
        console.print("[dim]Static-only mode: skipping LLM agent loop[/dim]")
    elif not static_analysis:
        _run_agent_loop(target, context, model, verbose, analyzer_result=None, route_data=route_data, priority_summary=priority_summary)
    else:
        _run_agent_loop(target, context, model, verbose, analyzer_result, route_data=route_data, priority_summary=priority_summary)

    # Step 7: Verification pipeline (validate LLM findings)
    # Skip legacy verification for new pipeline — new pipeline has its own
    # verification agent that already validated findings.
    llm_findings = get_findings()
    if llm_findings and not static_only and verify and not new_pipeline:
        with console.status("[bold]Verifying LLM findings...[/bold]"):
            try:
                from agies.verification import VerificationPipeline
                from agies.llm import get_model as get_llm_model

                # Resolve strong model for cross-model verification
                strong_model_instance = None
                if strong_model:
                    strong_model_instance = get_llm_model(strong_model, max_retries=1)
                elif "claude" in model.lower():
                    strong_model_instance = get_llm_model("claude-opus-4-7", max_retries=1)
                elif "gpt" in model.lower():
                    strong_model_instance = get_llm_model("gpt-4o", max_retries=1)

                pipeline = VerificationPipeline(
                    target_root=target,
                    strong_model=strong_model_instance,
                )
                pipeline.run(llm_findings)

                # Count verification results
                verified = sum(1 for f in llm_findings
                               if f.get("verification", {}).get("verification_status") == "verified")
                uncertain = sum(1 for f in llm_findings
                                if f.get("verification", {}).get("verification_status") == "uncertain")
                contradicted = sum(1 for f in llm_findings
                                   if f.get("verification", {}).get("verification_status") == "contradicted")
                corrected_paths = sum(1 for f in llm_findings
                                      if f.get("verification", {}).get("file_corrected"))
                console.print(f"  Verification: {len(llm_findings)} findings — "
                              f"[green]{verified} verified[/green], "
                              f"[yellow]{uncertain} uncertain[/yellow], "
                              f"[red]{contradicted} contradicted[/red]"
                              + (f", {corrected_paths} paths corrected" if corrected_paths else ""))
            except Exception as e:
                if verbose:
                    console.print(f"  [dim]Verification skipped: {e}[/dim]")

    # Step 8: Generate report
    static_findings = len(analyzer_result.findings) if analyzer_result else 0
    llm_findings = len(get_findings())
    total_findings = static_findings + llm_findings
    console.print(f"\n[bold]Audit complete. {total_findings} finding(s) ({static_findings} static, {llm_findings} LLM).[/bold]\n")

    route_section = route_data.get("report_section", "") if route_data else ""

    if output_format == "json":
        from agies.core.report import generate_json
        report_data = generate_json()
        import json as _json
        report_str = _json.dumps(report_data, indent=2, ensure_ascii=False)
    else:
        report_str = generate_markdown(target, context, analyzer_result, route_section=route_section)

    if output:
        with open(output, "w") as f:
            f.write(report_str)
        console.print(f"Report written to [cyan]{output}[/cyan]")
    else:
        console.print(Markdown(report_str))


def _calc_max_turns(context: dict) -> int:
    """Dynamically calculate max agent turns based on project complexity.

    Rules:
    - Small project (<50 files): 50 turns (enough for thorough scan)
    - Medium project (50-200 files): 100 turns
    - Large project (200-500 files): 200 turns
    - Extra-large project (500+ files): 300 turns, warn about size
    - Java/Spring projects (RuoYi-style): +50% bonus due to XML + annotation complexity
    """
    file_count = context.get("file_count", 0)
    languages = [l.lower() for l in context.get("languages", [])]
    has_java = any("java" in l for l in languages)

    if file_count >= 500:
        base = 300
    elif file_count >= 200:
        base = 200
    elif file_count >= 50:
        base = 100
    else:
        base = 50

    if has_java:
        base = int(base * 1.5)

    return min(base, 500)  # absolute cap at 500 turns


def _run_agent_loop(target: str, context: dict, model: str, verbose: bool, analyzer_result=None, route_data=None, priority_summary: str = ""):
    """Run the LLM agent loop via DeepSeek API (OpenAI-compatible).

    Hacker-mindset strategy loop:
    Phase 1 — Global mapping (project structure, key files)
    Phase 2 — Asset discovery (controllers, mappers, configs, interceptors)
    Phase 3 — Deep dive + chain validation (follow data flows, verify sinks)
    Phase 4 — Final sweep (check remaining coverage areas)
    No hard per-phase limit — model stops naturally when no more tool calls.
    """
    from agies.llm import get_model

    model_instance = get_model(model)
    tool_defs = get_tool_definitions()
    openai_tools = [t["schema"] for t in tool_defs]
    tool_map = {t["name"]: t["fn"] for t in tool_defs}

    if not model_instance.api_key:
        console.print(f"[red]Error: {model_instance.env_key_name} environment variable not set[/red]")
        raise typer.Exit(1)

    system_prompt = _build_system_prompt(target, context, analyzer_result, route_data, priority_summary)

    max_turns = _calc_max_turns(context)
    file_count = context.get("file_count", 0)
    is_large = file_count > 200

    if is_large:
        console.print(f"  [yellow]Large project ({file_count} files). Max agent turns: {max_turns}[/yellow]")
    else:
        console.print(f"  [dim]Max agent turns: {max_turns}[/dim]")

    user_msg = f"""对 {target} 执行安全审计。

## 执行流程

### 第一阶段：全局测绘（开始后的前 5-10 轮）
不要急着读代码，先用 list_directory 和 grep_search 做项目测绘：
- 项目整体结构（模块/包/分层）
- 所有 Controller / RestController
- MyBatis XML Mapper 文件
- Security 过滤器 / 拦截器
- 配置文件（application.yml/properties, pom.xml）

### 第二阶段：高危资产深入（测绘完成后）
锁定 80% 价值的那 20% 文件，深入审计：
- 硬编码密钥/凭据 → 立即 write_report
- ${{}} 动态 SQL → 立即 write_report
- 未授权接口 → 确认后立即 write_report
- 权限校验缺陷 → 确认后立即 write_report
- 框架配置缺陷 → 确认后立即 write_report

### 第三阶段：跨文件链路闭环
对每个数据流路径，追踪入口→出口的完整链条：
- Controller 参数 → Service → Mapper → DB
- 要么证实漏洞存在（write_report），要么排除并记录原因
- 注意 Java 的注解配置：@RequestMapping、@PathVariable、@RequestBody、@SQL

### 第四阶段：兜底扫描
确认没有遗漏：检查日志、错误处理、调试接口、静态分析结果中的可疑点。

**关键纪律：发现即存证，不要等。write_report 是你的保险。**
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]

    turn = 0
    tool_call_count = 0
    consecutive_no_tools = 0  # Track idle turns — 2 consecutive = done

    while turn < max_turns:
        turn += 1
        if verbose:
            console.print(f"\n[dim]--- Turn {turn}/{max_turns} ---[/dim]")

        response = model_instance.chat_completion(
            messages=messages,
            tools=openai_tools,
            max_tokens=4096,
        )

        # Display assistant text
        if response.content and response.content.strip():
            if verbose:
                console.print(Panel(Markdown(response.content[:500]), title="Agent", border_style="blue"))
            else:
                lines = [l for l in response.content.strip().split("\n") if l.strip() and not l.strip().startswith("```")]
                if lines:
                    last = lines[-1][:120]
                    console.print(f"  [dim]Turn {turn}:[/dim] {last}")

        # Build assistant message for history
        assistant_msg = {"role": "assistant", "content": response.content or ""}
        if response.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }
                }
                for tc in response.tool_calls
            ]
        messages.append(assistant_msg)

        if not response.tool_calls:
            consecutive_no_tools += 1
            if consecutive_no_tools >= 2:
                if verbose:
                    console.print("[green]Agent idle for 2 turns. Audit complete.[/green]")
                break
            continue

        consecutive_no_tools = 0

        # Execute tool calls
        persisted_this_turn = False
        for tc in response.tool_calls:
            fn = tool_map.get(tc.name)
            if not fn:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": f"Error: unknown tool '{tc.name}'",
                })
                continue

            try:
                args = json.loads(tc.arguments)
                result = fn(**args)
                if not isinstance(result, str):
                    result = str(result)

                if len(result) > 50000:
                    result = result[:50000] + "\n... [truncated]"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

                if tc.name == "write_report":
                    persisted_this_turn = True
                    tool_call_count += 1
                    if verbose:
                        console.print(f"  [red]✗ Finding persisted:[/red] {result}")

                if verbose:
                    console.print(f"  [yellow]Tool:[/yellow] {tc.name}(...) → {len(result)} chars")
            except Exception as e:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": f"Error executing {tc.name}: {e}",
                })
                if verbose:
                    console.print(f"  [red]Tool error:[/red] {tc.name}: {e}")

        # Progress indicator for non-verbose mode
        if not verbose and persisted_this_turn:
            console.print(f"  [dim]Turn {turn}: found + persisted[/dim]")

    findings_count = len(get_findings())
    console.print(f"  [yellow]Agent loop finished: {turn} turns, {tool_call_count} findings persisted[/yellow]")
