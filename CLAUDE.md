# agies — AI-native code audit CLI

## Project Overview
AI-native code audit CLI with multi-model LLM support, static analysis, and verification pipeline. Written in Python.

## Core Development Principles

- **通用性优先** — 必须保持高度通用性，能有效支持各种 Python/JS/TS 项目，而不是仅适配当前测试的特定靶子。
- **以大多数为准** — 所有修改都必须以「大多数真实开源项目和 Bounty 程序」的平均情况为准，禁止针对单个靶子的特性做硬编码或特殊优化。
- **target-specific hack 必须标记** — 如果某个优化只对特定靶子特别有效，必须明确标记为「target-specific hack」，并提供通用 fallback 方案。
- **最小改动 + 最大泛化** — 优先考虑「最小必要改动」+「最大泛化能力」。在提出任何修改方案前，先思考：「这个改动在 LangChain、FastAPI、Django、Next.js、Flask 大项目上是否仍然合理？」
- **每次修改附泛化评估** — 在每次修改建议的最后额外输出一段：【泛化评估】：这个改动对其他项目的潜在影响是？可能引入的过拟合风险等级（低/中/高）及理由。

## Quick Reference

### Commands
- `agies audit <target>` — Full audit (static + LLM agent + verification)
- `agies audit <target> --new-pipeline` — New Xint-inspired pipeline (sourcer → bulk → verification)
- `agies scan <target>` — Quick scan (static only, no API key needed)
- `agies init [target]` — Generate `.agies/config.yml`
- `agies init [target] --ci` — Also generate CI/CD templates

### BountyBench Test (zipp CVE-2024-5569)
```bash
agies audit /tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c \
  --new-pipeline --no-static --model deepseek-chat --output-format markdown
```

### Key CLI Options
- `--model <name>` — Default: `deepseek-chat`. Also: `gpt-*`, `claude-*`, `ollama/*`
- `--strong-model <name>` — Cross-model verification model
- `--verify/--no-verify` — Enable/disable verification pipeline
- `--new-pipeline/--no-new-pipeline` — Toggle Xint-inspired pipeline
- `--no-static` — Skip static analysis phase
- `--workers N` — Parallel agent concurrency (default: 5)
- `--output-format markdown|json`

## Architecture

### Current file structure (2026-06-08)
```
agies/
├── engine/                       # Engine — v2 (xint-style) + v3 (path-slice) + graph
│   ├── v2/                       # v2: per-function bulk LLM analysis pipeline
│   │   ├── brain.py              # Decision loop (submit → poll → execute → register)
│   │   ├── state.py              # ProjectState + dedup + checkpoint + blackboard
│   │   ├── runner.py             # ThreadPoolExecutor parallel executor
│   │   ├── context.py            # Context compression + Anthropic prompt cache
│   │   ├── router.py             # Priority Router (QuotaMonitor + Crash Defender)
│   │   ├── feedback.py           # Cross-scan feedback loop persistence
│   │   ├── director/             # Intelligence aggregation (Phase 0)
│   │   │   ├── __init__.py       # Director orchestrator (run, get_neighbors)
│   │   │   ├── repomap.py        # Signal-weighted PageRank (from Aider)
│   │   │   ├── signals.py        # 13 SAST signal types + weights
│   │   │   ├── aggregator.py     # Attack chain cards (EntryAnalysisCard)
│   │   │   └── queries/          # .scm tag queries (py/java/js/ts)
│   │   ├── sast/                 # SAST pattern matching engine
│   │   │   ├── __init__.py       # SASTRule, MatchResult models
│   │   │   ├── matcher.py        # tree-sitter pattern matching (302 lines)
│   │   │   ├── pathfinder.py     # CallChainAnalyzer — Phase B (574 lines)
│   │   │   └── bound_checker.py  # Recursive depth guard detector
│   │   ├── agents/               # 11 agent definitions
│   │   │   ├── base.py           # Agent base class (tool loop + iteration limit)
│   │   │   ├── mapping.py        # Project structure + trust assumptions
│   │   │   ├── attack_surface.py # Entry point discovery
│   │   │   ├── dataflow.py       # Data flow path tracing
│   │   │   ├── vulnerability.py  # Legacy vulnerability discovery
│   │   │   ├── sourcer_agent.py  # Deterministic function index builder
│   │   │   ├── bulk_analysis_agent.py  # Phase 1: per-function LLM scan
│   │   │   ├── verification_agent.py   # Phase 2: tool-using verification
│   │   │   ├── verify.py         # Legacy verification agent
│   │   │   └── report_agent.py   # LLM-powered report generator
│   │   ├── sourcer/              # Function-level code indexing
│   │   │   ├── models.py         # SourceFunction, FunctionIndex, CandidateFinding
│   │   │   ├── extractor.py      # tree-sitter fn + call extraction (Py/Java/JS/TS)
│   │   │   └── loader.py         # Index builder (traverse, filter, parse)
│   │   ├── analysis/             # Phase 1 bulk analysis
│   │   │   ├── bulk.py           # asyncio parallel per-function LLM analysis
│   │   │   └── prompts.py        # Single/multi-function prompt templates
│   │   ├── prompt/               # Prompt management (YAML + Jinja2)
│   │   │   ├── models.py         # Pydantic models (PromptMapping, AgentPrompts)
│   │   │   └── manager.py        # PromptManager (load → compile → bind)
│   │   ├── prompts/
│   │   │   └── default.yaml      # All agent prompts as YAML templates
│   │   ├── task_queue/           # Priority task scheduling
│   │   │   ├── models.py         # Task, TaskDesc, AgentType, TaskStatus
│   │   │   └── queue.py          # TaskQueue (heap + concurrency + retry)
│   │   └── rules/
│   │       └── python/           # 6 YAML rules (eval-exec, pickle, zip-slip, etc.)
│   │
│   ├── v3/                       # v3: source→sink path slicing + Intent/Logic agents
│   │   ├── __init__.py           # Module doc
│   │   ├── runner.py             # Main orchestrator (tree-sitter → slice → LLM → verify)
│   │   ├── classifier.py         # Project type classifier (app vs lib)
│   │   ├── codeql/               # CodeQL integration (models + query + queries/)
│   │   ├── slicer/               # Path sorting engine (score_path, select_top_k)
│   │   │   ├── models.py         # PathSlice, SortResult
│   │   │   └── sorter.py         # score_path, select_top_k, is_anomalous
│   │   ├── pathfinder/           # Tree-sitter source→sink path discovery
│   │   │   ├── sink_patterns.py  # Sink definitions per vuln type
│   │   │   └── treesitter.py     # TreeSitterPathFinder (reverse caller trace)
│   │   ├── prompts/              # 8 vuln-type prompts (+ ReDoS)
│   │   │   ├── rce.py / lfi.py / ssrf.py / sqli.py / xss.py / afo.py / idor.py
│   │   │   ├── redos.py          # ReDoS prompt (non-vulnhuntr)
│   │   │   └── readme_summary.py # README summary prompt
│   │   ├── aggregator/           # Blackboard + Intent cache
│   │   │   ├── __init__.py
│   │   │   ├── blackboard.py     # BlackboardAggregator (Intent cache + knowledge)
│   │   │   └── models.py         # CachedIntent, KnowledgeEntry, AgentPhaseResult
│   │   └── agents/               # 9 agent definitions
│   │       ├── __init__.py
│   │       ├── intent_agent.py       # 4-5 functions → developer intent pseudocode
│   │       ├── logic_agent.py        # Pseudocode chain → contradiction detection
│   │       ├── merge.py              # Deterministic Intent output arrangement
│   │       ├── path_code_loader.py   # Path coords → function grouping + cache query
│   │       ├── aggregator.py         # Multi-path merge + sort
│   │       ├── bridge_verifier.py    # Attribute taint bridge path analysis
│   │       ├── evidence_checker.py   # Code-level evidence verification
│   │       ├── adversary_agent.py    # Devil's advocate rebuttal
│   │       └── poc_agent.py          # PoC script generation
│   │
│   ├── graph/                    # Graph generators (Joern/tree-sitter/CodeQL)
│   │   ├── base.py               # GraphGenerator ABC
│   │   ├── models.py             # GraphNode, ProgramGraph, ProgramSlice
│   │   ├── joern.py              # JoernGraphGenerator (Docker CPG)
│   │   ├── joern_docker.py       # Docker lifecycle management
│   │   ├── treesitter.py         # TreeSitterGraphGenerator
│   │   ├── codeql.py             # CodeQLGraphGenerator
│   │   └── codeql_queries/       # QL query files
│   │
│   └── __init__.py
│
├── llm/                          # LLM provider abstraction (4 providers)
│   ├── base.py                   # Abstract base provider
│   ├── deepseek.py               # Native DeepSeek API (OpenAI SDK)
│   ├── openai_provider.py        # OpenAI API
│   ├── anthropic_provider.py     # Anthropic API (cache_breakpoint support)
│   ├── ollama.py                 # Local ollama provider
│   └── registry.py               # Auto-select provider by model name
│
├── tools/                        # Deterministic tool layer for agents
│   ├── file_ops.py               # read_file, list_directory
│   ├── search.py                 # grep_search (with Crash Defender)
│   ├── index_tools.py            # lookup_function, find_callers, find_callees, record_knowledge
│   ├── command.py                # Shell command execution
│   └── report.py                 # Legacy report generation
│
├── core/                         # Orchestration & CLI
│   ├── auditor.py                # run_audit + _run_new_pipeline bridge
│   ├── config.py                 # Configuration loading
│   ├── scanner.py                # Static analysis scanner
│   └── report.py                 # Report output
│
├── analyzer/                     # Legacy static analysis (being phased out)
├── verification/                 # Legacy verification pipeline
├── strategy/                     # File prioritization
├── rules/                        # Audit rule prompts
├── tests/
├── pocs/                         # Generated PoC scripts
└── cli.py                        # Typer CLI
```

### Two Pipeline Modes

**Legacy pipeline** (default, `use_new_pipeline=False`):
```
mapping → attack_surface → dataflow → vulnerability → verify → report
```

**New pipeline** (`--new-pipeline`, `use_new_pipeline=True`):
```
mapping → sourcer (tree-sitter function index, no LLM)
        → bulk_analysis (Phase 1: parallel per-function LLM scan, over-zealous)
        → verification (Phase 2: tool-using agent per candidate, deep analysis)
        → report
```

### Key Design Decisions
- CLI > `.agies/config.yml` > hardcoded defaults (priority order)
- tree-sitter for cross-language parsing (not regex)
- Graceful degradation: LLM failure → heuristic fallback
- **DeepSeek native API**: Uses OpenAI SDK at `https://api.deepseek.com`. Falls back to `ANTHROPIC_API_KEY` env var when `DEEPSEEK_API_KEY` not set.
- **kwargs safety**: All index_tools accept `**kwargs` to survive LLMs that send extra params.
- **Iteration limit final call**: Strips trailing tool call/result pair and passes `tools=[]` to force JSON output.
- **Report bridge**: New pipeline findings bridged from `state.verified_findings` to legacy `_findings` for CLI report.

### API keys
| Env Var | Provider | Required for |
|---------|----------|-------------|
| `DEEPSEEK_API_KEY` | DeepSeek (default model) | Agent pipeline |
| `ANTHROPIC_API_KEY` | Claude / DeepSeek fallback | Cross-model verification |
| `OPENAI_API_KEY` | GPT models | Alternative models |

`DEEPSEEK_API_KEY` takes priority. When only `ANTHROPIC_API_KEY` is set, DeepSeek provider uses it as API key against `https://api.deepseek.com`.

## Development Workflow
1. Read `IDEA.md` for current architecture thinking and design decisions
2. Read `PROGRESS.md` for current state and task checklist
3. Read `DEVELOPMENT.md` for original architecture context
4. Read `docs/v3/plan.md` for v3 graph-based vulnerability discovery plan
5. Read `docs/v3/noise_reduction_research.md` for noise reduction research
6. Implement per checklist
7. Run `python3 -m pytest tests/ -v` before marking done (**703 pass, 1 known failure** — test_missing_api_key)
8. Update `PROGRESS.md` with date when completing items
9. Update `IDEA.md` if architecture decisions change

### Archive Docs
- `docs/v1/` — tree-sitter / SAST era docs (cahe.md, sandyaa_paper.md, etc.)
- `docs/v2/` — graph layer / Joern / CodeQL era docs (ARCHITECTURE-v2.md, etc.)
- `docs/v3/` — graph-based vulnerability discovery (当前阶段)

### Roadmap
- `docs/huntr_roadmap.md` — huntr 路线图，P0（重分类）→ P1（ML 扩展）→ P2（CodeQL）

### Quick Test
```bash
python3 -m pytest tests/ -v --tb=short 2>&1 | tail -30
```

### BountyBench Round-trip
```bash
agies audit /tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c \
  --new-pipeline --no-static --model deepseek-chat --output-format markdown
```

## Current Status
See `PROGRESS.md` for detailed checklist. See `IDEA.md` for architecture design.

Completed: v2 Phases 0-9, Steps A-F, SAST Phase A/B, Feedback Loop. v3 P0-P8 (pending CodeQL CLI for P1/P9).

**所有已知问题已在代码中修复**（收敛警告 + Crash Defender + 文本降级 + 确定性注入）。
文档更新日期：2026-06-08。
