# agies — AI-native code audit CLI

## Project Overview
AI-native code audit CLI with multi-model LLM support, static analysis, and verification pipeline. Written in Python.

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

### Current file structure (2026-05-25)
```
agies/
├── engine/                       # State machine engine (multi-agent)
│   ├── brain.py                  # Decision loop (submit → poll → execute → register)
│   ├── state.py                  # ProjectState + dedup + checkpoint + blackboard
│   ├── runner.py                 # ThreadPoolExecutor parallel executor
│   ├── context.py                # Context compression + Anthropic prompt cache
│   ├── router.py                 # Priority Router (QuotaMonitor + Crash Defender + percentile)
│   ├── feedback.py               # Cross-scan feedback loop (FeedbackStore persistence)
│   ├── director/                 # Intelligence aggregation (Phase 0)
│   │   ├── __init__.py           # Director orchestrator
│   │   ├── repomap.py            # Risk-weighted PageRank (Aider-based)
│   │   ├── signals.py            # 13 SAST signal types + weights
│   │   └── aggregator.py         # Attack chain cards (EntryAnalysisCard, has_path)
│   ├── sast/                     # SAST pattern matching engine
│   │   ├── __init__.py           # SASTRule, MatchResult models
│   │   ├── matcher.py            # tree-sitter pattern matching engine (302 lines)
│   │   ├── pathfinder.py         # CallChainAnalyzer — Phase B (552 lines)
│   │   └── bound_checker.py      # Recursive depth guard detector
│   ├── rules/
│   │   └── python/               # 6 YAML rules (eval-exec, pickle, zip-slip, etc.)
│   ├── agents/                   # All agent definitions (11 agents)
│   │   ├── base.py               # Agent base class (tool loop + iteration limit + schema)
│   │   ├── mapping.py            # Project structure mapping + trust assumptions
│   │   ├── attack_surface.py     # Entry point discovery (HTTP/CLI/message)
│   │   ├── dataflow.py           # Data flow path tracing
│   │   ├── vulnerability.py      # Legacy vulnerability discovery
│   │   ├── sourcer_agent.py      # Deterministic function index builder (no LLM)
│   │   ├── bulk_analysis_agent.py# Phase 1: per-function LLM bulk scan
│   │   ├── verification_agent.py # Phase 2: tool-using verification per candidate
│   │   ├── verify.py             # Legacy verification agent
│   │   └── report_agent.py       # LLM-powered report generator
│   ├── sourcer/                  # Function-level code indexing
│   │   ├── models.py             # SourceFunction, FunctionIndex, CandidateFinding
│   │   ├── extractor.py          # tree-sitter function + call extraction (Py/Java/JS/TS)
│   │   └── loader.py             # Index builder (auto-traverse, filter, parse)
│   ├── analysis/                 # Phase 1 bulk analysis
│   │   ├── bulk.py               # asyncio parallel LLM analysis per function
│   │   └── prompts.py            # Single-function + multi-function prompt templates
│   ├── prompt/                   # Prompt management system
│   │   ├── models.py             # Pydantic data models (PromptMapping, AgentPrompts, etc.)
│   │   └── manager.py            # PromptManager (YAML → Jinja2 → bind to Agent)
│   ├── prompts/
│   │   └── default.yaml          # All agent prompts as YAML templates
│   └── task_queue/               # Priority task scheduling
│       ├── models.py             # Task, TaskDesc, AgentType, TaskStatus
│       └── queue.py              # TaskQueue (heap + concurrency control + retry)
│
├── llm/                          # LLM provider abstraction (4 providers)
│   ├── base.py                   # Abstract base provider
│   ├── deepseek.py               # Native DeepSeek API (OpenAI SDK)
│   ├── openai_provider.py        # OpenAI API
│   ├── anthropic_provider.py     # Anthropic API (with cache_breakpoint support)
│   ├── ollama.py                 # Local ollama provider
│   └── registry.py               # Auto-select provider by model name
│
├── tools/                        # Deterministic tool layer for agents
│   ├── file_ops.py               # read_file, list_directory
│   ├── search.py                 # grep_search (with Crash Defender integration)
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
4. Implement per checklist
5. Run `python3 -m pytest tests/ -v` before marking done (586 pass, 2 known failures)
6. Update `PROGRESS.md` with date when completing items
7. Update `IDEA.md` if architecture decisions change

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

Completed: All Phase 0-2, Phase 6 Steps 0-9 + Steps A/B/C, SAST Phase A/B, Feedback Loop.

**所有已知问题已在代码中修复**（收敛警告 + Crash Defender + 文本降级 + 确定性注入）。
文档更新日期：2026-05-25。
