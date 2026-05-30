# agies — AI-native Code Audit CLI

[![Tests](https://img.shields.io/badge/tests-627%20passed-brightgreen)](#)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](#)

**agies** is an AI-native code audit engine that combines static analysis with multi-agent LLM orchestration. It finds exploitable vulnerabilities in source code through a hybrid pipeline: deterministic static pre-scan → parallel LLM bulk analysis → tool-using verification → structured report.

Inspired by Theori's AIxCC-winning xint approach and built on academic research (PageRank-weighted call graphs, adaptive iteration scheduling, cross-model verification).

---

## Features

- **Multi-model LLM support**: DeepSeek, OpenAI, Anthropic Claude, local Ollama — pluggable providers
- **tree-sitter SAST engine**: 13 signal types across Python/Java/JS/TypeScript — pattern matching without regex fragility
- **Parallel bulk analysis**: asyncio + semaphore-controlled concurrency with dynamic worker scaling
- **Verification pipeline**: tool-using LLM agents confirm exploitability with evidence chains
- **Cross-model verification**: optional second model validates findings for hallucination reduction
- **Feedback loop**: cross-scan FeedbackStore learns from past results (persistent SQLite)
- **Priority routing**: Crash Defender + Quota Monitor + percentile-based load shedding
- **Context compression**: sliding-window token budget with prompt cache for Anthropic
- **Graph-based analysis (v3)**: Joern CPG integration for Java/JS/C++ — exact call graphs with Docker-based Code Property Graph generation
- **Docker sandbox**: isolated command execution for verification

---

## Installation

```bash
pip install agies
# or from source
git clone https://github.com/xcyjibada/code-agies.git
cd code-agies
pip install -e .
```

Requires Python 3.12+. Set one of these environment variables:

```bash
export DEEPSEEK_API_KEY="sk-..."    # Default model provider
# or
export ANTHROPIC_API_KEY="sk-ant-..."  # Claude models
# or
export OPENAI_API_KEY="sk-..."       # GPT models
```

---

## Quick Start

```bash
# Scan a project for quick static analysis (no API key needed)
agies scan /path/to/project

# Full AI-powered audit
agies audit /path/to/project --model deepseek-chat

# New xint-inspired pipeline (sourcer → bulk analysis → verification)
agies audit /path/to/project --new-pipeline --model deepseek-chat

# Cross-model verification with Claude
agies audit /path/to/project --model deepseek-chat --strong-model claude-sonnet-4-6

# Initialize configuration
agies init /path/to/project
```

---

## CLI Commands

| Command | Description | API Key Required |
|---------|-------------|-----------------|
| `agies audit <target>` | Full AI-powered audit (static + LLM agent + verification) | Yes |
| `agies scan <target>` | Quick static analysis only | No |
| `agies init [target]` | Generate `.agies/config.yml` | No |

### Key Options

| Option | Description |
|--------|-------------|
| `--model` | LLM model (default: `deepseek-chat`) |
| `--strong-model` | Cross-model verification (e.g., `claude-sonnet-4-6`) |
| `--new-pipeline` | Use xint-inspired pipeline (sourcer → bulk → verification) |
| `--no-static` | Skip static analysis phase |
| `--output-format markdown|json` | Report format |
| `--verify/--no-verify` | Toggle verification pipeline |
| `--workers N` | Parallel agent concurrency (default: 5) |
| `--sandbox` | Run verification commands in Docker container |

---

## Architecture

### Two Pipeline Modes

```
Legacy Pipeline (default):
  mapping → attack_surface → dataflow → vulnerability → verify → report

New Pipeline (--new-pipeline):
  mapping → sourcer (tree-sitter function index)
          → bulk_analysis (Phase 1: parallel per-function LLM scan)
          → verification (Phase 2: tool-using agent per candidate)
          → report
```

### Module Layout

```
agies/
├── engine/
│   ├── v2/                          # Xint-style bulk LLM analysis
│   │   ├── brain.py                 # LLM decision loop (submit → poll → execute)
│   │   ├── state.py                 # Project state + dedup + checkpoint
│   │   ├── runner.py                # ThreadPoolExecutor parallel executor
│   │   ├── directors/               # Intelligence aggregation (PageRank + attack path)
│   │   │   ├── repomap.py           # Tag extraction + PageRank (forked from Aider)
│   │   │   ├── aggregator.py        # Attack chain cards + reachability
│   │   │   └── signals.py           # 13 SAST signal types + weights
│   │   ├── agents/                  # 11 agent definitions
│   │   ├── sast/                    # tree-sitter pattern matching
│   │   ├── sourcer/                 # Function-level code indexing
│   │   ├── analysis/                # Phase 1 bulk LLM analysis
│   │   └── rules/                   # SAST YAML rules (6 rules)
│   │
│   ├── graph/                       # v3: Graph-based vulnerability analysis
│   │   ├── base.py                  # GraphGenerator ABC (pluggable interface)
│   │   ├── models.py                # GraphNode, ProgramGraph, ProgramSlice
│   │   ├── joern.py                 # JoernGraphGenerator (Docker CPG)
│   │   ├── joern_docker.py          # Docker lifecycle management
│   │   ├── treesitter.py            # TreeSitterGraphGenerator
│   │   └── codeql.py                # CodeQLGraphGenerator (interface validation)
│   │
│   ├── llm/                         # LLM provider abstraction
│   │   ├── base.py                  # Abstract base provider
│   │   ├── deepseek.py              # DeepSeek API
│   │   ├── openai_provider.py       # OpenAI API
│   │   ├── anthropic_provider.py    # Anthropic (with cache_breakpoint)
│   │   └── ollama.py                # Local Ollama
│   │
│   ├── tools/                       # Deterministic tool layer
│   └── core/                        # Orchestration & CLI
│
├── tests/                           # 627 tests
├── docs/                            # Architecture documentation
│   ├── v1/                          # tree-sitter / SAST era
│   ├── v2/                          # xint-style bulk analysis era
│   └── v3/                          # Graph-based analysis (current phase)
```

### v2 Pipeline Details

```
SAST (tree-sitter, 13 signal types)
    │
    ▼
Director (PageRank + attack path scoring, zero LLM, ~100ms)
    │  Output: EntryAnalysisCard per entry point
    │  - Risk score = PageRank × 0.3 + attack_path × 0.7
    │  - SAST signal aggregation
    │  - Call chain BFS expansion
    ▼
Brain (1 LLM call, strategic decision)
    │  Selects which entry points to analyze
    │  Deterministic shortlist (top 15) → LLM fine-select (3-5)
    ▼
Bulk Analysis (N parallel LLM calls)
    │  Per-function or per-chunk analysis
    │  ~200-400 functions max for large projects
    ▼
Verification (M tool-using LLM calls)
    │  Confirms exploitability with evidence chain
    │  Uses file_ops, search, index_tools
    ▼
Report
```

### v3 Pipeline (In Development)

```
Source code
    │
    ▼
Graph Generator (Joern CPG / tree-sitter / CodeQL)
    │  Exact call graph + data flow edges
    │  Cross-file, cross-language
    ▼
ProgramGraph (unified data model)
    │  - GraphNode (function-level metadata + signals)
    │  - GraphEdge (call sites + data flow)
    │  - File-level signal aggregation
    ▼
GraphGenerator ABC methods:
    ├── build_program_graph()       → ProgramGraph
    ├── compute_page_rank()         → per-node score
    ├── compute_attack_paths()      → entry→sink reachability
    └── create_slices()             → ProgramSlice[]
    │
    ▼
Director / Brain (unchanged from v2)
    │  Consumes ProgramSlice instead of FunctionIndex
    ▼
Verification pipeline (unchanged)
```

---

## SAST Engine

13 signal types with configurable risk weights:

| Signal | Risk Weight | Detection Method |
|--------|-------------|-----------------|
| `dynamic_exec` (eval/exec) | 0.9 | keyword |
| `shell_command` (os.system) | 0.9 | keyword |
| `sql_operation` | 0.8 | keyword |
| `serialization` (pickle) | 0.8 | keyword |
| `regex_operation` | 0.7 | keyword |
| `auth_check` | 0.7 | AST |
| `web_route` | 0.6 | AST |
| `file_operation` | 0.5 | keyword |
| `network_operation` | 0.5 | keyword |
| `user_input_reachable` | 0.9 | call graph BFS |
| `crypto_operation` | 0.4 | keyword |

Negative signals apply weight discounts: `test_code` (0.0), `dead_code` (0.1), `pure_helper` (0.3).

SAST signals are **sensors, not gates** — they influence priority but never block visibility. The Brain (LLM) makes final decisions.

---

## LLM Providers

| Provider | Env Var | Models |
|----------|---------|--------|
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat, deepseek-reasoner |
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4-6, claude-opus-4-7, claude-haiku-4-5 |
| OpenAI | `OPENAI_API_KEY` | gpt-4o, gpt-4o-mini, etc. |
| Ollama | — | ollama/* (local) |

Auto-selected by model name prefix via `llm/registry.py`.

---

## Graph Generators (v3)

| Generator | Language | Method | Status |
|-----------|----------|--------|--------|
| TreeSitterGraphGenerator | Python | tree-sitter AST | ✅ Production |
| JoernGraphGenerator | Java/JS/C++ | Docker CPG (Scala script) | ✅ Production |
| CodeQLGraphGenerator | All | CodeQL CLI | 🔧 Stub (download pending) |

The Director auto-selects the appropriate generator per language: Java/JS/C++ → Joern, Python → tree-sitter.

---

## Configuration

`.agies/config.yml` (auto-generated by `agies init`):

```yaml
project:
  language: auto
  exclude_patterns: ["test_*", "node_modules", "venv"]

llm:
  model: deepseek-chat
  strong_model: claude-sonnet-4-6

analysis:
  new_pipeline: true
  verify: true
  workers: 5

report:
  format: markdown
  output: ./agies-report.md
```

CLI flags override config file, which overrides hardcoded defaults.

---

## Tests

```bash
pytest tests/ -v        # 627 passed, 1 pre-existing failure
pytest tests/ -v --tb=short  # compact output
```

Test categories:
- Unit tests: SAST matcher, function extractor, state management
- Integration: end-to-end pipeline with mock LLM, Director, bulk analysis
- Graph: Joern Docker integration (27 tests), graph models (27 tests)
- Real project vuln detection (vulpy, zipp)

---

## Documentation

- `docs/v1/` — tree-sitter / SAST era design docs
- `docs/v2/` — xint-style bulk analysis architecture + critique
- `docs/v3/` — graph-based vulnerability discovery plan + noise reduction research
- `CLAUDE.md` — Project instructions for AI agents
- `IDEA.md` — Architecture evolution and design decisions
- `PROGRESS.md` — Implementation checklist

---

## License

MIT

---

## Acknowledgments

- **Theori** — AIxCC-winning xint architecture that inspired the v2 pipeline
- **Aider** — RepoMap PageRank algorithm (forked and adapted)
- **SecureLayer7** — Sandyaa RLM research (arxiv 2512.24601)
- **DARPA AIxCC** — Competition that validated the LLM-native audit approach
