# agies Engine Refactoring Plan

> Goal: Restructure from "file-level probe" → "function-level pipeline"
> Modeled on Theori/Xint CRS architecture (`theori-io/aixcc-afc-archive`)
> Date: 2026-05-14

---

## Current Architecture

```
Mapping (LLM picks key_files)
    ↓
VulnerabilityAgent × key_file (per-file deep analysis)
    ↓
State: candidate_vulnerabilities
```

**Problems:**
- Coverage limited to Mapping Agent's selected key_files (~15 files)
- No systematic function-level analysis
- No two-phase discovery + verification separation
- Cross-function vulnerabilities easily missed

---

## Target Architecture

```
                          sourcer/ (function index)
                    tree-sitter parse ALL functions
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
           analysis/bulk.py     analysis/bulk.py
           (single-function)    (multi-function chunked)
                    │                    │
                    └─────────┬──────────┘
                              ▼
                    Phase 1: CandidateFindings
                    (low precision, high recall)
                              │
                              ▼
                    VerificationAgent
                    (tools: lookup, find_callers,
                     find_callees, read_source)
                              │
                              ▼
                    Phase 2: VerifiedFindings
                    (high precision)
                              │
                              ▼
                    ReportAgent
```

### Agent Flow (Brain iterations)

```
Iter 1:  Mapping Agent              → project structure + key_files
Iter 2:  Build FunctionIndex        → `sourcer/` (no LLM, deterministic)
Iter 3:  Bulk analysis (Phase 1)    → parallel LLM per function/chunk
Iter 4..N: Verify (Phase 2)        → VerificationAgent per candidate
Iter N+1: Report Agent              → final report
```

---

## New Modules

### 1. `engine/sourcer/models.py` — Data structures

```python
@dataclass
class SourceFunction:
    name: str               # function name
    fullname: str           # parent_class::method_name
    file_path: str
    line_start: int
    line_end: int
    body: str               # function source code
    signature: str          # parameter declarations

@dataclass
class FunctionIndex:
    sources: dict[str, SourceFile]
    funcs: list[SourceFunction]
    name_index: dict[str, list[SourceFunction]]   # by function name
    file_index: dict[str, list[SourceFunction]]   # by file path
```

### 2. `engine/sourcer/extractor.py` — tree-sitter function extraction

Based on Xint's `c_tree_sitter.py` / `java_tree_sitter.py`.

Languages: Python, Java, JavaScript/TypeScript.

Each parser is ~50-100 lines: a tree-sitter query + loop extracting matches into SourceFunction.

Reuses `analyzer/parser_java.py` and `analyzer/parser_js.py` (adapt output format).

### 3. `engine/sourcer/loader.py` — Walk files → Build index

```python
def build_index(project_path: str) -> FunctionIndex:
    for file_path in walk_files(project_path):
        lang = detect_language(file_path)
        parser = get_parser(lang)
        source_file = SourceFile(file_path, read(file_path))
        functions = parser.extract(source_file)
        index.add(source_file, functions)
    index.build_call_graph()  # reuse analyzer/call_graph.py
    return index
```

### 4. `engine/sourcer/chunker.py` — Multi-mode file grouping

Based on Xint's `full.py` token-based chunking.

Algorithm: group files sharing common tokens into chunks. Same-chunk files likely reference the same data structures/functions, enabling cross-function reasoning in a single LLM call.

### 5. `engine/analysis/prompts.py` — Prompt templates

Translate Xint's `FullModeSingleC` / `FullModeMultiC` prompts:

- **Single-function mode**: LLM outputs `sinks` (over-zealous), `vulns` (subset), `invariants` (assumptions)
- **Multi-function mode**: LLM outputs interprocedural analysis with file paths per function
- **Key rule**: "don't report simple wrappers — the caller will be reported"

### 6. `engine/analysis/bulk.py` — Phase 1 parallel LLM calls

Two modes:

```python
class BulkAnalyzer:
    def analyze_single(index: FunctionIndex, llm, concurrency=50)
        # Each function → one LLM call, parallel via asyncio.gather
        # Returns list[CandidateFinding]

    def analyze_multi(index: FunctionIndex, llm, concurrency=10)
        # Chunk → one LLM call, parallel
        # Returns list[CandidateFinding]
```

Output: `CandidateFinding(file, function, type, severity, description, reasoning, sink_type)`

---

## Modified Modules

### 7. `engine/agents/vulnerability.py` → VerificationAgent

Change role from "discover vulnerabilities" to "verify candidates".

New tool set:
- `lookup_function(name)` — query FunctionIndex
- `find_callers(name)` — who calls this function
- `find_callees(name)` — what does this function call
- `read_source(path, lines)` — read source code
- `grep_search(pattern)` — search codebase

Input: `CandidateFinding` from Phase 1
Output: `VerifiedFinding(triggerable: bool, conditions: str, false_positive_reason: str)`

### 8. `engine/state.py` — New state fields

```python
# Add to ProjectState:
function_index: FunctionIndex | None = None
candidates: list[CandidateFinding] = field(default_factory=list)
# verified_findings already exists
```

### 9. `engine/brain.py` — Updated dispatch

Add new agent types:
- `sourcer` (deterministic, no LLM)
- `bulk_analysis` (Phase 1)
- `verification` (Phase 2, replaces old vulnerability Mode 1/2)

---

## Unchanged Modules

| Module | Reason |
|--------|--------|
| `llm/` | Provider abstraction unchanged |
| `analyzer/call_graph.py` | Reused by `sourcer/loader.py` |
| `analyzer/parser_java.py` | Reused by `sourcer/extractor.py` |
| `analyzer/parser_js.py` | Reused by `sourcer/extractor.py` |
| `tools/` | New tools added, existing kept |
| `verification/` | Unchanged for now |
| `cli.py` | Entry point unchanged |
| `engine/runner.py` | Parallel executor unchanged |
| `engine/agents/base.py` | Base class unchanged |
| `engine/agents/mapping.py` | Unchanged (still first step) |

---

## Implementation Order

```
Day 1:  engine/sourcer/models.py        — data structures
Day 1:  engine/sourcer/extractor.py     — tree-sitter function extraction
Day 2:  engine/sourcer/loader.py        — index builder
Day 2:  engine/analysis/prompts.py      — prompt templates
Day 3:  engine/analysis/bulk.py         — Phase 1 parallel analysis
Day 3:  engine/sourcer/chunker.py       — multi-mode grouping
Day 4:  engine/agents/vulnerability.py  → VerificationAgent rewrite
Day 4:  engine/state.py                 — new state fields
Day 5:  engine/brain.py                 — updated dispatch + integration tests
```

---

## Cost Comparison

| | Current | After refactor |
|---|---|---|
| LLM calls per scan | ~15 (1 per key_file) | ~N functions + M candidates |
| Cost (1000-func project) | ~$0.14 | ~$0.14 (Flash Phase 1) + $0.17 (Pro Phase 2) |
| Coverage | Key files only | All functions |
| Cross-function detection | Limited | Multi-mode chunks + verification tools |

## Model Usage Strategy

Two-tier model support (already supported by `--model` / `--strong-model`):

| Phase | Recommended Model | Cost |
|-------|-------------------|------|
| Phase 1 (bulk scan) | `deepseek-v4-flash` | $0.14/M tokens |
| Phase 2 (verification) | `deepseek-v4-pro` | $1.74/M tokens |

Configured via `.agies/config.yml`:
```yaml
llm:
  model: deepseek-v4-flash
  strong_model: deepseek-v4-pro
```
