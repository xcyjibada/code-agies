"""Phase 0: LLM-based sink discovery.

Extracts all function call names from the project, filters out names already
covered by ``sink_patterns.py``, then asks the LLM to classify the remaining
unknown ones as potentially dangerous sinks.

This replaces the manual process of adding patterns to ``sink_patterns.py``
every time a new dangerous function is discovered.

Usage::

    from agies.engine.v3.pathfinder.sink_discovery import discover_sinks

    extra_sinks = discover_sinks(llm, function_index)
    # extra_sinks = {"custom_exec": VulnType.RCE, ...}

Design
------
Phase 0 runs after ``TreeSitterPathFinder.build_index()`` but before
``run_all()``.  The LLM classifies all non-trivial, unknown function call
names in the project into vulnerability types (RCE, LFI, SSRF, etc.).

Cost: 1 LLM call, typically < 500 input tokens and < 200 output tokens.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from agies.engine.v3.codeql.models import VulnType
from agies.engine.v3.pathfinder.sink_patterns import (
    classify_sink,
    EXACT_SINKS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Call name extraction from function bodies
# ---------------------------------------------------------------------------

# Regex: capture identifier (or qualified name) followed by '('
# Examples: "open(", "subprocess.run(", "self.foo("
_CALL_PATTERN: re.Pattern = re.compile(r"\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(")

# Call names that are never security-relevant as sinks.
_SAFE_NAMES: frozenset[str] = frozenset({
    # Python builtins
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "callable", "chr", "classmethod", "complex", "delattr",
    "dict", "dir", "divmod", "enumerate", "filter", "float", "format",
    "frozenset", "getattr", "globals", "hasattr", "hash", "hex", "id",
    "input", "int", "isinstance", "issubclass", "iter", "len", "list",
    "locals", "map", "max", "memoryview", "min", "next", "object", "oct",
    "ord", "pow", "print", "property", "range", "repr",
    "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod",
    "str", "sum", "super", "tuple", "type", "vars", "zip",
    # Sequence / string methods
    "append", "extend", "insert", "remove", "pop", "clear", "copy",
    "count", "index", "reverse", "sort", "join", "split", "rsplit",
    "splitlines", "strip", "lstrip", "rstrip", "upper", "lower",
    "swapcase", "capitalize", "casefold", "title", "replace", "find",
    "rfind", "index", "rindex", "startswith", "endswith", "encode",
    "decode", "zfill", "center", "ljust", "rjust", "expandtabs",
    "format_map", "translate", "maketrans", "partition", "rpartition",
    # Dict / set methods
    "keys", "values", "items", "get", "setdefault", "popitem",
    "difference", "symmetric_difference", "intersection", "union",
    "update", "discard", "add", "popitem",
    "items", "keys", "values",
    # File-like methods
    "read", "write", "close", "flush", "seek", "tell", "truncate",
    "readable", "writable", "seekable", "fileno", "isatty",
    "readline", "readlines", "writelines",
    # Logging
    "debug", "info", "warning", "error", "critical", "exception", "log",
    # Test / assert
    "assertEqual", "assertNotEqual", "assertTrue", "assertFalse",
    "assertIs", "assertIsNot", "assertIsNone", "assertIsNotNone",
    "assertIn", "assertNotIn", "assertIsInstance", "assertNotIsInstance",
    "assertRaises", "assertRaisesRegex", "assertWarns", "assertWarnsRegex",
    "assertLogs", "assertAlmostEqual", "assertNotAlmostEqual",
    "assertGreater", "assertGreaterEqual", "assertLess", "assertLessEqual",
    "assertRegex", "assertNotRegex", "assertCountEqual",
    "assertMultiLineEqual", "assertSequenceEqual", "assertListEqual",
    "assertTupleEqual", "assertSetEqual", "assertDictEqual",
    "fail", "skipTest", "skipIf", "skipUnless", "expectedFailure",
    # Dunder (special) methods — never security-relevant
    "__call__", "__init__", "__init_subclass__", "__new__",
    "__del__", "__repr__", "__str__", "__contains__",
    "__enter__", "__exit__", "__aenter__", "__aexit__",
    "__iter__", "__next__", "__len__", "__getitem__",
    "__setitem__", "__delitem__", "__eq__", "__hash__",
    "__lt__", "__le__", "__gt__", "__ge__", "__ne__",
    "__bool__", "__int__", "__float__", "__neg__",
    "__pos__", "__abs__", "__invert__",
    # Decorator / descriptor
    "property", "abstractmethod", "cached_property",
    # os.path (benign query methods)
    "abspath", "dirname", "basename", "normpath", "realpath", "relpath",
    "exists", "isfile", "isdir", "islink", "ismount", "isabs",
    "samefile", "sameopenfile", "samestat",
    "commonpath", "commonprefix", "expanduser", "expandvars",
    "normcase", "lexists", "supports_unicode_filenames",
    # re (safe pattern building)
    "escape",
    # json (safe ser/de)
    "dumps", "loads", "dump", "load",
    # time
    "time", "sleep", "localtime", "gmtime", "strftime", "strptime",
    "mktime", "asctime", "ctime", "perf_counter", "monotonic",
    "process_time", "thread_time",
    # Math / random
    "randint", "random", "uniform", "choice", "shuffle", "sample",
    "seed", "getrandbits",
    # Typing / dataclasses
    "field", "dataclass",
    # Itertools / functools
    "chain", "cycle", "repeat", "accumulate", "product", "permutations",
    "combinations", "groupby", "partial", "reduce", "lru_cache",
    "wraps", "singledispatch", "cache",
    # Contextlib
    "contextmanager", "suppress", "closing", "redirect_stdout",
    # Collections
    "namedtuple", "defaultdict", "Counter", "OrderedDict", "deque",
    # Enum
    "Enum", "IntEnum", "Flag", "IntFlag", "auto",
    # Pathlib
    "cwd", "home", "stat", "lstat", "chmod", "exists", "is_dir",
    "is_file", "is_symlink", "is_socket", "is_fifo", "is_block_device",
    "is_char_device", "iterdir", "glob", "rglob", "absolute",
    "resolve", "samefile", "mkdir", "rmdir", "rename", "replace",
    "symlink_to", "hardlink_to", "touch",
    # Shutil (safe)
    "copymode", "copystat", "copytree", "rmtree", "move",
    "make_archive", "get_archive_formats", "get_unpack_formats",
    "disk_usage", "chown", "which", "disk_usage",
    # Subprocess (safe)
    "PIPE", "DEVNULL", "CalledProcessError", "SubprocessError",
    "TimeoutExpired",
    # Tempfile (safe)
    "mkstemp", "mkdtemp", "mkdtemp", "NamedTemporaryFile",
    "SpooledTemporaryFile", "TemporaryDirectory",
    # Unittest
    "main", "skip", "skipIf", "skipUnless", "expectedFailure",
    "TestCase",
    # Asyncio
    "run", "sleep", "gather", "wait", "wait_for", "as_completed",
    "ensure_future", "create_task", "run_coroutine_threadsafe",
    "run_in_executor", "shield", "timeout", "to_thread",
    "get_event_loop", "new_event_loop", "set_event_loop",
    "get_running_loop", "all_tasks", "current_task",
    "iscoroutine", "iscoroutinefunction", "isgeneratorfunction",
    "Queue", "Lock", "Semaphore", "Event", "Condition",
    # Web framework neutral
    "status_code", "json", "headers", "cookies", "text", "content",
    "raise_for_status", "elapsed", "encoding", "history",
    "iter_content", "iter_lines",
    # Django/Flask/Pydantic
    "save", "delete", "filter", "exclude", "order_by", "annotate",
    "aggregate", "values", "values_list", "distinct", "first",
    "last", "get_or_create", "update_or_create", "bulk_create",
    "bulk_update", "select_related", "prefetch_related",
    "only", "defer", "using", "select_for_update", "explain",
    "extra", "raw",
    # Pytest
    "fixture", "mark", "parametrize", "skip", "skipif", "xfail",
    "raises", "warns", "approx",
    # Pydantic
    "model_dump", "model_dump_json", "model_validate",
    "model_validate_json",
})

# Build set of names already covered by EXACT_SINKS
_KNOWN_SINKS: set[str] = set()
for name, _ in EXACT_SINKS:
    _KNOWN_SINKS.add(name)
    _KNOWN_SINKS.add(name.split(".")[-1])


def extract_calls(function_index) -> set[str]:
    """Extract all unique function call names from the project.

    Iterates every ``SourceFunction.body`` in the index and extracts
    call patterns using a lightweight regex (no tree-sitter re-parse).
    Returns a deduplicated set of call names, including qualified names.
    """
    calls: set[str] = set()
    for fn in function_index.funcs:
        body = fn.body
        if not body:
            continue
        for match in _CALL_PATTERN.finditer(body):
            name = match.group(1).strip()
            if not name or len(name) <= 1 or name.isdigit():
                continue
            calls.add(name)
    return calls


def _is_likely_function_call(name: str) -> bool:
    """Heuristic: is ``name`` a potential function call (not a class constructor)?

    Filters out obvious class/type references like ``ActionOutput``, ``ValueError``,
    ``BeautifulSoup``, but keeps qualified calls like ``Tool.from_code`` and
    private functions like ``_execute_code`` where the dangerous stuff often lives.
    """
    short = name.split(".")[-1] if "." in name else name
    # Built-in constants are never function calls
    if short in ("True", "False", "None"):
        return False
    # Dunder methods are never sinks
    if short.startswith("__") and short.endswith("__"):
        return False
    # Names like "import", "code", "pickle" — these were found by regex in
    # ambiguous contexts.  Drop bare nouns with no '.', no '_', and no verb suffix.
    if "." not in name and not name.startswith("_"):
        # Keep only if it looks verb-like (ends with typical verb suffixes)
        if not any(name.endswith(suf) for suf in ("run", "exec", "eval", "load",
            "dump", "read", "write", "open", "call", "send", "get", "set",
            "put", "post", "delete", "patch", "head", "fetch", "push", "pull",
            "create", "build", "parse", "convert", "process", "handle",
            "check", "validate", "verify", "encode", "decode", "import",
            "install", "execute", "compile", "search", "filter", "extract",
            "transform", "generate", "dispatch", "route", "serve",
            "init", "config", "format", "render", "apply", "merge",
            "split", "join", "clean", "escape", "resolve", "normalize")):
            return False
    return True


def filter_unknown(calls: set[str]) -> set[str]:
    """Keep only call names NOT already covered by ``sink_patterns.py``
    or the safe list.

    A name is "known" if it (or its short form) appears in EXACT_SINKS,
    matches ``classify_sink()``, or is in the safe-name list.
    """
    unknown: set[str] = set()
    for name in calls:
        short = name.split(".")[-1] if "." in name else name
        if name in _KNOWN_SINKS or short in _KNOWN_SINKS:
            continue
        if classify_sink(name) is not None:
            continue
        if name in _SAFE_NAMES or short in _SAFE_NAMES:
            continue
        # Skip names with common verbs appended (teardown, setup, cleanup)
        if short.startswith("test_") or short.endswith("_test"):
            continue
        # Skip dunder methods (filtered in _SAFE_NAMES but also catch all __xx__)
        if short.startswith("__") and short.endswith("__"):
            continue
        # Heuristic: skip names that don't look like function calls
        if not _is_likely_function_call(name):
            continue
        unknown.add(name)
    return unknown


def classify_via_llm(
    llm: Any,
    unknown_calls: set[str],
    max_calls: int = 200,
) -> dict[str, VulnType]:
    """Ask the LLM to classify unknown call names as dangerous sinks.

    Parameters
    ----------
    llm : LLMProvider
        The LLM provider (must support ``chat_completion``).
    unknown_calls : set[str]
        Function call names not covered by existing patterns.
    max_calls : int
        Maximum call names to include in the prompt (default 200).
        Names are sorted alphabetically before truncation for
        deterministic behaviour.

    Returns
    -------
    dict[str, VulnType]
        Mapping of function name -> VulnType for calls the LLM flagged
        as dangerous.  Only entries where ``VulnType`` is valid are
        included.
    """
    if not unknown_calls:
        return {}

    sorted_calls = sorted(unknown_calls)
    if len(sorted_calls) > max_calls:
        logger.info(
            "Phase 0: %d unknown calls, truncating to %d",
            len(sorted_calls), max_calls,
        )
        sorted_calls = sorted_calls[:max_calls]

    calls_text = "\n".join(f"- {name}" for name in sorted_calls)

    prompt = f"""You are a security expert analyzing function call names from a Python project.
For each function name below, determine if it could be a DANGEROUS SINK when an attacker controls its arguments.

Only flag a function if it realistically processes attacker-controlled input leading to a vulnerability.
Classification options (use the EXACT string):
- RCE: code/command execution (subprocess, eval, os.system, pickle.loads, deserialization)
- LFI: file read (open, read_file, etc.)
- SSRF: outbound HTTP request (requests, urlopen, httpx, etc.)
- SQLI: SQL injection (execute, raw_query, etc.)
- AFO: arbitrary file write (write, shutil.copy, zipfile.extractall, etc.)
- SSTI: template injection (render_template_string, Template, etc.)
- XXE: XML external entity (etree.parse, fromstring, SAXParser, etc.)
- REDOS: ReDoS via regex (re.compile with attacker pattern, fnmatch, etc.)
- IDOR: direct object reference (get_object_or_404, etc.)
- SUSPICIOUS: potentially dangerous but unclear which class
- null: SAFE — definitely not a sink

Respond with ONLY a JSON object like: {{"func_name": "RCE", "other_func": "LFI", ...}}
Use null for safe functions. Do NOT wrap in markdown.

Functions to classify:
{calls_text}
"""

    try:
        response = llm.chat_completion(
            [{"role": "user", "content": prompt}],
            # No response_format constraint — it makes DeepSeek overly conservative
        )
        if not response or not response.content:
            logger.warning("Phase 0: LLM returned empty response")
            return {}

        content = response.content.strip()
        # Strip markdown code fences if present
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
            content = content.rsplit("\n```", 1)[0]
        content = content.strip()

        result = json.loads(content)
        if not isinstance(result, dict):
            logger.warning("Phase 0: LLM returned non-dict: %s", type(result))
            return {}

        vtype_map = {v.value: v for v in VulnType}
        sinks: dict[str, VulnType] = {}
        for name, vtype_str in result.items():
            if not vtype_str or vtype_str in ("null", "None", "none"):
                continue
            vtype_str = vtype_str.strip().lower()
            vt = vtype_map.get(vtype_str)
            if vt is not None and vt != VulnType.UNKNOWN:
                sinks[name] = vt

        logger.info(
            "Phase 0: LLM flagged %d/%d calls as sinks",
            len(sinks), len(sorted_calls),
        )
        return sinks

    except json.JSONDecodeError as e:
        logger.warning("Phase 0: LLM JSON parse error: %s", e)
        logger.debug("Raw content: %s", response.content[:500] if response else "N/A")
    except Exception as e:
        logger.warning("Phase 0: LLM call failed: %s", e)

    return {}


def discover_sinks(
    llm: Any,
    function_index,
    max_calls: int = 200,
) -> dict[str, VulnType]:
    """Run the full Phase 0 pipeline: extract → filter → LLM classify.

    Usage from ``runner.py``::

        from agies.engine.v3.pathfinder.sink_discovery import discover_sinks
        extra_sinks = discover_sinks(llm, function_index)
        finder.set_extra_sinks(extra_sinks)

    Parameters
    ----------
    llm : LLMProvider
        LLM provider for classification.
    function_index : FunctionIndex
        The project's function index (must have call graph populated).
    max_calls : int
        Max call names to send to LLM (default 200).

    Returns
    -------
    dict[str, VulnType]
        Newly discovered sink function names mapped to their vulnerability
        type.  Empty dict when discovery fails or finds nothing new.
    """
    all_calls = extract_calls(function_index)
    unknown = filter_unknown(all_calls)
    logger.info(
        "Phase 0: %d total calls, %d unknown after filtering",
        len(all_calls), len(unknown),
    )

    if not unknown:
        logger.info("Phase 0: no unknown calls — all covered by existing patterns.")
        return {}

    return classify_via_llm(llm, unknown, max_calls=max_calls)
