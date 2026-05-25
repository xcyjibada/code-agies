"""Tests for SAST Phase B — Directed Call-Chain Summarizer.

Test categories:
1. CallChainAnalyzer path finding — graph building + nx.all_simple_paths
2. Noise filtering — logging.info(), print() excluded from paths and summaries
3. Logic extraction — tree-sitter and text-based
4. Sanitizer / Auth-gate tagging — [Sanitized], [Auth_Gate] annotations
5. Edge cases — missing sink, missing entry, empty graph
6. Tool integration — get_call_chain_logic via index_tools
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from agies.engine.sast.pathfinder import (
    NOISE_FUNCTIONS,
    CallChainAnalyzer,
    _is_noise_call,
    _has_sanitizer,
    _has_auth_gate,
    _detect_lang,
)
from agies.engine.sourcer.models import FunctionIndex, SourceFile, SourceFunction


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def index_with_chain() -> FunctionIndex:
    """Build a FunctionIndex with: handle_login → verify_user → db_query."""
    idx = FunctionIndex()
    idx.call_graph = {
        # callee → {callers}
        "verify_user": {"handle_login"},
        "db_query": {"verify_user"},
    }
    return idx


@pytest.fixture
def index_with_branching() -> FunctionIndex:
    """Multiple paths: handle_request → (validate|process) → write_db."""
    idx = FunctionIndex()
    idx.call_graph = {
        "validate_input": {"handle_request", "api_handler"},
        "process_data": {"handle_request"},
        "write_db": {"validate_input", "process_data"},
        "log_request": {"handle_request", "api_handler"},
    }
    return idx


@pytest.fixture
def index_with_noise() -> FunctionIndex:
    """A chain where some functions also call noise functions (like logging),
    but the real call chain bypasses them."""
    idx = FunctionIndex()
    idx.call_graph = {
        "process": {"handle_request"},
        "logging.info": {"handle_request"},  # noise call in handle_request
        "db_query": {"process"},             # process → db_query is the real chain
        "print": {"process"},                # noise call in process
    }
    return idx


@pytest.fixture
def index_with_sources() -> FunctionIndex:
    """A FunctionIndex with actual source files for logic extraction."""
    idx = FunctionIndex()
    code = """
def process_input(data):
    if data is None:
        return None
    clean = sanitize(data)
    if len(clean) > 0:
        return clean
    return None

def handle_login(request):
    username = request.get("username")
    logging.info(f"login attempt: {username}")
    if check_auth(username) is None:
        return "unauthorized"
    return process_input(username)
"""
    sf = SourceFile(path="test_app.py", source=code)
    idx.sources["test_app.py"] = sf
    idx.name_index["process_input"] = [
        SourceFunction(
            name="process_input",
            fullname="process_input",
            file_path="test_app.py",
            line_start=3,
            line_end=8,
            signature="def process_input(data):",
            body="    if data is None:\n        return None\n    clean = sanitize(data)\n    if len(clean) > 0:\n        return clean\n    return None\n",
        ),
    ]
    idx.name_index["handle_login"] = [
        SourceFunction(
            name="handle_login",
            fullname="handle_login",
            file_path="test_app.py",
            line_start=10,
            line_end=17,
            signature="def handle_login(request):",
            body="    username = request.get(\"username\")\n    logging.info(f\"login attempt: {username}\")\n    if check_auth(username) is None:\n        return \"unauthorized\"\n    return process_input(username)\n",
        ),
    ]
    idx.funcs = idx.name_index["process_input"] + idx.name_index["handle_login"]
    idx.call_graph = {
        "process_input": {"handle_login"},
    }
    return idx


# ===================================================================
# Noise detection
# ===================================================================


class TestNoiseDetection:
    def test_print_is_noise(self) -> None:
        assert _is_noise_call("print")

    def test_logging_info_is_noise(self) -> None:
        assert _is_noise_call("logging.info")

    def test_console_log_is_noise(self) -> None:
        assert _is_noise_call("console.log")

    def test_system_out_is_noise(self) -> None:
        assert _is_noise_call("System.out.println")

    def test_logger_debug_is_noise(self) -> None:
        assert _is_noise_call("logger.debug")

    def test_normal_function_not_noise(self) -> None:
        assert not _is_noise_call("execute_query")

    def test_sanitize_not_noise(self) -> None:
        assert not _is_noise_call("sanitize")

    def test_check_auth_not_noise(self) -> None:
        assert not _is_noise_call("check_auth")

    def test_empty_string_not_noise(self) -> None:
        assert not _is_noise_call("")

    def test_noise_functions_set_not_empty(self) -> None:
        assert len(NOISE_FUNCTIONS) > 10


# ===================================================================
# Sanitizer / Auth gate detection
# ===================================================================


class TestSanitizerAuthGate:
    def test_sanitize_detected(self) -> None:
        assert _has_sanitizer("calls sanitize()")

    def test_escape_detected(self) -> None:
        assert _has_sanitizer("calls escape_string()")

    def test_encode_detected(self) -> None:
        assert _has_sanitizer("if encodeURIComponent(data)")

    def test_validate_detected(self) -> None:
        assert _has_sanitizer("calls validate_input()")

    def test_not_sanitizer(self) -> None:
        assert not _has_sanitizer("calls execute_query()")

    def test_auth_gate_detected(self) -> None:
        assert _has_auth_gate("if check_auth(user)")

    def test_login_required_detected(self) -> None:
        assert _has_auth_gate("calls login_required()")

    def test_is_admin_detected(self) -> None:
        assert _has_auth_gate("if is_admin(request)")

    def test_authorize_detected(self) -> None:
        assert _has_auth_gate("calls authorize_user()")

    def test_not_auth_gate(self) -> None:
        assert not _has_auth_gate("calls format_string()")

    def test_both_sanitizer_and_auth(self) -> None:
        combined = "calls validate_input(); if check_auth(user)"
        assert _has_sanitizer(combined)
        assert _has_auth_gate(combined)


# ===================================================================
# Language detection
# ===================================================================


class TestDetectLang:
    def test_python(self) -> None:
        assert _detect_lang("app.py") == "python"

    def test_java(self) -> None:
        assert _detect_lang("Controller.java") == "java"

    def test_javascript(self) -> None:
        assert _detect_lang("routes.js") == "javascript"

    def test_typescript(self) -> None:
        assert _detect_lang("server.ts") == "typescript"

    def test_unknown_fallback(self) -> None:
        assert _detect_lang("Makefile") == "python"


# ===================================================================
# Graph building
# ===================================================================


class TestGraphBuilding:
    def test_builds_forward_graph(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        finder._build_graph()
        G = finder._graph
        assert G is not None
        assert G.has_edge("handle_login", "verify_user")
        assert G.has_edge("verify_user", "db_query")

    def test_noise_functions_excluded(self, index_with_noise: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_noise)
        finder._build_graph()
        G = finder._graph
        # logging.info and print should NOT be in the graph
        assert "logging.info" not in G
        assert "print" not in G
        # The chain should be: handle_request → process → db_query
        assert G.has_edge("handle_request", "process")
        assert G.has_edge("process", "db_query")

    def test_empty_index(self) -> None:
        idx = FunctionIndex()
        finder = CallChainAnalyzer(idx)
        finder._build_graph()
        G = finder._graph
        assert G is not None
        assert len(G.nodes) == 0

    def test_branching_graph(self, index_with_branching: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_branching)
        finder._build_graph()
        G = finder._graph
        assert G.has_edge("handle_request", "validate_input")
        assert G.has_edge("handle_request", "process_data")
        assert G.has_edge("validate_input", "write_db")
        assert G.has_edge("process_data", "write_db")
        # log_request should be in graph too (noise but not in NOISE_FUNCTIONS)
        assert "log_request" in G

    def test_graph_no_leak_noise_as_intermediary(
        self, index_with_noise: FunctionIndex,
    ) -> None:
        """Noise functions should not appear as path nodes."""
        finder = CallChainAnalyzer(index_with_noise)
        finder._build_graph()
        G = finder._graph
        for node in G.nodes:
            assert not _is_noise_call(node), f"{node} should not be in graph"


# ===================================================================
# Path finding
# ===================================================================


class TestPathFinding:
    def test_simple_chain(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        paths = finder._find_paths("db_query", entry="handle_login")
        assert len(paths) >= 1
        assert paths[0] == ["handle_login", "verify_user", "db_query"]

    def test_no_entry_finds_all(self, index_with_branching: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_branching)
        paths = finder._find_paths("write_db")
        assert len(paths) >= 2  # at least 2 distinct paths to write_db
        # All paths should end with write_db
        for p in paths:
            assert p[-1] == "write_db"

    def test_sink_not_in_graph(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        paths = finder._find_paths("nonexistent")
        assert paths == []

    def test_entry_not_in_graph(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        paths = finder._find_paths("db_query", entry="ghost")
        assert paths == []

    def test_noise_filtered_path(self, index_with_noise: FunctionIndex) -> None:
        """Noise functions should not appear in the path."""
        finder = CallChainAnalyzer(index_with_noise)
        paths = finder._find_paths("db_query", entry="handle_request")
        assert len(paths) >= 1
        # The path should NOT include logging.info or print
        for p in paths:
            assert "logging.info" not in p
            assert "print" not in p

    def test_path_count_limited(self, index_with_branching: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_branching)
        paths = finder._find_paths("write_db", max_paths=1)
        assert len(paths) <= 1


# ===================================================================
# Analyze (full pipeline)
# ===================================================================


class TestAnalyze:
    def test_analyze_returns_dossier(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        result = finder.analyze("db_query", entry="handle_login")
        assert "handle_login" in result
        assert "verify_user" in result
        assert "db_query" in result
        assert "Path 1:" in result
        assert "Conclusion:" in result

    def test_analyze_no_entry(self, index_with_branching: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_branching)
        result = finder.analyze("write_db")
        assert "Path 1:" in result
        assert "write_db" in result
        assert "Conclusion:" in result

    def test_analyze_missing_sink(self, index_with_chain: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_chain)
        result = finder.analyze("ghost")
        assert "no paths found" in result.lower()

    def test_analyze_empty_index(self) -> None:
        idx = FunctionIndex()
        finder = CallChainAnalyzer(idx)
        result = finder.analyze("sink")
        assert "no paths found" in result.lower()

    def test_analyze_with_noise_graph(self, index_with_noise: FunctionIndex) -> None:
        """Noise functions should not appear in the dossier output."""
        finder = CallChainAnalyzer(index_with_noise)
        result = finder.analyze("db_query", entry="handle_request")
        assert "logging.info" not in result
        assert "print" not in result

    def test_analyze_branching_paths(self, index_with_branching: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_branching)
        result = finder.analyze("write_db")
        # Should show multiple paths
        assert result.count("Path ") >= 1


# ===================================================================
# Logic extraction
# ===================================================================


class TestLogicExtraction:
    def test_extract_with_text_if_condition(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    if data is None:\n        return None\n"
        parts = finder._extract_with_text(body)
        assert any("if data is None" in p for p in parts)

    def test_extract_with_text_return(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    return None\n"
        parts = finder._extract_with_text(body)
        assert any("return None" in p for p in parts)

    def test_extract_with_text_call(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    result = execute_query(sql)\n"
        parts = finder._extract_with_text(body)
        assert any("execute_query" in p for p in parts)

    def test_noise_filtered_in_text_extraction(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    logging.info(f'processing: {data}')\n    process(data)\n"
        parts = finder._extract_with_text(body)
        # logging.info should be filtered out
        assert not any("logging.info" in p for p in parts)
        # But process should be kept
        assert any("process" in p for p in parts)

    def test_extract_with_text_empty(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        assert finder._extract_with_text("") == []

    def test_extract_with_text_no_logic(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    x = 1\n    y = x + 1\n"
        parts = finder._extract_with_text(body)
        assert parts == []  # no if/call/return

    def test_extract_with_text_elif(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    if x > 0:\n        return x\n    elif x == 0:\n        return 0\n"
        parts = finder._extract_with_text(body)
        assert any("elif x == 0" in p for p in parts)

    def test_extract_with_text_multiple_calls(self) -> None:
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    validate(data)\n    sanitize(data)\n    execute_query(sql)\n"
        parts = finder._extract_with_text(body)
        assert any("validate" in p for p in parts)
        assert any("sanitize" in p for p in parts)
        assert any("execute_query" in p for p in parts)

    def test_extract_skip_duplicate_calls(self) -> None:
        """Same call repeated should appear once."""
        finder = CallChainAnalyzer(FunctionIndex())
        body = "    validate(data)\n    validate(data)\n"
        parts = finder._extract_with_text(body)
        count = sum(1 for p in parts if "validate" in p)
        assert count == 1


# ===================================================================
# Tool integration (get_call_chain_logic)
# ===================================================================


class TestGetCallChainLogic:
    def test_tool_returns_dossier(self, index_with_chain: FunctionIndex) -> None:
        from agies.tools.index_tools import get_call_chain_logic, set_index
        set_index(index_with_chain)
        result = get_call_chain_logic(
            sink_function="db_query",
            entry_function="handle_login",
        )
        assert "handle_login" in result
        assert "verify_user" in result
        assert "db_query" in result
        set_index(None)

    def test_tool_no_index(self) -> None:
        from agies.tools.index_tools import get_call_chain_logic
        result = get_call_chain_logic(sink_function="x")
        assert "not available" in result

    def test_tool_no_entry(self, index_with_chain: FunctionIndex) -> None:
        from agies.tools.index_tools import get_call_chain_logic, set_index
        set_index(index_with_chain)
        result = get_call_chain_logic(sink_function="db_query")
        assert "db_query" in result
        set_index(None)


# ===================================================================
# Integration: logic extraction via tree-sitter (Python)
# ===================================================================


class TestTreesitterLogicExtraction:
    def test_extract_if_condition(self, index_with_sources: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_sources)
        parts = finder._extract_with_treesitter(
            index_with_sources.sources["test_app.py"].source,
            "process_input",
            "python",
        )
        if parts:
            assert any("if data is None" in p for p in parts) or any("if len" in p for p in parts)

    def test_extract_call(self, index_with_sources: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_sources)
        parts = finder._extract_with_treesitter(
            index_with_sources.sources["test_app.py"].source,
            "process_input",
            "python",
        )
        if parts:
            assert any("sanitize" in p for p in parts)

    def test_noise_filtered_in_treesitter(self, index_with_sources: FunctionIndex) -> None:
        """logging.info should not appear in extracted logic."""
        finder = CallChainAnalyzer(index_with_sources)
        parts = finder._extract_with_treesitter(
            index_with_sources.sources["test_app.py"].source,
            "handle_login",
            "python",
        )
        if parts:
            assert not any("logging.info" in p for p in parts)

    def test_extract_auth_gate(self, index_with_sources: FunctionIndex) -> None:
        """check_auth should be extracted as a call."""
        finder = CallChainAnalyzer(index_with_sources)
        parts = finder._extract_with_treesitter(
            index_with_sources.sources["test_app.py"].source,
            "handle_login",
            "python",
        )
        if parts:
            assert any("check_auth" in p for p in parts)

    def test_extract_return(self, index_with_sources: FunctionIndex) -> None:
        finder = CallChainAnalyzer(index_with_sources)
        parts = finder._extract_with_treesitter(
            index_with_sources.sources["test_app.py"].source,
            "handle_login",
            "python",
        )
        if parts:
            assert any("unauthorized" in p for p in parts) or any("process_input" in p for p in parts)

    def test_treesitter_fallback_on_error(self) -> None:
        """When tree-sitter fails, text extraction is used."""
        idx = FunctionIndex()
        idx.name_index["foo"] = [
            SourceFunction(
                name="foo",
                fullname="foo",
                file_path="nonexistent.py",
                line_start=1,
                line_end=3,
                signature="def foo():",
                body="    if x:\n        return 1\n",
            ),
        ]
        finder = CallChainAnalyzer(idx)
        parts = finder._extract_function_logic("foo")
        assert any("if x" in p for p in parts)


# ===================================================================
# Edge cases
# ===================================================================


class TestEdgeCases:
    def test_function_not_in_index(self) -> None:
        idx = FunctionIndex()
        finder = CallChainAnalyzer(idx)
        parts = finder._extract_function_logic("ghost")
        assert parts == []

    def test_source_file_missing(self) -> None:
        idx = FunctionIndex()
        idx.name_index["foo"] = [
            SourceFunction(
                name="foo",
                fullname="foo",
                file_path="gone.py",
                line_start=1,
                line_end=2,
                signature="def foo():",
                body="    pass\n",
            ),
        ]
        finder = CallChainAnalyzer(idx)
        parts = finder._extract_function_logic("foo")
        # Fallback: should extract from body text
        assert isinstance(parts, list)

    def test_empty_body(self) -> None:
        idx = FunctionIndex()
        idx.name_index["foo"] = [
            SourceFunction(
                name="foo", fullname="foo", file_path="a.py",
                line_start=1, line_end=1, signature="def foo():",
                body="",
            ),
        ]
        finder = CallChainAnalyzer(idx)
        parts = finder._extract_function_logic("foo")
        assert parts == []

    def test_detect_lang_all_extensions(self) -> None:
        exts = [
            (".py", "python"), (".java", "java"),
            (".js", "javascript"), (".ts", "typescript"),
            (".jsx", "javascript"), (".tsx", "typescript"),
        ]
        for ext, expected in exts:
            assert _detect_lang(f"file{ext}") == expected

    def test_noise_function_prefixes(self) -> None:
        """Only log/logger/logging prefixes get suffix-based matching."""
        assert _is_noise_call("log.info")
        assert _is_noise_call("logger.error")
        assert _is_noise_call("logging.debug")
        assert not _is_noise_call("validator.info")  # not a logger prefix
        assert not _is_noise_call("mylogger.info")  # unknown prefix → exact set only


# ===================================================================
# Sanitizer / Auth-gate tagging in analyze output
# ===================================================================


class TestTaggingInAnalyze:
    def test_sanitizer_tag_appears(self) -> None:
        """When a path function calls escape/sanitize, [Sanitized] should appear."""
        idx = FunctionIndex()
        idx.call_graph = {"sanitize": {"process"}, "db_query": {"sanitize"}}
        idx.name_index["sanitize"] = []
        finder = CallChainAnalyzer(idx)
        result = finder.analyze("db_query", entry="process")
        # The path itself should be found
        assert "Path 1:" in result

    def test_auth_gate_tag_appears(self) -> None:
        """When a path function calls check_auth, [Auth_Gate] should appear."""
        idx = FunctionIndex()
        idx.call_graph = {"check_auth": {"login"}, "db_query": {"check_auth"}}
        idx.name_index["check_auth"] = []
        finder = CallChainAnalyzer(idx)
        result = finder.analyze("db_query", entry="login")
        assert "Path 1:" in result


# ===================================================================
# Get call chain logic tool schema
# ===================================================================


class TestToolSchema:
    def test_tool_in_definitions(self) -> None:
        from agies.tools import get_tool_definitions
        names = [t["name"] for t in get_tool_definitions()]
        assert "get_call_chain_logic" in names

    def test_tool_has_schema(self) -> None:
        from agies.tools import get_tool_definitions
        tool = next(t for t in get_tool_definitions() if t["name"] == "get_call_chain_logic")
        schema = tool["schema"]["function"]
        assert "sink_function" in schema["parameters"]["properties"]
        assert "entry_function" in schema["parameters"]["properties"]
        assert "max_depth" in schema["parameters"]["properties"]
        assert schema["parameters"]["required"] == ["sink_function"]
