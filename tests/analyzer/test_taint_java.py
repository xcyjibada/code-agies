"""Tests for the Java taint propagation engine."""

from pathlib import Path

from agies.analyzer.parser_java import parse_java_file, parse_files
from agies.analyzer.symbol_table import SymbolTableBuilder
from agies.analyzer.call_graph import CallGraphBuilder
from agies.analyzer.config import AnalysisConfig, _default_java_config
from agies.analyzer.taint_java import TaintEngineJava

FIXTURES = Path(__file__).parent.parent / "fixtures"
CONTROLLER = FIXTURES / "UserController.java"


def _setup_engine(file_path: str) -> TaintEngineJava:
    """Helper to build a TaintEngineJava from a file."""
    ir = parse_java_file(file_path)
    builder = SymbolTableBuilder([ir])
    symbol_table = builder.build()
    cg_builder = CallGraphBuilder([ir], symbol_table)
    call_graph = cg_builder.build()
    java_cfg = _default_java_config()
    return TaintEngineJava(java_cfg, symbol_table, call_graph)


def test_taint_detects_exec_with_tainted_param():
    """getUser: id → query → Runtime.exec(query) should be detected."""
    engine = _setup_engine(str(CONTROLLER))
    paths = engine.analyze()
    # Should find at least Runtime.exec paths from tainted params
    exec_paths = [p for p in paths if p.sink_rule_name in ("exec", "Runtime.exec")]
    assert len(exec_paths) >= 1, f"No exec taint paths found. Got {len(paths)} total paths."


def test_taint_detects_multiple_sinks():
    """Both getUser and createUser have taint-to-sink patterns."""
    engine = _setup_engine(str(CONTROLLER))
    paths = engine.analyze()
    # Expecting at minimum 2 findings (getUser exec, createUser exec)
    assert len(paths) >= 2, f"Expected >=2 taint paths, got {len(paths)}"


def test_taint_source_seeded_from_handler_params():
    """Handler method params should be seeded as sources."""
    engine = _setup_engine(str(CONTROLLER))
    paths = engine.analyze()
    # TaintPath source.detail references the original param name
    # (e.g. "propagated from id" references the seeded source)
    param_refs = []
    for p in paths:
        detail = p.source.detail
        if "id" in detail or "input" in detail:
            param_refs.append(detail)
    assert len(param_refs) >= 1, f"no path references id/input: {[p.source.detail for p in paths]}"
    # The propagation source should mention the handler param
    assert any("id" in p.source.detail or "input" in p.source.detail for p in paths)


def test_taint_ignores_non_handler():
    """notAHandler has no annotation, so its params should not be seeded."""
    engine = _setup_engine(str(CONTROLLER))
    paths = engine.analyze()
    # notAHandler's 'safe' param should not be a source
    for p in paths:
        assert "safe" not in p.source.detail, "non-handler param should not be seeded as source"


def test_taint_deduplication():
    """Same sink (file, line, call) should not produce duplicate paths."""
    engine = _setup_engine(str(CONTROLLER))
    paths = engine.analyze()

    # Check no duplicates by (sink_file, sink_line, sink_expr)
    seen: set[tuple[str, int, str]] = set()
    for p in paths:
        key = (p.sink.file_path, p.sink.line, p.sink.variable_or_expr)
        assert key not in seen, f"duplicate taint path at {key}"
        seen.add(key)


def test_taint_with_standalone_java_snippet():
    """Test a minimal Java snippet not from the fixture."""
    import tempfile, os

    code = """
class Test {
    // Simulate a servlet-like handler (no Spring annotations)
    public String unsafe(String userInput) {
        try {
            Runtime rt = Runtime.getRuntime();
            rt.exec(userInput);
        } catch (Exception e) {
            // ignore
        }
        return "done";
    }
}
"""
    with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    engine = _setup_engine(fpath)
    paths = engine.analyze()
    os.unlink(fpath)

    # This handler has no @GetMapping annotation, so params won't be seeded
    exec_paths = [p for p in paths if "exec" in p.sink_rule_name]
    assert len(exec_paths) == 0, "non-handler method should not have tainted params"


def test_taint_with_handler_annotation():
    """Test that @GetMapping seeds params as sources for taint."""
    import tempfile, os

    code = """
import org.springframework.web.bind.annotation.GetMapping;

class TestController {
    @GetMapping
    public String search(String query) {
        Runtime.getRuntime().exec(query);
        return query;
    }
}
"""
    with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    engine = _setup_engine(fpath)
    paths = engine.analyze()
    os.unlink(fpath)

    assert len(paths) >= 1, "@GetMapping handler should seed params as sources"
    assert any("query" in p.source.detail for p in paths)


def test_inline_taint_propagation():
    """Test that taint propagates through string concatenation."""
    import tempfile, os

    code = """
import org.springframework.web.bind.annotation.GetMapping;

class VulnController {
    @GetMapping
    public String handle(String input) {
        String cmd = "echo " + input;
        Runtime.getRuntime().exec(cmd);
        return cmd;
    }
}
"""
    with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    engine = _setup_engine(fpath)
    paths = engine.analyze()
    os.unlink(fpath)

    assert len(paths) >= 1
    # The propagation should happen: input tainted → cmd tainted → exec(cmd) sink
    assert any("input" in p.source.detail for p in paths), "source should be 'input' param"
