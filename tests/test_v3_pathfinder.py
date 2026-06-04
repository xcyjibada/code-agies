"""Tests for v3 TreeSitterPathFinder and sink patterns."""

from __future__ import annotations

from agies.engine.v3.codeql.models import VulnType
from agies.engine.v3.pathfinder.sink_patterns import (
    classify_sink,
    is_entry_point,
    KNOWN_SINK_NAMES,
    EXACT_SINKS,
)


class TestClassifySink:
    def test_rce_sinks(self):
        """exec/eval/subprocess should be classified as RCE."""
        for name in ["exec", "eval", "compile", "os.system", "os.popen",
                      "subprocess.call", "subprocess.Popen", "subprocess.run"]:
            assert classify_sink(name) == VulnType.RCE, f"{name} should be RCE"

    def test_pickle_sinks(self):
        """pickle/cloudpickle/yaml loads should be classified as RCE."""
        for name in ["pickle.loads", "pickle.load", "yaml.load",
                      "cloudpickle.load", "marshal.loads"]:
            assert classify_sink(name) == VulnType.RCE, f"{name} should be RCE (deserialization)"

    def test_lfi_sinks(self):
        """open/read functions should be classified as LFI."""
        for name in ["open", "pathlib.Path.open",
                      "pathlib.Path.read_text", "pathlib.Path.read_bytes"]:
            assert classify_sink(name) == VulnType.LFI, f"{name} should be LFI"

    def test_ssrf_sinks(self):
        """urlopen/httpx should be classified as SSRF."""
        for name in ["urlopen", "urlretrieve",
                      "urllib.request.urlopen", "httpx.Client",
                      "aiohttp.ClientSession"]:
            assert classify_sink(name) == VulnType.SSRF, f"{name} should be SSRF"

    def test_sqli_sinks(self):
        """execute/executemany should be classified as SQLI."""
        for name in ["execute", "executemany", "executescript"]:
            assert classify_sink(name) == VulnType.SQLI, f"{name} should be SQLI"

    def test_xss_sinks(self):
        """render_template_string/Markup should be classified as XSS."""
        assert classify_sink("render_template_string") == VulnType.XSS
        assert classify_sink("Markup") == VulnType.XSS

    def test_afo_sinks(self):
        """write_text/shutil.copy should be classified as AFO."""
        assert classify_sink("pathlib.Path.write_text") == VulnType.AFO
        assert classify_sink("shutil.copy") == VulnType.AFO

    def test_unknown_sink(self):
        """Unknown function names should return None."""
        assert classify_sink("some_random_func") is None
        assert classify_sink("validateUser") is None
        assert classify_sink("") is None

    def test_regex_sinks(self):
        """Regex patterns should catch variations."""
        assert classify_sink("execute_command") == VulnType.RCE
        assert classify_sink("read_file") == VulnType.LFI
        assert classify_sink("fetch") == VulnType.SSRF
        assert classify_sink("query") == VulnType.SQLI


class TestIsEntryPoint:
    def test_http_methods(self):
        """GET/POST/PUT/DELETE should be entry points."""
        assert is_entry_point("get")
        assert is_entry_point("post")
        assert is_entry_point("delete")

    def test_handler_patterns(self):
        """handle_XXX / XXX_handler should be entry points."""
        assert is_entry_point("handle_request")
        assert is_entry_point("request_handler")
        assert is_entry_point("on_message")

    def test_main_functions(self):
        """main/run/serve/start should be entry points."""
        assert is_entry_point("main")
        assert is_entry_point("run")
        assert is_entry_point("serve")

    def test_non_entry_points(self):
        """Internal functions should not be entry points."""
        assert not is_entry_point("validate")
        assert not is_entry_point("transform")
        assert not is_entry_point("helper")


class TestSinkPatternsExact:
    def test_all_exact_sinks_have_known_names(self):
        """Every exact sink should be in KNOWN_SINK_NAMES."""
        for name, vtype in EXACT_SINKS:
            assert name in KNOWN_SINK_NAMES or name.split(".")[-1] in KNOWN_SINK_NAMES

    def test_all_exact_sinks_classify_correctly(self):
        """Every exact sink should classify back to itself."""
        for name, expected_vtype in EXACT_SINKS:
            result = classify_sink(name)
            assert result == expected_vtype, (
                f"{name} → {result}, expected {expected_vtype}"
            )


class TestTreeSitterPathFinderIntegration:
    """Integration tests against the existing test data.

    These tests require tree-sitter parsers to be installed.
    """

    def test_build_index_on_project_root(self):
        """Should build an index on the project's own source code."""
        from agies.engine.v3.pathfinder.treesitter import TreeSitterPathFinder
        import os

        # Use this project's own source dir as test data
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        source_dir = os.path.join(project_root, "agies", "engine")

        finder = TreeSitterPathFinder(source_dir)
        index = finder.build_index()

        assert index is not None
        assert len(index.funcs) > 0, "Should find functions in engine/"

    def test_run_all_queries(self):
        """Should run all queries without crashing."""
        from agies.engine.v3.pathfinder.treesitter import TreeSitterPathFinder
        import os

        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        source_dir = os.path.join(project_root, "agies", "engine")

        finder = TreeSitterPathFinder(source_dir)
        results = finder.run_all()

        assert isinstance(results, list)
        for r in results:
            assert hasattr(r, "vuln_type")
            assert hasattr(r, "total_sinks")
