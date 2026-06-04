"""Tests for v3 prompts module."""

from agies.engine.v3.prompts import get_prompt, PROMPT_BUILDERS


class TestGetPrompt:
    def test_rce_prompt_format(self):
        """RCE prompt should contain key markers."""
        prompt = get_prompt("rce", code_block="print('test')", readme_summary="A web app")
        assert "Remote Code Execution" in prompt
        assert "code_block" not in prompt  # template should be filled
        assert "exec/eval/subprocess" in prompt or "exec/eval" in prompt
        assert "A web app" in prompt

    def test_lfi_prompt_format(self):
        """LFI prompt should contain key markers."""
        prompt = get_prompt("lfi")
        assert "Local File Inclusion" in prompt or "Path Traversal" in prompt

    def test_ssrf_prompt_format(self):
        """SSRF prompt should contain key markers."""
        prompt = get_prompt("ssrf")
        assert "Server-Side Request Forgery" in prompt

    def test_sqli_prompt_format(self):
        """SQLI prompt should contain key markers."""
        prompt = get_prompt("sqli")
        assert "SQL Injection" in prompt

    def test_xss_prompt_format(self):
        """XSS prompt should contain key markers."""
        prompt = get_prompt("xss")
        assert "Cross-Site Scripting" in prompt

    def test_afo_prompt_format(self):
        """AFO prompt should contain key markers."""
        prompt = get_prompt("afo")
        assert "Arbitrary File Overwrite" in prompt

    def test_idor_prompt_format(self):
        """IDOR prompt should contain key markers."""
        prompt = get_prompt("idor")
        assert "Insecure Direct Object Reference" in prompt

    def test_unknown_type_fallback(self):
        """Unknown vuln type should use generic prompt."""
        prompt = get_prompt("unknown_type", code_block="code here")
        assert "code here" in prompt

    def test_all_builders_are_callable(self):
        """All entries in PROMPT_BUILDERS should be callable."""
        for name, builder in PROMPT_BUILDERS.items():
            result = builder(code_block="test", readme_summary="test")
            assert isinstance(result, str), f"{name} did not return a string"
            assert len(result) > 50, f"{name} prompt too short"

    def test_readme_prompt(self):
        """README summary prompt should format correctly."""
        from agies.engine.v3.prompts.readme_summary import build_readme_prompt
        prompt = build_readme_prompt("This is a test README with API server info.")
        assert "test README" in prompt or "API" in prompt
        assert "```json" in prompt
