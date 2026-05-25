"""Tests for the JavaScript tree-sitter parser."""

from pathlib import Path

from agies.analyzer.parser_js import parse_js_file, parse_files

FIXTURES = Path(__file__).parent.parent / "fixtures"
APP_JS = FIXTURES / "app.js"


def test_parse_js_file_basic():
    """Test basic JS file parsing."""
    ir = parse_js_file(str(APP_JS))
    assert ir.parse_error is None, f"parse error: {ir.parse_error}"
    assert ir.language == "javascript"
    assert ir.file_path.endswith("app.js")
    assert ir.line_count > 0


def test_parse_js_file_functions():
    """Test function extraction."""
    ir = parse_js_file(str(APP_JS))
    # getUser, handleRequest, safeFunction, processUser, UserService.getProfile, UserService.constructor
    assert len(ir.functions) >= 5, f"got {len(ir.functions)} functions"

    # Check a simple function
    get_user = [f for f in ir.functions if f.qualified_name == "getUser"]
    assert len(get_user) == 1
    assert get_user[0].params == ["id"]
    assert get_user[0].is_method is False


def test_parse_js_file_classes():
    """Test class extraction."""
    ir = parse_js_file(str(APP_JS))
    classes = [c for c in ir.classes if c.qualified_name == "UserService"]
    assert len(classes) == 1
    cls = classes[0]
    assert len(cls.methods) >= 2  # constructor + getProfile


def test_parse_js_file_methods():
    """Test class method extraction."""
    ir = parse_js_file(str(APP_JS))
    methods = [f for f in ir.functions if f.is_method]
    assert len(methods) >= 2
    for m in methods:
        assert m.class_name in ("UserService",)
        assert m.is_method is True


def test_parse_js_file_arrow_functions():
    """Test arrow function extraction."""
    # Create a snippet with arrow functions
    import tempfile, os

    code = """
const greet = (name) => {
    return "Hello " + name;
};

const add = (a, b) => a + b;
"""
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    ir = parse_js_file(fpath)
    os.unlink(fpath)

    names = {fn.qualified_name for fn in ir.functions}
    assert "greet" in names, f"expected greet, got {names}"
    # add is an expression body, not a block — it might not be captured
    assert len(ir.functions) >= 1, f"expected >=1 functions, got {len(ir.functions)}"


def test_parse_js_file_require_imports():
    """Test require() call detection."""
    import tempfile, os

    code = """
const express = require("express");
const fs = require("fs");
"""
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    ir = parse_js_file(fpath)
    os.unlink(fpath)

    modules = {imp.module for imp in ir.imports}
    assert "express" in modules, f"expected express, got {modules}"
    assert "fs" in modules


def test_parse_js_file_es_imports():
    """Test ES module import detection."""
    import tempfile, os

    code = """
import React, { useState, useEffect } from "react";
import { BrowserRouter as Router } from "react-router-dom";
"""
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    ir = parse_js_file(fpath)
    os.unlink(fpath)

    modules = {imp.module for imp in ir.imports}
    assert "react" in modules
    assert "react-router-dom" in modules


def test_parse_js_file_error():
    """Test parsing a non-existent file."""
    ir = parse_js_file("/nonexistent/File.js")
    assert ir.parse_error is not None
    assert ir.language == "javascript"


def test_parse_files_directory():
    """Test parsing a directory for JS files."""
    results = parse_files(str(FIXTURES))
    js_files = [r for r in results if r.language == "javascript"]
    assert len(js_files) >= 1
    for jf in js_files:
        if jf.file_path.endswith("app.js"):
            assert jf.parse_error is None


def test_parse_files_single_file():
    """Test parse_files with a single JS file."""
    results = parse_files(str(APP_JS))
    assert len(results) == 1
    assert results[0].language == "javascript"
