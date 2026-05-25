"""Tests for the Java tree-sitter parser."""

from pathlib import Path

from agies.analyzer.parser_java import parse_java_file, parse_files

FIXTURES = Path(__file__).parent.parent / "fixtures"
CONTROLLER = FIXTURES / "UserController.java"


def test_parse_java_file_basic():
    """Test basic Java file parsing."""
    ir = parse_java_file(str(CONTROLLER))
    assert ir.parse_error is None, f"parse error: {ir.parse_error}"
    assert ir.language == "java"
    assert ir.file_path.endswith("UserController.java")
    assert ir.line_count > 0


def test_parse_java_file_classes():
    """Test class extraction."""
    ir = parse_java_file(str(CONTROLLER))
    assert len(ir.classes) == 1
    cls = ir.classes[0]
    assert cls.qualified_name == "UserController"
    assert cls.file_path.endswith("UserController.java")


def test_parse_java_file_functions():
    """Test method extraction."""
    ir = parse_java_file(str(CONTROLLER))
    assert len(ir.functions) >= 4  # getUser(x2), createUser, getProfile, notAHandler

    # Check a handler method
    handlers = [f for f in ir.functions if f.decorators]
    assert len(handlers) >= 2  # at least @GetMapping and @PostMapping


def test_parse_java_file_getUser():
    """Test specific method details."""
    ir = parse_java_file(str(CONTROLLER))
    get_users = [f for f in ir.functions if f.qualified_name.endswith("getUser")]
    assert len(get_users) >= 1
    get_user = get_users[0]

    assert get_user.is_method is True
    assert get_user.class_name == "UserController"
    assert "id" in get_user.params
    assert "GetMapping" in get_user.decorators


def test_parse_java_file_createUser():
    """Test method with @RequestParam."""
    ir = parse_java_file(str(CONTROLLER))
    creators = [f for f in ir.functions if f.qualified_name.endswith("createUser")]
    assert len(creators) >= 1
    create = creators[0]

    assert "PostMapping" in create.decorators
    assert "input" in create.params
    assert create.is_method is True


def test_parse_java_file_imports():
    """Test import extraction."""
    ir = parse_java_file(str(CONTROLLER))
    modules = {imp.module for imp in ir.imports}
    assert "org.springframework.web.bind.annotation.GetMapping" in modules
    assert "org.springframework.web.bind.annotation.PostMapping" in modules
    assert "org.springframework.web.bind.annotation.RequestParam" in modules


def test_parse_java_file_not_a_handler():
    """Test method without handler annotation."""
    ir = parse_java_file(str(CONTROLLER))
    non_handlers = [f for f in ir.functions if f.qualified_name.endswith("notAHandler")]
    assert len(non_handlers) >= 1
    nh = non_handlers[0]

    assert nh.decorators == []  # no annotations
    assert "safe" in nh.params


def test_parse_java_file_error():
    """Test parsing a non-existent file."""
    ir = parse_java_file("/nonexistent/File.java")
    assert ir.parse_error is not None
    assert ir.language == "java"


def test_parse_files_directory():
    """Test parsing a directory for Java files."""
    results = parse_files(str(FIXTURES))
    java_files = [r for r in results if r.language == "java"]
    assert len(java_files) >= 1
    # Should not have parse errors for the clean controller
    for jf in java_files:
        if jf.file_path.endswith("UserController.java"):
            assert jf.parse_error is None


def test_parse_files_single_file():
    """Test parse_files with a single Java file."""
    results = parse_files(str(CONTROLLER))
    assert len(results) == 1
    assert results[0].language == "java"
