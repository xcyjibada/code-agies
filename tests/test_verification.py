"""Tests for the verification pipeline."""
import os
import tempfile
import json

from agies.verification import (
    VerificationPipeline,
    FileExistenceValidator,
    LineNumberValidator,
    ContradictionDetector,
    VerificationResult,
)


def test_file_existence_validator_found():
    """File that exists should pass."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("x = 1\n")
        tmp_path = f.name

    try:
        validator = FileExistenceValidator(target_root=os.path.dirname(tmp_path))
        finding = {"file_path": tmp_path}
        result = validator.validate(finding)
        assert result.file_exists is True
        assert result.file_corrected is False
        # Finding should be unchanged
        assert finding["file_path"] == tmp_path
    finally:
        os.unlink(tmp_path)


def test_file_existence_validator_not_found():
    """Non-existent file should fail."""
    validator = FileExistenceValidator(target_root="/tmp")
    finding = {"file_path": "/nonexistent/path/that/does/not/exist.py"}
    result = validator.validate(finding)
    assert result.file_exists is False
    assert len(result.evidence_chain) > 0
    assert result.evidence_chain[0]["status"] == "failed"


def test_file_existence_validator_no_path():
    """Finding without file_path should be skipped."""
    validator = FileExistenceValidator(target_root="/tmp")
    finding = {"title": "test"}
    result = validator.validate(finding)
    assert result.evidence_chain[0]["status"] == "skipped"


def test_file_existence_outside_target():
    """File outside target boundary should be rejected."""
    tmp = tempfile.mkdtemp()
    outside = os.path.join(tempfile.mkdtemp(), "test.py")
    try:
        open(outside, "w").close()
        validator = FileExistenceValidator(target_root=tmp)
        finding = {"file_path": outside}
        result = validator.validate(finding)
        # It would find the file but it's outside the target boundary
        # Actually the validator only checks existence + boundary
        # Let me check: does it reject outside files?
        assert result.file_exists is True  # File exists
        assert result.evidence_chain[-1]["status"] == "failed"  # But boundary check fails
    finally:
        os.unlink(outside)
        os.rmdir(tmp)


def test_line_number_validator_valid():
    """Valid line number should pass."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("line1\nline2\nline3\n")
        tmp_path = f.name

    try:
        validator = LineNumberValidator()
        file_result = VerificationResult(file_exists=True)
        finding = {"file_path": tmp_path, "line_number": 2}
        result = validator.validate(finding, file_result)
        assert result.line_valid is True
    finally:
        os.unlink(tmp_path)


def test_line_number_validator_out_of_range():
    """Line number exceeding file length should fail."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("line1\nline2\n")
        tmp_path = f.name

    try:
        validator = LineNumberValidator()
        file_result = VerificationResult(file_exists=True)
        finding = {"file_path": tmp_path, "line_number": 999}
        result = validator.validate(finding, file_result)
        assert result.line_valid is False
        assert any("out of range" in e["detail"] for e in result.evidence_chain)
    finally:
        os.unlink(tmp_path)


def test_line_number_validator_no_line():
    """Finding without line number should be skipped."""
    validator = LineNumberValidator()
    file_result = VerificationResult(file_exists=True)
    finding = {"file_path": "/some/file.py"}
    result = validator.validate(finding, file_result)
    assert result.line_valid is False
    assert result.evidence_chain[0]["status"] == "skipped"


def test_contradiction_detector_no_static():
    """When no static analysis is available, contradiction check should skip."""
    detector = ContradictionDetector(static_findings=[])
    result = VerificationResult(file_exists=True)
    finding = {"file_path": "test.py", "severity": "critical"}
    result = detector.validate(finding, result)
    assert result.evidence_chain[-1]["status"] == "skipped"


def test_verification_pipeline():
    """Full pipeline with real files."""
    import tempfile
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "src")
    os.makedirs(src)

    # Create a real file
    real_file = os.path.join(src, "controller.py")
    with open(real_file, "w") as f:
        f.write("def handle():\n    pass\n")

    findings = [
        {"title": "Real vuln", "severity": "critical", "file_path": real_file,
         "line_number": 1, "detail": "SQL injection in handle()", "confidence": "L2"},
        {"title": "Fake vuln", "severity": "high", "file_path": "/dev/null/nonexistent.py",
         "line_number": 999, "detail": "test", "confidence": "L1"},
    ]

    pipeline = VerificationPipeline(target_root=tmp)
    results = pipeline.run(findings)

    # First finding should pass file check
    v1 = results[0].get("verification", {})
    assert v1["file_exists"] is True
    assert v1["line_valid"] is True

    # Second finding should fail file check
    v2 = results[1].get("verification", {})
    assert v2["file_exists"] is False
    assert v2["line_valid"] is False


def test_verification_pipeline_evidence_chain():
    """Pipeline should produce evidence chain entries."""
    import tempfile
    tmp = tempfile.mkdtemp()
    real_file = os.path.join(tmp, "app.py")
    with open(real_file, "w") as f:
        f.write("print('hello')\n")

    finding = {"title": "Test", "severity": "low", "file_path": real_file,
               "line_number": 1, "detail": "test finding", "confidence": "L1"}

    pipeline = VerificationPipeline(target_root=tmp, enable_cross_model=False)
    results = pipeline.run([finding])
    v = results[0].get("verification", {})
    assert len(v["evidence_chain"]) >= 2  # At least file + line checks


def test_verification_pipeline_no_llm_static():
    """Pipeline should run without static analysis or LLM available."""
    import tempfile
    tmp = tempfile.mkdtemp()
    real_file = os.path.join(tmp, "config.py")
    with open(real_file, "w") as f:
        f.write("SECRET_KEY = 'test'\n")

    finding = {"title": "Hardcoded secret", "severity": "high", "file_path": real_file,
               "line_number": 1, "detail": "Secret key hardcoded", "confidence": "L2"}

    pipeline = VerificationPipeline(target_root=tmp, enable_cross_model=False)
    results = pipeline.run([finding])
    v = results[0].get("verification", {})
    assert v["file_exists"] is True
    assert v["verification_status"] == "verified"
