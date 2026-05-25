"""Tests for the scanning strategy module."""
import os
import tempfile

from agies.strategy import (
    StrategyEngine,
    FilePrioritizer,
    DynamicChunker,
    ChunkMetrics,
)


def _create_project(tmp: str, files: list[tuple[str, str]]) -> list[str]:
    """Helper to create a project directory with files.
    Each tuple is (relative_path, content).
    Returns sorted list of absolute paths.
    """
    paths = []
    for rel_path, content in files:
        abs_path = os.path.join(tmp, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w") as f:
            f.write(content)
        paths.append(abs_path)
    return sorted(paths)


def test_heuristic_prioritizer_security_files_first():
    """Security-sensitive files should score higher."""
    tmp = tempfile.mkdtemp()
    files = _create_project(tmp, [
        ("src/controller/UserController.java", "public class UserController {}"),
        ("src/model/User.java", "public class User {}"),
        ("config/application.yml", "secret: value"),
        ("test/TestUser.java", "public class TestUser {}"),
        ("README.md", "# Project"),
    ])

    prioritizer = FilePrioritizer(target_root=tmp)
    scored = prioritizer._heuristic_prioritize(files)

    # Controller and config should be in the top results
    top_paths = [s.path for s in scored]
    controller = next((p for p in top_paths if "controller" in p.lower()), None)
    config = next((p for p in top_paths if "application.yml" in p), None)
    assert controller is not None, "Controller should be prioritized"
    assert config is not None, "Config should be prioritized"

    # Controller should have higher score than README
    controller_score = next(s.score for s in scored if "controller" in s.path.lower())
    readme = next((s for s in scored if "README" in s.path), None)
    if readme:
        assert controller_score > readme.score, "Controller should score higher than README"


def test_heuristic_prioritizer_deprioritizes_assets():
    """CSS, images, etc. should be deprioritized."""
    tmp = tempfile.mkdtemp()
    files = _create_project(tmp, [
        ("src/app.py", "print('hello')"),
        ("static/style.css", "body {}"),
        ("static/icon.svg", "<svg />"),
    ])

    prioritizer = FilePrioritizer(target_root=tmp)
    scored = prioritizer._heuristic_prioritize(files)
    scored_paths = [s.path for s in scored]

    # app.py should be prioritized, css/svg should NOT be in scored list
    assert any("app.py" in p for p in scored_paths), "app.py should be in scored files"
    # CSS might appear if it has a positive match too, but should have lower score
    for s in scored:
        if "style.css" in s.path:
            assert s.score <= 30, "CSS should have very low score"


def test_dynamic_chunker_default():
    """Chunker should return reasonable chunk sizes."""
    chunker = DynamicChunker(target_size_tokens=30000, min_chunk=5, max_chunk=50)
    size = chunker.get_chunk_size()
    assert 5 <= size <= 50


def test_dynamic_chunker_context_pressure():
    """High context pressure should reduce chunk size."""
    chunker = DynamicChunker(target_size_tokens=30000, min_chunk=5, max_chunk=50)
    normal = chunker.get_chunk_size(context_pressure=0.0)
    pressured = chunker.get_chunk_size(context_pressure=0.8)
    assert pressured <= normal, "High pressure should reduce chunk size"


def test_dynamic_chunker_large_files():
    """High ratio of large files should reduce chunk size."""
    chunker = DynamicChunker(target_size_tokens=30000, min_chunk=5, max_chunk=50)
    normal = chunker.get_chunk_size(large_file_ratio=0.0)
    large = chunker.get_chunk_size(large_file_ratio=0.5)
    assert large <= normal, "Large files should reduce chunk size"


def test_dynamic_chunker_ema_update():
    """EMA metrics should update after processing chunks."""
    chunker = DynamicChunker(target_size_tokens=30000, ema_alpha=0.3)
    assert chunker.avg_tokens_per_file == 500.0  # Initial

    chunker.update_metrics(ChunkMetrics(avg_tokens=1000.0, num_files=10, analysis_time=30.0))

    expected = 0.3 * 1000 + 0.7 * 500
    assert abs(chunker.avg_tokens_per_file - expected) < 0.1


def test_dynamic_chunker_chunk_files():
    """chunk_files should split files into correctly sized groups."""
    chunker = DynamicChunker(target_size_tokens=30000, min_chunk=5, max_chunk=50)
    files = [f"file_{i}.py" for i in range(100)]

    chunks = chunker.chunk_files(files)
    assert len(chunks) > 0
    # Each chunk should have between min_chunk and max_chunk files
    for chunk in chunks:
        assert 5 <= len(chunk) <= 50
    # Total files should be preserved
    flattened = [f for chunk in chunks for f in chunk]
    assert len(flattened) == 100


def test_strategy_engine_prioritizes():
    """Strategy engine should identify high-value files."""
    tmp = tempfile.mkdtemp()
    _create_project(tmp, [
        ("src/main/java/com/app/controller/AuthController.java",
         "public class AuthController { @PostMapping('/login') public String login() {} }"),
        ("src/main/java/com/app/config/SecurityConfig.java",
         "public class SecurityConfig { }"),
        ("src/main/java/com/app/model/User.java",
         "public class User { }"),
        ("src/main/java/com/app/repository/UserRepository.java",
         "public interface UserRepository { }"),
        ("src/main/resources/application.yml",
         "secret: ${SECRET}"),
        ("README.md", "# Project"),
        ("pom.xml", "<project><dependencies></dependencies></project>"),
    ])

    engine = StrategyEngine(target_root=tmp)
    all_files = [
        os.path.join(tmp, "src/main/java/com/app/controller/AuthController.java"),
        os.path.join(tmp, "src/main/java/com/app/config/SecurityConfig.java"),
        os.path.join(tmp, "src/main/java/com/app/model/User.java"),
        os.path.join(tmp, "src/main/java/com/app/repository/UserRepository.java"),
        os.path.join(tmp, "src/main/resources/application.yml"),
        os.path.join(tmp, "README.md"),
        os.path.join(tmp, "pom.xml"),
    ]

    result = engine.analyze_project(all_files)
    assert len(result["high_value_files"]) > 0
    assert result["priority_summary"]
    assert "AuthController" in result["priority_summary"] or "controller" in result["priority_summary"].lower()


def test_strategy_engine_two_phase():
    """Phase 1 + Phase 2 should cover all files."""
    tmp = tempfile.mkdtemp()
    files = _create_project(tmp, [
        (f"file_{i}.py", f"# file {i}") for i in range(20)
    ])

    engine = StrategyEngine(target_root=tmp, phase1_ratio=0.2, phase1_min_files=3)
    result = engine.analyze_project(files)

    hv = set(result["high_value_files"])
    remaining = set(result["remaining_files"])
    all_result = hv | remaining

    assert len(all_result) == len(files), "All files should be covered"
    assert len(hv) >= 3, "Phase 1 should have at least min files"
    assert len(result["chunks"]["phase1"]) > 0, "Phase 1 should have chunks"
    assert len(result["chunks"]["phase2"]) > 0, "Phase 2 should have chunks"
