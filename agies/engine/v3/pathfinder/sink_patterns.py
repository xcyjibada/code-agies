"""Sink function name patterns → vulnerability type mapping.

Used by ``TreeSitterPathFinder`` and also sharable with CodeQL-based path
discovery.  Maps function names (and patterns) to vulnerability types so
the pathfinder can classify sinks it finds in the call graph.
"""

from __future__ import annotations

import re

from agies.engine.v3.codeql.models import VulnType

# ---------------------------------------------------------------------------
# Sink name → VulnType mapping
# ---------------------------------------------------------------------------
# A function whose name matches any of these is considered a sink of the
# corresponding vulnerability type.
#
# Structure: list of (exact_name | exact_method, VulnType)
# where exact_name matches simple names like "exec",
# and exact_method matches qualified names like "subprocess.call".

EXACT_SINKS: list[tuple[str, VulnType]] = [
    # -- RCE: code / command execution --
    ("exec", VulnType.RCE),
    ("eval", VulnType.RCE),
    ("__import__", VulnType.RCE),
    ("os.system", VulnType.RCE),
    ("os.popen", VulnType.RCE),
    ("subprocess.call", VulnType.RCE),
    ("subprocess.Popen", VulnType.RCE),
    ("subprocess.run", VulnType.RCE),
    ("subprocess.check_call", VulnType.RCE),
    ("subprocess.check_output", VulnType.RCE),
    ("subprocess.getoutput", VulnType.RCE),
    ("subprocess.getstatusoutput", VulnType.RCE),
    ("popen", VulnType.RCE),
    ("check_output", VulnType.RCE),
    # -- Deserialization RCE --
    ("pickle.loads", VulnType.RCE),
    ("pickle.load", VulnType.RCE),
    ("cloudpickle.loads", VulnType.RCE),
    ("cloudpickle.load", VulnType.RCE),
    ("yaml.load", VulnType.RCE),
    ("yaml.unsafe_load", VulnType.RCE),
    ("marshal.loads", VulnType.RCE),
    ("marshal.load", VulnType.RCE),
    # -- LFI: file read --
    ("open", VulnType.LFI),
    ("pathlib.Path.open", VulnType.LFI),
    ("pathlib.Path.read_text", VulnType.LFI),
    ("pathlib.Path.read_bytes", VulnType.LFI),
    ("file", VulnType.LFI),
    # -- SSRF: outbound HTTP --
    ("urlopen", VulnType.SSRF),
    ("urlretrieve", VulnType.SSRF),
    ("urllib.request.urlopen", VulnType.SSRF),
    ("urllib.request.urlretrieve", VulnType.SSRF),
    ("httpx.Client", VulnType.SSRF),
    ("httpx.AsyncClient", VulnType.SSRF),
    ("aiohttp.ClientSession", VulnType.SSRF),
    # -- SQLI: database queries --
    ("execute", VulnType.SQLI),
    ("executemany", VulnType.SQLI),
    ("executescript", VulnType.SQLI),
    # -- XSS: output rendering --
    ("render_template_string", VulnType.XSS),
    ("Markup", VulnType.XSS),
    # -- AFO: file write --
    ("pathlib.Path.write_text", VulnType.AFO),
    ("pathlib.Path.write_bytes", VulnType.AFO),
    ("shutil.copy", VulnType.AFO),
    ("shutil.move", VulnType.AFO),
    ("os.remove", VulnType.AFO),
    ("os.unlink", VulnType.AFO),
    # -- REDOS: regex / pattern matching --
    ("glob", VulnType.REDOS),
    ("fnmatch.translate", VulnType.REDOS),
    ("fnmatch.filter", VulnType.REDOS),
    ("re.match", VulnType.REDOS),
    ("re.search", VulnType.REDOS),
    ("re.findall", VulnType.REDOS),
    ("re.fullmatch", VulnType.REDOS),
    ("re.sub", VulnType.REDOS),
    ("re.compile", VulnType.REDOS),
    # `compile` must come AFTER `re.compile` so `classify_sink` .endswith
    # check matches REDOS before the broader RCE match.
    ("compile", VulnType.RCE),
]

# ---------------------------------------------------------------------------
# Regex patterns — catch sink-like names that are not exact matches
# ---------------------------------------------------------------------------

SINK_REGEX: list[tuple[re.Pattern, VulnType]] = [
    # RCE: any function with "exec" or "eval" in name
    (re.compile(r"^(?:safe_|unsafe_)?exec(?:ute(?:_command)?)?$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"^(?:safe_|unsafe_)?eval$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"^popen$", re.IGNORECASE), VulnType.RCE),
    (re.compile(r"^system$", re.IGNORECASE), VulnType.RCE),
    # LFI: read-like functions
    (re.compile(r"^(read|read_file|read_text|read_bytes|load_file|get_file)$", re.IGNORECASE), VulnType.LFI),
    # SSRF: fetch/get/request
    (re.compile(r"^(fetch|http_request|make_request|do_request)$", re.IGNORECASE), VulnType.SSRF),
    # SQLI: query-like
    (re.compile(r"^(query|raw_query|run_query|native_query|execute_query)$", re.IGNORECASE), VulnType.SQLI),
]

# ---------------------------------------------------------------------------
# Known entry-point function name patterns
# ---------------------------------------------------------------------------

ENTRY_POINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(get|post|put|delete|patch|head|options)$", re.IGNORECASE),
    re.compile(r"^handle_.*", re.IGNORECASE),
    re.compile(r"^on_.*", re.IGNORECASE),
    re.compile(r".*_handler$", re.IGNORECASE),
    re.compile(r".*_route$", re.IGNORECASE),
    re.compile(r"^main$"),
    re.compile(r"^run$"),
    re.compile(r"^serve$"),
    re.compile(r"^start$"),
    re.compile(r"^dispatch$"),
]


def classify_sink(name: str) -> VulnType | None:
    """Classify a function name as a sink of a specific vulnerability type.

    Returns ``None`` if the name does not match any known sink pattern.
    """
    # Exact check first
    for pattern, vuln_type in EXACT_SINKS:
        if name == pattern or name.endswith(f".{pattern}"):
            return vuln_type

    # Regex check
    for pattern, vuln_type in SINK_REGEX:
        if pattern.match(name):
            return vuln_type

    return None


def is_entry_point(name: str) -> bool:
    """Check whether a function name looks like an entry point."""
    return any(p.match(name) for p in ENTRY_POINT_PATTERNS)


KNOWN_SINK_NAMES: set[str] = {name for name, _ in EXACT_SINKS}
"""Set of all known exact sink names, for quick lookup."""

# ---------------------------------------------------------------------------
# Sensitive call patterns — functions whose *body* calls these are candidates
# for Explore slots even if their name doesn't match a known sink.
# ---------------------------------------------------------------------------
# These catch logic vulnerabilities like path traversal, permission bypass,
# and missing validation — things that don't have a single dangerous sink
# function but involve sensitive operations on untrusted data.

SENSITIVE_CALL_PATTERNS: list[tuple[re.Pattern, VulnType]] = [
    # Path manipulation → path traversal (LFI). These construct paths,
    # not write files — map to LFI for better prompt coverage.
    (re.compile(r"posixpath\.join"), VulnType.LFI),
    (re.compile(r"ntpath\.join"), VulnType.LFI),
    (re.compile(r"os\.path\.join"), VulnType.LFI),
    (re.compile(r"PurePosixPath"), VulnType.LFI),
    (re.compile(r"PureWindowsPath"), VulnType.LFI),
    (re.compile(r"pathlib\.PurePosixPath"), VulnType.LFI),
    (re.compile(r"zipfile\.Path"), VulnType.LFI),
    # Archive extraction — zip slip / tar slip → AFO (writes files)
    (re.compile(r"zipfile\.ZipFile"), VulnType.AFO),
    (re.compile(r"zipfile\.ZipFile\.extractall"), VulnType.AFO),
    (re.compile(r"zipfile\.ZipFile\.extract"), VulnType.AFO),
    (re.compile(r"tarfile\.open"), VulnType.AFO),
    (re.compile(r"tarfile\.extractall"), VulnType.AFO),
    # File write / copy via less common paths
    (re.compile(r"pathlib\.Path\(.*\)\.write"), VulnType.AFO),
    # File read via less common paths
    (re.compile(r"io\.open"), VulnType.LFI),
    # REDOS: regex operations (body-level detection catches cases not in EXACT_SINKS)
    (re.compile(r"re\.(match|search|findall|fullmatch|sub|compile|split)"), VulnType.REDOS),
    (re.compile(r"fnmatch\.(translate|filter)"), VulnType.REDOS),
    # Dynamic import / code generation (exact built-in compile(), NOT re.compile)
    (re.compile(r"__import__"), VulnType.RCE),
    (re.compile(r"\bcompile\("), VulnType.RCE),
    # RCE: eval/exec in function bodies (catches inline calls in route handlers)
    (re.compile(r"\beval\s*\("), VulnType.RCE),
    (re.compile(r"\bexec\s*\("), VulnType.RCE),
    (re.compile(r"os\.system\s*\("), VulnType.RCE),
    (re.compile(r"os\.popen\s*\("), VulnType.RCE),
    (re.compile(r"subprocess\.\w+\s*\("), VulnType.RCE),
    # RCE: pickle/cloudpickle deserialization in function bodies
    (re.compile(r"pickle\.loads?\s*\("), VulnType.RCE),
    (re.compile(r"cloudpickle\.loads?\s*\("), VulnType.RCE),
    # LFI: bare open() in function bodies
    (re.compile(r"\bopen\s*\("), VulnType.LFI),
    # SQLI: execute/executemany in function bodies
    (re.compile(r"\bexecute\b"), VulnType.SQLI),
    (re.compile(r"executemany\b"), VulnType.SQLI),
    # SSRF: requests/urllib in function bodies
    (re.compile(r"requests\.\w+\s*\("), VulnType.SSRF),
    (re.compile(r"urlopen\s*\("), VulnType.SSRF),
    (re.compile(r"httpx\.\w+\s*\("), VulnType.SSRF),
]


def classify_sensitive_body(source_code: str) -> VulnType | None:
    """Check a function's body source code for sensitive API calls.

    Returns the ``VulnType`` of the first matching pattern, or ``None``
    if no sensitive calls are found.

    This is used by ``TreeSitterPathFinder`` in its second pass to flag
    functions for Explore slots — catching logic-level vulnerabilities
    that don't have a telltale sink function name.
    """
    for pattern, vuln_type in SENSITIVE_CALL_PATTERNS:
        if pattern.search(source_code):
            return vuln_type
    return None
