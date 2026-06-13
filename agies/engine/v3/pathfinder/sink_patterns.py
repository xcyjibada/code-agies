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
    ("Markup", VulnType.XSS),
    # -- XXE: XML parsing with insecure defaults --
    ("xml.etree.ElementTree.parse", VulnType.XXE),
    ("xml.etree.ElementTree.fromstring", VulnType.XXE),
    ("lxml.etree.parse", VulnType.XXE),
    ("lxml.etree.fromstring", VulnType.XXE),
    ("lxml.etree.XMLParser", VulnType.XXE),
    ("xml.dom.minidom.parse", VulnType.XXE),
    ("xml.dom.minidom.parseString", VulnType.XXE),
    ("xml.sax.parse", VulnType.XXE),
    ("xml.sax.parseString", VulnType.XXE),
    ("lxml.objectify.parse", VulnType.XXE),
    ("lxml.objectify.fromstring", VulnType.XXE),
    # -- SSTI: template injection (Jinja2 / Mako / Django) --
    ("render_template_string", VulnType.SSTI),
    ("jinja2.Template", VulnType.SSTI),
    ("jinja2.Environment", VulnType.SSTI),
    ("Template", VulnType.SSTI),  # string.Template FP possible — LLM filters it
    ("Template.render", VulnType.SSTI),
    ("Environment.from_string", VulnType.SSTI),
    ("mako.template.Template", VulnType.SSTI),
    # -- AFO: file write --
    ("pathlib.Path.write_text", VulnType.AFO),
    ("pathlib.Path.write_bytes", VulnType.AFO),
    ("shutil.copy", VulnType.AFO),
    ("shutil.move", VulnType.AFO),
    ("os.remove", VulnType.AFO),
    ("os.unlink", VulnType.AFO),
    # -- ML / AI framework sinks --
    # PyTorch: torch.load without weights_only → RCE
    ("torch.load", VulnType.RCE),
    ("torch.hub.load", VulnType.RCE),
    ("torch.hub.download_url_to_file", VulnType.SSRF),
    # HuggingFace: from_pretrained loads arbitrary code from hub
    ("AutoModel.from_pretrained", VulnType.RCE),
    ("AutoModelForSequenceClassification.from_pretrained", VulnType.RCE),
    ("AutoModelForCausalLM.from_pretrained", VulnType.RCE),
    ("AutoTokenizer.from_pretrained", VulnType.RCE),
    ("transformers.pipeline", VulnType.RCE),
    ("pipeline", VulnType.RCE),
    # safetensors: file path can be controlled → arbitrary file write/read
    ("safetensors.torch.load_file", VulnType.AFO),
    # ONNX: model binary could embed malicious operations
    ("onnxruntime.InferenceSession", VulnType.RCE),
    # joblib / skops: model serialization deserialization
    ("joblib.load", VulnType.RCE),
    ("skops.load", VulnType.RCE),
    ("skops.io.visualization.load", VulnType.RCE),
    # MLflow: model loading from artifact stores
    ("mlflow.pyfunc.load_model", VulnType.RCE),
    ("mlflow.pytorch.load_model", VulnType.RCE),
    ("mlflow.huggingface.load_model", VulnType.RCE),
    # TensorFlow / Keras: loading models with custom layers
    ("tf.keras.models.load_model", VulnType.RCE),
    ("tensorflow.keras.models.load_model", VulnType.RCE),
    # numpy: allow_pickle=True → deserialization RCE
    ("numpy.load", VulnType.RCE),
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
    # -- XXE / XML Entity Expansion (CWE-611) --
    # XXE occurs when XML parsers with insecure defaults process untrusted
    # XML input, allowing DTD entity expansion, file exfiltration, and SSRF.
    # High confidence: XML parsing of untrusted data with default settings
    # is almost always exploitable.
    (re.compile(r"xml\.etree\.ElementTree\.(?:parse|fromstring)"), VulnType.XXE),
    (re.compile(r"lxml\.etree\.(?:parse|fromstring|XMLParser)"), VulnType.XXE),
    (re.compile(r"xml\.dom\.minidom\.(?:parse|parseString)"), VulnType.XXE),
    (re.compile(r"xml\.sax\.(?:parse|parseString)"), VulnType.XXE),
    (re.compile(r"BeautifulSoup\(.*['\"]xml['\"]"), VulnType.XXE),
    (re.compile(r"lxml\.objectify\.(?:fromstring|parse)"), VulnType.XXE),
    # Common import aliases: from xml.etree import ElementTree; ElementTree.fromstring(...)
    (re.compile(r"ElementTree\.(?:parse|fromstring)"), VulnType.XXE),
    (re.compile(r"etree\.(?:parse|fromstring|XMLParser)"), VulnType.XXE),
    # -- SSTI: Server-Side Template Injection (CWE-1336) --
    # User input flowing into template engines without sanitization can
    # lead to RCE via Jinja2 sandbox escapes, Mako arbitrary code execution,
    # or Django template variable leakage.
    (re.compile(r"render_template_string\s*\("), VulnType.SSTI),
    (re.compile(r"\bTemplate\s*\("), VulnType.SSTI),
    (re.compile(r"Environment\s*\(.*from_string"), VulnType.SSTI),
    (re.compile(r"\.render\s*\(.*\{"), VulnType.SSTI),
    # Path manipulation — suspicious constructors, not necessarily LFI.
    # These build paths but don't do I/O. The actual vulnerability type
    # (DoS, path traversal, race condition) depends on how the constructed
    # path is used by callers. Classify as SUSPICIOUS so the LLM analyzes
    # freely rather than being pre-judged as LFI.
    (re.compile(r"posixpath\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"ntpath\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"os\.path\.join"), VulnType.SUSPICIOUS),
    (re.compile(r"PurePosixPath"), VulnType.SUSPICIOUS),
    (re.compile(r"PureWindowsPath"), VulnType.SUSPICIOUS),
    (re.compile(r"pathlib\.PurePosixPath"), VulnType.SUSPICIOUS),
    (re.compile(r"zipfile\.Path"), VulnType.SUSPICIOUS),
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
    # ML: trust_remote_code=True enables arbitrary code execution via HF hub
    (re.compile(r"trust_remote_code\s*=\s*True"), VulnType.RCE),
    # ML: PyTorch deserialization (torch.load without weights_only)
    (re.compile(r"torch\.load\s*\("), VulnType.RCE),
    (re.compile(r"torch\.hub\.load\s*\("), VulnType.RCE),
    # ML: joblib model deserialization
    (re.compile(r"joblib\.load\s*\("), VulnType.RCE),
    # ML: HuggingFace from_pretrained (any model/tokenizer/processor)
    (re.compile(r"from_pretrained\s*\("), VulnType.RCE),
    # ML: transformers pipeline
    (re.compile(r"transformers\.pipeline\s*\("), VulnType.RCE),
    # ML: ONNX runtime — loads and executes model binaries
    (re.compile(r"onnxruntime\.InferenceSession\s*\("), VulnType.RCE),
    # ML: safetensors file load — path traversal
    (re.compile(r"safetensors\.\w+\.load_file\s*\("), VulnType.AFO),
    (re.compile(r"safetensors\.\w+\.load\s*\("), VulnType.AFO),
    # ML: numpy load with allow_pickle
    (re.compile(r"numpy\.load\s*\("), VulnType.RCE),
    # ML: MLflow model loading
    (re.compile(r"mlflow\.\w+\.load_model\s*\("), VulnType.RCE),
    # ML: TF/Keras model loading — custom layers can execute code
    (re.compile(r"(?:tf|tensorflow|keras)\.\w*models?\.load_model\s*\("), VulnType.RCE),
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
