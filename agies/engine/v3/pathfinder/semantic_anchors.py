"""Semantic Anchor Engine — discovers high-value logical controllers.

Replaces the sink-centric approach with business-semantic-aware discovery.

Instead of: "find all functions that call exec/eval/pickle"
This does:  "find all classes/functions that manage auth/session/token/secret/privilege"

These "high-value logical controllers" are the business-logic analogues of dangerous
sinks — places where a security boundary SHOULD exist but may not be correctly
implemented.  Examples:

  - GatewaySecret       (manages service credentials → trust boundary)
  - JWTMiddleware       (validates/auth tokens → auth bypass risk)
  - PermissionGuard     (enforces access control → privilege escalation)
  - ConfigLoader        (loads external config → injection via config)
  - SessionManager      (manages user sessions → session hijacking)
  - AuditLogger         (writes audit logs → log injection/pii leak)

Semantic slices (complete class + companion methods) are fed to Intent/Logic
agents for contract-based analysis: the Intent Agent writes a Security Contract,
the Logic Agent finds Spec Falsification — violations of that contract.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Semantic Anchor Definitions
# ---------------------------------------------------------------------------

def _anchor_pat(words: str) -> re.Pattern:
    """Build anchor regex that matches snake_case, CamelCase, and kebab-case.

    Leading ``\\b`` fails for CamelCase compounds like ``SqlGatewaySecret``
    (no boundary between 'l' and 'G').  This uses ``\\b`` OR a lowercase-
    preceded position (the CamelCase transition), combined with a trailing
    lookahead that accepts ``\\b``, uppercase (next CamelCase word),
    underscore (snake_case continuation), or digit (versioned names).

    ``(?-i:[a-z])`` keeps the lookbehind case-sensitive even though the
    outer ``(?i)`` flag enables case-insensitive matching for the words.
    Also ``(?<=_)`` catches snake_case continuations (``config`` in
    ``gateway_config``), which ``\\b`` misses because Python's ``\\w``
    includes underscore.
    """
    return re.compile(rf"(?i)(?:\b|(?<=_)|(?<=(?-i:[a-z])))({words})(?=\b|(?-i:[A-Z_0-9]))")


SEMANTIC_ANCHORS: list[tuple[re.Pattern, str]] = [
    # -- Authentication & Identity --
    (_anchor_pat("auth|authenticate|login|signin|sign_up|sign_in"),
     "authentication"),
    (_anchor_pat("oauth|oidc|saml|sso|openid"),
     "federated_auth"),
    (_anchor_pat("session|user_session|session_manager|session_store"),
     "session_management"),
    (_anchor_pat("token|jwt|refresh_token|access_token|id_token|csrf_token"),
     "token_management"),
    (_anchor_pat("credential|credentials|password|passwd|passwd_hash|hash_password|api_key|api_secret"),
     "credential_management"),
    # -- Authorization & Access Control --
    (_anchor_pat("permission|privilege|role|rbac|acl|access_control"),
     "authorization"),
    (_anchor_pat("gateway|api_gateway|proxy|middleware|interceptor|filter"),
     "gateway"),
    (_anchor_pat("guard|check_permission|authorize|is_allowed|can_access|has_role"),
     "access_guard"),
    # -- Execution & Privilege --
    (_anchor_pat("executor|runner|scheduler|task_queue|job_runner|worker"),
     "execution_controller"),
    (_anchor_pat("sandbox|isolate|restrict|quota|rate_limit|throttle"),
     "security_boundary"),
    (_anchor_pat("privilege|escalat|elevat|impersonat|suplant"),
     "privilege_management"),
    # -- Data Protection --
    (_anchor_pat("encrypt|decrypt|cipher|crypto|cryptography|ciphertext"),
     "cryptography"),
    (_anchor_pat("sanitize|validate|filter|escape|cleanse|purify"),
     "input_validation"),
    (_anchor_pat("mask|redact|anonymize|obfuscate|deidentify"),
     "data_protection"),
    # -- Configuration & Secrets --
    (_anchor_pat("secret|vault|key_management|key_store|secret_manager"),
     "secret_management"),
    (_anchor_pat("trust_store|certificate|cert|tls|ssl|ca_bundle"),
     "trust_management"),
    (_anchor_pat("config|settings|configuration|env_loader"),
     "configuration"),
    # -- Audit & Compliance --
    (_anchor_pat("audit|audit_log|compliance|gdpr|pci|hipaa|sox"),
     "audit"),
]

# Patterns to filter out false positives — names that match SEMANTIC_ANCHORS
# regex patterns but are clearly NOT security-relevant in practice.
_ANCHOR_EXCLUDE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)test_"),
    re.compile(r"(?i)mock"),
    re.compile(r"(?i)fixture"),
    re.compile(r"(?i)_example"),
    re.compile(r"(?i)_demo_"),
]

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class SemanticAnchorMatch:
    """A matched semantic anchor — a class or function with security-sensitive naming."""

    anchor_type: str
    """The anchor category, e.g. ``"token_management"``, ``"authentication"``."""

    name: str
    """Name of the matched class or function."""

    file_path: str
    """Absolute file path."""

    line_start: int
    """Starting line number."""

    line_end: int
    """Ending line number."""

    source_code: str
    """Complete source code of the class/function."""

    is_class: bool
    """True if this is a class match, False if function-level."""

    companion_methods: list[dict[str, Any]] = field(default_factory=list)
    """List of companion methods in the same class (for class matches).
    Each: ``{"name", "file_path", "line_start", "line_end", "code"}``."""

    description: str = ""
    """Human-readable context summary."""


@dataclass
class SemanticSlice:
    """A semantic code unit for contract-based analysis.

    Unlike PathSlice (which represents a source→sink data flow path),
    a SemanticSlice represents a domain-level code unit centered around
    a high-value logical controller like ``GatewaySecret`` or ``JWTMiddleware``.
    """

    id: str
    """Semantic slice ID, e.g. ``"sem-auth-001"``."""

    anchor_type: str
    """Anchor category."""

    primary_class: str
    """Name of the primary matched class."""

    file_path: str
    """File path of the primary class."""

    code_block: str
    """Complete source code — class definition + all companion methods."""

    companion_functions: list[str] = field(default_factory=list)
    """Names of all functions in this slice (used for blackboard lookup)."""

    description: str = ""
    """Human-readable description."""

    semantic_analysis_hint: str = ""
    """Hint for the LLM about what to look for during spec-falsification analysis.

    Generated from the anchor type, e.g. for ``token_management``:
    'This class manages authentication tokens. The security contract should
    cover: token validity verification, signature validation, expiration
    checking, and protection against token reuse/replay.'
    """


# Map of anchor types to analysis hints (guides LLM what security contract to expect)
_ANALYSIS_HINTS: dict[str, str] = {
    "authentication": (
        "This class manages authentication. "
        "Expected security contract: validates credentials, prevents brute-force, "
        "does not leak user enumeration, uses constant-time comparison."
    ),
    "federated_auth": (
        "This class handles federated/OAuth authentication. "
        "Expected security contract: validates redirect_uri, "
        "prevents CSRF via state parameter, verifies issuer and audience in tokens."
    ),
    "session_management": (
        "This class manages user sessions. "
        "Expected security contract: generates unpredictable session IDs, "
        "prevents fixation, expires sessions properly, "
        "invalidates on logout, binds session to user agent/IP."
    ),
    "token_management": (
        "This class manages tokens (JWT, access tokens, API keys). "
        "Expected security contract: verifies signature, checks expiration, "
        "validates issuer/audience, prevents token reuse, "
        "uses secure key storage, does not leak tokens in logs."
    ),
    "credential_management": (
        "This class manages credentials/passwords. "
        "Expected security contract: uses proper hashing (bcrypt/argon2), "
        "never stores plaintext, uses constant-time comparison, "
        "prevents credential stuffing, rate-limits login attempts."
    ),
    "authorization": (
        "This class enforces access control. "
        "Expected security contract: checks permissions on every access, "
        "default-deny, verifies ownership for resources, "
        "prevents privilege escalation and IDOR."
    ),
    "gateway": (
        "This class acts as a gateway/middleware/proxy. "
        "Expected security contract: validates all incoming requests, "
        "applies rate limiting, does not forward untrusted data unchanged, "
        "handles timeouts and circuit breaking safely."
    ),
    "access_guard": (
        "This class guards access to resources. "
        "Expected security contract: every security decision is explicit, "
        "default-deny, authorization is not bypassable via parameter manipulation, "
        "role/permission checks are not based on user-controlled values."
    ),
    "secret_management": (
        "This class manages secrets/keys. "
        "Expected security contract: secrets never logged or exposed in error messages, "
        "access to secrets is audited, keys are rotated, "
        "no hardcoded secrets in source code."
    ),
    "input_validation": (
        "This class validates/filters/sanitizes input. "
        "Expected security contract: validation cannot be bypassed by encoding tricks, "
        "filter list is complete (not blocklist), "
        "validation is applied consistently at all entry points."
    ),
    "execution_controller": (
        "This class controls code/task execution. "
        "Expected security contract: prevents arbitrary code execution, "
        "sandboxes untrusted workloads, enforces resource limits, "
        "validates input passed to exec/eval/subprocess."
    ),
    "security_boundary": (
        "This class enforces a security boundary. "
        "Expected security contract: isolation is not bypassable, "
        "resource limits are enforced, escape from sandbox is prevented, "
        "boundary violations are detected and logged."
    ),
    "privilege_management": (
        "This class manages privilege levels. "
        "Expected security contract: privilege escalation is prevented, "
        "privilege checks are not based on user-supplied values, "
        "elevation requires re-authentication."
    ),
    "cryptography": (
        "This class implements cryptographic operations. "
        "Expected security contract: uses modern algorithms (not MD5/SHA1 for security), "
        "key management is secure, IV/nonce is random and unique, "
        "does not implement custom crypto, handles padding oracle resistance."
    ),
    "configuration": (
        "This class loads/processes configuration. "
        "Expected security contract: config sources are trusted, "
        "no arbitrary code execution during config loading, "
        "sensitive config values are not exposed in error messages."
    ),
    "data_protection": (
        "This class masks/redacts/anonymizes data. "
        "Expected security contract: sensitive data is not leaked, "
        "redaction cannot be reversed, masking is applied consistently."
    ),
    "audit": (
        "This class implements audit logging. "
        "Expected security contract: log injection is prevented, "
        "sensitive data is not written to logs, "
        "audit trail cannot be tampered with."
    ),
    "trust_management": (
        "This class manages TLS/certificate trust. "
        "Expected security contract: certificate validation is enforced, "
        "does not disable hostname verification, "
        "trust store is not modifiable at runtime."
    ),
}


def _classify_semantic(name: str) -> list[str]:
    """Check if a name matches any semantic anchor.

    Returns a list of matching anchor type strings, e.g.
    ``["session_management", "token_management"]``.
    Returns empty list if no anchor matches.
    """
    # Skip excluded patterns
    for excl in _ANCHOR_EXCLUDE_PATTERNS:
        if excl.search(name):
            return []

    matches: list[str] = []
    for pattern, anchor_type in SEMANTIC_ANCHORS:
        if pattern.search(name):
            matches.append(anchor_type)
    return matches


def _get_analysis_hint(anchor_types: list[str]) -> str:
    """Build a combined analysis hint from all matching anchor types."""
    hints = []
    seen = set()
    for atype in anchor_types:
        hint = _ANALYSIS_HINTS.get(atype)
        if hint and atype not in seen:
            hints.append(hint)
            seen.add(atype)
    return "\n".join(hints)


# ---------------------------------------------------------------------------
# Semantic Anchor Finder
# ---------------------------------------------------------------------------


class SemanticAnchorFinder:
    """Scans a project for semantic anchors and builds SemanticSlices.

    Works alongside TreeSitterPathFinder (sink-based): semantic anchors detect
    different classes of problem that sink-based discovery cannot see.

    Usage::

        finder = SemanticAnchorFinder(project_path)
        finder.scan(function_index)             # or scan_fast() for no-index
        slices = finder.build_semantic_slices()  # → list[SemanticSlice]
    """

    def __init__(self, project_path: str) -> None:
        self._project_path = os.path.abspath(project_path)
        self._matches: list[SemanticAnchorMatch] = []

    def scan(self, function_index=None) -> list[SemanticAnchorMatch]:
        """Scan the project for semantic anchors.

        Uses FunctionIndex when available (faster), otherwise falls back
        to AST-based file scanning.

        Returns list of SemanticAnchorMatch objects.
        """
        self._matches = []

        if function_index is not None:
            return self._scan_with_index(function_index)
        return self._scan_with_ast()

    def _scan_with_index(self, function_index) -> list[SemanticAnchorMatch]:
        """Scan using FunctionIndex function names."""
        seen_classes: dict[str, list] = {}
        for fn in function_index.funcs if hasattr(function_index, 'funcs') else []:
            anchor_types = _classify_semantic(fn.name)
            if not anchor_types:
                continue

            self._matches.append(SemanticAnchorMatch(
                anchor_type=anchor_types[0],
                name=fn.name,
                file_path=fn.file_path,
                line_start=fn.line_start,
                line_end=fn.line_end,
                source_code=fn.body or "",
                is_class=False,
            ))

        # Class-level scanning via AST
        self._scan_classes_with_ast()
        return self._matches

    def _scan_with_ast(self) -> list[SemanticAnchorMatch]:
        """Fallback: scan Python files with AST for class definitions."""
        self._scan_classes_with_ast()
        return self._matches

    def _scan_classes_with_ast(self) -> None:
        """Scan project Python files for classes that match semantic anchors."""
        for root, _dirs, files in os.walk(self._project_path):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                if "/test" in fpath or "/tests" in fpath or "/__pycache__" in fpath:
                    continue
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                except OSError:
                    continue

                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        anchor_types = _classify_semantic(node.name)
                        if not anchor_types:
                            continue

                        # Get lines from source
                        lines = source.splitlines()
                        start = node.lineno - 1
                        # Find end — last line of last body item
                        end = start
                        for item in ast.walk(node):
                            if hasattr(item, 'end_lineno') and item.end_lineno:
                                end = max(end, item.end_lineno - 1)
                            elif hasattr(item, 'lineno') and item.lineno:
                                end = max(end, item.lineno)

                        class_code = "\n".join(lines[start:end + 1])

                        # Extract companion methods
                        companions = []
                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                if hasattr(item, 'end_lineno') and item.end_lineno:
                                    fn_lines = lines[item.lineno - 1:item.end_lineno]
                                else:
                                    fn_lines = [f"def {item.name}(...): ..."]
                                companions.append({
                                    "name": item.name,
                                    "file_path": fpath,
                                    "line_start": item.lineno,
                                    "line_end": getattr(item, 'end_lineno', item.lineno) or item.lineno,
                                    "code": "\n".join(fn_lines),
                                })

                        self._matches.append(SemanticAnchorMatch(
                            anchor_type=anchor_types[0],
                            name=node.name,
                            file_path=fpath,
                            line_start=node.lineno,
                            line_end=end + 1,
                            source_code=class_code,
                            is_class=True,
                            companion_methods=companions,
                        ))

        # Deduplicate by (file_path, name)
        seen: set[tuple[str, str]] = set()
        deduped = []
        for m in self._matches:
            key = (m.file_path, m.name)
            if key not in seen:
                seen.add(key)
                deduped.append(m)
        self._matches = deduped

    def build_semantic_slices(self) -> list[SemanticSlice]:
        """Convert matched anchors into SemanticSlices for the pipeline.

        Each SemanticSlice is a self-contained code unit ready for
        Intent→Logic spec-falsification analysis.
        """
        slices: list[SemanticSlice] = []
        for i, match in enumerate(self._matches):
            anchor_type = match.anchor_type

            # Build companion function names
            companion_names = [c["name"] for c in match.companion_methods]
            if match.name not in companion_names:
                companion_names.insert(0, match.name)

            slice_id = f"sem-{anchor_type}-{i:03d}"

            slices.append(SemanticSlice(
                id=slice_id,
                anchor_type=anchor_type,
                primary_class=match.name,
                file_path=match.file_path,
                code_block=match.source_code,
                companion_functions=companion_names,
                description=f"Semantic anchor [{anchor_type}]: {match.name} "
                            f"({os.path.relpath(match.file_path, self._project_path)})",
                semantic_analysis_hint=_get_analysis_hint(
                    [anchor_type] + (
                        self._get_extra_hints(match.name, match.source_code)
                    )
                ),
            ))
        return slices

    @staticmethod
    def _get_extra_hints(name: str, source: str) -> list[str]:
        """Check source for additional anchor types beyond the name match."""
        extra: list[str] = []
        for pattern, anchor_type in SEMANTIC_ANCHORS:
            if pattern.search(source):
                if anchor_type not in extra:
                    extra.append(anchor_type)
        return extra

    @property
    def matches(self) -> list[SemanticAnchorMatch]:
        return self._matches


def build_semantic_prompt(slice_: SemanticSlice) -> str:
    """Build the initial prompt for semantic slice analysis.

    Unlike sink-based prompts (which ask "find vulns"), this asks:
    "what security contract does this code enforce, and does it do so correctly?"
    """
    return (
        "# Semantic Security Analysis — No Dangerous API Required\n\n"
        f"## Code Unit: {slice_.primary_class}\n"
        f"**Anchor Type**: {slice_.anchor_type}\n"
        f"**File**: {slice_.file_path}\n\n"
        "### Analysis Approach: Security Contract Falsification\n\n"
        "This code has been selected because its name/business domain suggests "
        "it **enforces a security boundary**. Your task is NOT to find dangerous "
        "function calls (exec/eval/pickle) — it is to:\n\n"
        "1. **Derive the Security Contract**: What security property does this "
        "code CLAIM to enforce? Read the class name, method names, docstrings, "
        "and logic to infer the implicit security promise.\n\n"
        "2. **Find Contract Violations**: Does the actual IMPLEMENTATION uphold "
        "the contract? Look for:\n"
        "   - Missing validation that should exist\n"
        "   - Incomplete/bypassable checks\n"
        "   - Trust assumptions that don't hold\n"
        "   - Type confusion in permission/role checks\n"
        "   - State that diverges from ground truth\n"
        "   - TOCTOU between check and use\n"
        "   - Parser differentials between validation and execution\n\n"
        "3. **Output**: A structured falsification report.\n\n"
        f"### Domain-Specific Guidance\n{slice_.semantic_analysis_hint}\n\n"
        "### Source Code\n"
        f"```python\n{slice_.code_block}\n```"
    )
