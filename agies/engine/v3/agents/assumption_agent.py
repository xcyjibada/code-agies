"""Assumption Agent — three-phase sink-free semantic vulnerability discovery.

Replaces the sink-path LLM-based approach (boxIdea.md upgrade):

Phase 1: For each semantic anchor finding, scan source code for AST/regex patterns
         that reveal implicit security assumptions.  Pure deterministic — no LLM.

Phase 2: Cross-reference all assumptions across ALL findings.  Find contradictions
         between assumptions from different anchor types (cross-domain collisions).

Phase 3: LLM attack chain synthesis — only on confirmed contradictions.

Implements the "Security Knowledge Graph" from docs/boxIdea.md:

  Trust Boundary → State Transition → Parser Differential → Invariant Broken
  ───────────────────────────────────────────────────────────────────
  Instead of:       Assumption A × Assumption B (collision)
  This does:        Knowledge Graph ^-- contradiction detection on edges

Reference: docs/boxIdea.md — the full conversation transcript describing this design.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class Assumption:
    """A deterministic assumption extracted from code via pattern matching."""

    anchor_type: str
    """Semantic anchor category, e.g. ``"credential_management"``."""

    anchor_name: str
    """Name of the matched class/function."""

    file_path: str

    label: str
    """Short label like ``"env_resolution"``, ``"opaque_storage"``."""

    assumption: str
    """Human-readable: what the developer implicitly assumed."""

    evidence: str
    """Which code pattern triggered this assumption."""

    category: str
    """Knowledge kind from boxIdea.md:
    TRUST_BOUNDARY, STATE_TRANSITION, PARSER, OBJECT_IDENTITY, INVARIANT, AUTHORITY, CACHE, OWNERSHIP
    """

    line_number: int = 0


@dataclass
class Contradiction:
    """A detected contradiction between two assumptions from different domains."""

    assumption_a: Assumption
    assumption_b: Assumption
    description: str
    severity: str = "medium"  # high / medium / low


@dataclass
class AssumptionSignature:
    """Signature for detecting a specific assumption in source code."""

    label: str
    """Unique label, e.g. ``"env_resolution"``."""

    assumption: str
    """What the developer assumed."""

    category: str
    """Knowledge kind: TRUST_BOUNDARY, STATE_TRANSITION, etc."""

    risk: str
    """What goes wrong if this assumption is violated."""

    patterns: list[dict[str, Any]] = field(default_factory=list)
    """List of pattern dicts: each with ``type`` (``"regex"`` or ``"neg_regex"``) and ``pattern``.

    AND logic within a signature: all ``"regex"`` patterns must match, and no
    ``"neg_regex"`` patterns may match.
    """


# ---------------------------------------------------------------------------
# Anchor → Assumption Templates
# ---------------------------------------------------------------------------
# For each anchor type, define assumptions the code may be making and how
# to detect them deterministically from source code.  These are the
# "facts" that the LLM never touches — pure AST/regex extraction.

_ANCHOR_ASSUMPTION_TEMPLATES: dict[str, list[AssumptionSignature]] = {
    "credential_management": [
        AssumptionSignature(
            label="env_resolution",
            assumption="以 $ 开头的值被解析为服务器环境变量",
            category="STATE_TRANSITION",
            risk="环境变量包含敏感信息（数据库密码、API key），若攻击者可控制 env var name，可导致服务端凭据泄露",
            patterns=[
                {"type": "regex", "pattern": r"startswith\s*\(\s*['\"]\$['\"]"},
                {"type": "regex", "pattern": r"os\.environ\.get|os\.getenv"},
                {"type": "regex", "pattern": r"\$\{?[A-Z_][A-Z0-9_]*\}?"},
            ],
        ),
        AssumptionSignature(
            label="plaintext_handling",
            assumption="凭据在内存中以明文形式处理",
            category="STATE_TRANSITION",
            risk="明文凭据可能被日志记录、core dump 泄露或通过侧信道泄露",
            patterns=[
                {"type": "regex", "pattern": r"(?:api_key|secret|password|token)\s*[=:].*['\"][^'\"]{4,}['\"]"},
            ],
        ),
        AssumptionSignature(
            label="credential_return",
            assumption="凭据作为函数返回值传递",
            category="TRUST_BOUNDARY",
            risk="返回的凭据可能被调用方记录到日志或转发到外部",
            patterns=[
                {"type": "regex", "pattern": r"return\s+(?:self\.\w*)?(?:api_key|secret|password|token|credential)\b"},
            ],
        ),
    ],
    "secret_management": [
        AssumptionSignature(
            label="opaque_storage",
            assumption="secret 值作为不透明字符串存储，不解释其内容",
            category="TRUST_BOUNDARY",
            risk="若存储的 secret 被后续代码解析（如 $ENV 变量展开），则存储的保护失效",
            patterns=[
                {"type": "regex", "pattern": r"encrypt|encrypted|cipher|kek|dek|wrapped"},
                {"type": "regex", "pattern": r"Column\(.*String|Text|VARCHAR"},
            ],
        ),
        AssumptionSignature(
            label="opaque_storage",  # same label — either pattern triggers it
            assumption="secret 值作为不透明字符串存储",
            category="TRUST_BOUNDARY",
            risk="若存储的 secret 被后续代码解析，则存储的保护失效",
            patterns=[
                {"type": "regex", "pattern": r"secret_id|secret_name|secret_value|encrypted_value"},
                {"type": "neg_regex", "pattern": r"exec|eval|compile|__import__"},
            ],
        ),
        AssumptionSignature(
            label="deserialization_trust",
            assumption="从存储加载的值不会被反序列化为代码",
            category="PARSER",
            risk="存储的值若包含序列化 payload，反序列化时可导致 RCE",
            patterns=[
                {"type": "regex", "pattern": r"pickle\.loads|yaml\.load\b|json\.loads"},
            ],
        ),
    ],
    "gateway": [
        AssumptionSignature(
            label="external_forward",
            assumption="数据被转发到外部 URL",
            category="TRUST_BOUNDARY",
            risk="外部 URL 若由用户控制，可导致 SSRF",
            patterns=[
                {"type": "regex", "pattern": r"api_base|base_url|endpoint_url|proxy_url|litellm"},
                {"type": "regex", "pattern": r"requests\.(?:post|get|put|patch)|\bhttpx\b|urllib"},
            ],
        ),
        AssumptionSignature(
            label="auth_header_forward",
            assumption="认证凭据在 HTTP 请求头中转发",
            category="STATE_TRANSITION",
            risk="认证头可能被记录在代理日志或 access log 中",
            patterns=[
                {"type": "regex", "pattern": r"Authorization|Bearer|X-API-Key|api_key.*header"},
            ],
        ),
        AssumptionSignature(
            label="dynamic_endpoint",
            assumption="外部 API endpoint 地址在运行时动态确定",
            category="STATE_TRANSITION",
            risk="若 endpoint 可由攻击者控制（如通过配置注入或用户输入），可导致 SSRF 或凭据外泄",
            patterns=[
                {"type": "regex", "pattern": r"(?:api_base|base_url)\s*="},
                {"type": "neg_regex", "pattern": r"api_base\s*=\s*['\"][^'\"]+['\"]"},
            ],
        ),
    ],
    "authentication": [
        AssumptionSignature(
            label="credential_validation",
            assumption="用户凭据在每次请求时都被验证",
            category="TRUST_BOUNDARY",
            risk="认证检查可能被绕过（缓存、跳过检查路径、认证前泄露信息）",
            patterns=[
                {"type": "regex", "pattern": r"authenticate|login|verify_credential|check_auth|validate_token"},
            ],
        ),
        AssumptionSignature(
            label="no_credential_leak",
            assumption="认证逻辑不会泄露凭据信息",
            category="TRUST_BOUNDARY",
            risk="错误消息中可能包含凭据片段，帮助攻击者枚举有效账号",
            patterns=[
                {"type": "regex", "pattern": r"authenticate|login|verify|check_auth|password|credential"},
                {"type": "neg_regex", "pattern": r"return.*Invalid (?:username|email|credential|password)"},
                {"type": "neg_regex", "pattern": r"User not found|user.*(?:not found|doesn't exist|invalid)"},
            ],
        ),
    ],
    "token_management": [
        AssumptionSignature(
            label="signature_verification",
            assumption="JWT/token 签名在每次使用前都被验证",
            category="TRUST_BOUNDARY",
            risk="缺少签名验证可导致 token 伪造",
            patterns=[
                {"type": "regex", "pattern": r"jwt\.decode|verify_token|validate_token"},
                {"type": "neg_regex", "pattern": r"verify\s*=\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]"},
            ],
        ),
        AssumptionSignature(
            label="expiration_check",
            assumption="token 有有效期且在过期后被拒绝",
            category="STATE_TRANSITION",
            risk="无过期检查的 token 可被无限期使用",
            patterns=[
                {"type": "regex", "pattern": r"exp|expiration|expire|timeout|iat|nbf"},
                {"type": "neg_regex", "pattern": r"exp.*=.*None|expire.*False|skip.*exp"},
            ],
        ),
    ],
    "authorization": [
        AssumptionSignature(
            label="permission_check",
            assumption="每次资源访问都经过权限检查",
            category="TRUST_BOUNDARY",
            risk="缺少权限检查可导致越权访问",
            patterns=[
                {"type": "regex", "pattern": r"permission|privilege|role|rbac|acl|access_control"},
                {"type": "regex", "pattern": r"if.*(?:allowed|permission|has_role|can_access|authorize)"},
            ],
        ),
        AssumptionSignature(
            label="owner_check",
            assumption="资源访问检查所有者身份",
            category="OBJECT_IDENTITY",
            risk="缺少所有者检查可导致 IDOR — 用户可访问非自身资源",
            patterns=[
                {"type": "regex", "pattern": r"owner|user_id|resource_owner|created_by"},
                {"type": "neg_regex", "pattern": r"owner\s*==|user_id\s*==|\.owner\s*="},
            ],
        ),
    ],
    "input_validation": [
        AssumptionSignature(
            label="server_side_validation",
            assumption="输入验证在服务端执行",
            category="TRUST_BOUNDARY",
            risk="仅在客户端验证的输入可被直接绕过（JS 验证、仅前端正则）",
            patterns=[
                {"type": "regex", "pattern": r"validate|sanitize|cleanse|filter|escape|purify"},
            ],
        ),
        AssumptionSignature(
            label="encoding_consistency",
            assumption="输入验证和解码使用相同的编码方式",
            category="PARSER",
            risk="编码差异可导致验证绕过（UTF-8 绕过 XSS 过滤、Unicode 规范化差异）",
            patterns=[
                {"type": "regex", "pattern": r"decode|encode|unicode|utf|charset|normalize"},
            ],
        ),
    ],
    "session_management": [
        AssumptionSignature(
            label="secure_session_id",
            assumption="Session ID 由安全随机数生成器生成",
            category="STATE_TRANSITION",
            risk="可预测的 session ID 可导致会话劫持",
            patterns=[
                {"type": "regex", "pattern": r"secrets\.|os\.urandom|uuid4|random\.SystemRandom"},
                {"type": "neg_regex", "pattern": r"random\.randint|random\.choice"},
            ],
        ),
        AssumptionSignature(
            label="logout_invalidation",
            assumption="退出登录时 session 被完全失效",
            category="STATE_TRANSITION",
            risk="未失效的 session 可被攻击者继续使用",
            patterns=[
                {"type": "regex", "pattern": r"logout|invalidate|clear.*session|session\.clear|delete.*session"},
            ],
        ),
    ],
    "data_protection": [
        AssumptionSignature(
            label="redaction_coverage",
            assumption="敏感数据在所有输出路径上都被脱敏",
            category="TRUST_BOUNDARY",
            risk="漏掉一个输出路径即可导致 PII 泄露",
            patterns=[
                {"type": "regex", "pattern": r"mask|redact|anonymize|obfuscate|truncat"},
            ],
        ),
    ],
    "cryptography": [
        AssumptionSignature(
            label="modern_algorithm",
            assumption="使用现代加密算法（非 MD5/SHA1/DES）",
            category="INVARIANT",
            risk="MD5/SHA1/DES 等已破解算法可被暴力破解或碰撞",
            patterns=[
                {"type": "regex", "pattern": r"AES|ChaCha|bcrypt|argon2|SHA256|SHA3|RSA-OAEP|ED25519"},
                {"type": "neg_regex", "pattern": r"MD5|SHA-?1|DES|RC4|ECB"},
            ],
        ),
    ],
    "configuration": [
        AssumptionSignature(
            label="trusted_config_source",
            assumption="配置来源是可信的",
            category="TRUST_BOUNDARY",
            risk="若配置来源可由攻击者控制（如 env var、用户上传的 config），可导致任意配置注入",
            patterns=[
                {"type": "regex", "pattern": r"config|settings|yaml|json|toml"},
                {"type": "regex", "pattern": r"os\.environ|env|environ|env_loader"},
            ],
        ),
        AssumptionSignature(
            label="safe_deserialization",
            assumption="配置反序列化使用安全方法",
            category="PARSER",
            risk="yaml.load（无 Loader）可导致任意代码执行；eval 直接执行",
            patterns=[
                {"type": "regex", "pattern": r"yaml\.load\b"},
                {"type": "neg_regex", "pattern": r"Loader|SafeLoader|FullLoader"},
            ],
        ),
    ],
    "security_boundary": [
        AssumptionSignature(
            label="sandbox_isolation",
            assumption="沙箱/隔离机制不可绕过",
            category="TRUST_BOUNDARY",
            risk="沙箱逃逸可导致完全权限失控",
            patterns=[
                {"type": "regex", "pattern": r"sandbox|isolate|restrict|container|namespace"},
            ],
        ),
        AssumptionSignature(
            label="rate_limit",
            assumption="速率限制在所有入口点都被执行",
            category="TRUST_BOUNDARY",
            risk="缺少速率限制可导致暴力破解或 DoS",
            patterns=[
                {"type": "regex", "pattern": r"rate_limit|throttle|quota|max_requests"},
            ],
        ),
    ],
    "privilege_management": [
        AssumptionSignature(
            label="escalation_prevention",
            assumption="权限提升被明确禁止",
            category="TRUST_BOUNDARY",
            risk="缺少提升检查可导致水平/垂直越权",
            patterns=[
                {"type": "regex", "pattern": r"escalat|elevat|impersonat|suplant"},
            ],
        ),
    ],
    "execution_controller": [
        AssumptionSignature(
            label="no_arbitrary_exec",
            assumption="不会执行任意用户提供的代码",
            category="TRUST_BOUNDARY",
            risk="exec/eval/subprocess 执行用户输入可导致 RCE",
            patterns=[
                {"type": "regex", "pattern": r"exec|eval|compile|__import__|subprocess"},
                {"type": "neg_regex", "pattern": r"shlex\.quote|shell=False|input.*validate"},
            ],
        ),
    ],
    "audit": [
        AssumptionSignature(
            label="log_no_sensitive",
            assumption="审计日志不包含敏感数据",
            category="TRUST_BOUNDARY",
            risk="敏感数据（密码、token）写入日志可导致凭据泄露",
            patterns=[
                {"type": "regex", "pattern": r"audit|audit_log|logger|logging"},
                {"type": "neg_regex", "pattern": r"password|secret|token|credential"},
            ],
        ),
    ],
    "trust_management": [
        AssumptionSignature(
            label="cert_validation_enabled",
            assumption="TLS 证书验证已启用",
            category="TRUST_BOUNDARY",
            risk="禁用证书验证可导致中间人攻击",
            patterns=[
                {"type": "regex", "pattern": r"verify|ssl|certificate|cert"},
                {"type": "neg_regex", "pattern": r"verify\s*=\s*False|check_hostname\s*=\s*False"},
            ],
        ),
    ],
}

# ── Knowledge category groupings (from boxIdea.md: 7 knowledge kinds) ──
# Used to identify which category pairs can produce meaningful contradictions.

_CONTRADICTION_MATRIX: dict[tuple[str, str], str] = {
    ("TRUST_BOUNDARY", "STATE_TRANSITION"): "信任边界被状态转换绕过",
    ("TRUST_BOUNDARY", "PARSER"): "信任边界被解析差异绕过",
    ("STATE_TRANSITION", "OBJECT_IDENTITY"): "状态转换导致对象身份混淆",
    ("TRUST_BOUNDARY", "OBJECT_IDENTITY"): "信任边界被身份混淆绕过",
    ("PARSER", "STATE_TRANSITION"): "解析差异导致不安全状态转换",
    ("INVARIANT", "STATE_TRANSITION"): "不变量被状态转换破坏",
    ("INVARIANT", "PARSER"): "不变量被解析差异破坏",
    ("INVARIANT", "TRUST_BOUNDARY"): "安全不变量在信任边界处被破坏",
}


# ---------------------------------------------------------------------------
# Phase 1: Deterministic Assumption Extraction
# ---------------------------------------------------------------------------


def _match_signature(source: str, sig: AssumptionSignature) -> list[str] | None:
    """Check source code against an AssumptionSignature.

    AND logic: all ``"regex"`` patterns must match (at least one positive match
    required if any exist), and no ``"neg_regex"`` patterns may match.

    Returns list of matching evidence strings, or None if the signature
    does NOT apply to this source.
    """
    pos_patterns = [p for p in sig.patterns if p.get("type") != "neg_regex"]
    neg_patterns = [p for p in sig.patterns if p.get("type") == "neg_regex"]

    # Negative patterns: if any match, the assumption does NOT apply
    for p in neg_patterns:
        try:
            if re.search(p["pattern"], source):
                return None
        except re.error:
            continue

    # Positive patterns: at least one must match (OR within positive)
    evidence: list[str] = []
    if not pos_patterns:
        return evidence  # no positive patterns → vacuously true

    for p in pos_patterns:
        try:
            m = re.search(p["pattern"], source)
            if m:
                evidence.append(m.group())
        except re.error:
            continue

    return evidence if evidence else None


def extract_assumptions(
    anchor_type: str,
    anchor_name: str,
    file_path: str,
    source_code: str,
) -> list[Assumption]:
    """Phase 1: Extract assumptions from a single semantic anchor match.

    Pure deterministic — matches regex patterns against source code.
    No LLM calls.
    """
    if not source_code.strip():
        return []

    assumptions: list[Assumption] = []
    signatures = _ANCHOR_ASSUMPTION_TEMPLATES.get(anchor_type, [])

    for sig in signatures:
        evidence = _match_signature(source_code, sig)
        if evidence is None:
            continue

        # Find the line number of first match
        line_no = 0
        if evidence:
            first_pat = evidence[0]
            for i, line in enumerate(source_code.splitlines(), 1):
                if first_pat in line:
                    line_no = i
                    break

        assumptions.append(Assumption(
            anchor_type=anchor_type,
            anchor_name=anchor_name,
            file_path=file_path,
            label=sig.label,
            assumption=sig.assumption,
            evidence="; ".join(evidence[:3]),
            category=sig.category,
            line_number=line_no,
        ))

    return assumptions


def extract_all_assumptions(
    anchor_matches: list,
) -> list[Assumption]:
    """Extract assumptions from all semantic anchor findings.

    Args:
        anchor_matches: List of SemanticAnchorMatch objects from
            ``SemanticAnchorFinder.matches``.

    Returns:
        List of all extracted Assumption objects.  Empty list if no
        anchors provided.
    """
    all_assumptions: list[Assumption] = []

    for match in anchor_matches:
        source_code = getattr(match, "source_code", None) or ""
        if not source_code.strip():
            continue

        assumptions = extract_assumptions(
            anchor_type=match.anchor_type,
            anchor_name=match.name,
            file_path=match.file_path,
            source_code=source_code,
        )
        all_assumptions.extend(assumptions)

        # Also check companion methods (for class-level anchors)
        companions = getattr(match, "companion_methods", []) or []
        for cm in companions:
            cm_code = ""
            if isinstance(cm, dict):
                cm_code = cm.get("code", "") or ""
            elif hasattr(cm, "code"):
                cm_code = cm.code or ""

            if not cm_code.strip():
                continue

            cm_name = ""
            if isinstance(cm, dict):
                cm_name = cm.get("name", match.name)
            elif hasattr(cm, "name"):
                cm_name = cm.name
            else:
                cm_name = match.name

            cm_assumptions = extract_assumptions(
                anchor_type=match.anchor_type,
                anchor_name=cm_name,
                file_path=match.file_path,
                source_code=cm_code,
            )
            all_assumptions.extend(cm_assumptions)

    return all_assumptions


# ---------------------------------------------------------------------------
# Phase 2: Contradiction Detection
# ---------------------------------------------------------------------------
# Known contradiction rules between specific assumption labels.
# The key insight: most high-value findings come from assumptions that
# CONTRADICT across different business domains (anchor types).
#
# Format: (label_a, label_b, severity, description_template)

# Priority labels: contradictions involving these labels are ranked higher
_CONTRADICTION_LABEL_PRIORITY: dict[str, int] = {
    "env_resolution": 3,       # env vars = high-leverage attack surface
    "opaque_storage": 2,       # opaque storage bypassed = trust boundary violated
    "external_forward": 2,     # external forwarding = data exfiltration vector
    "dynamic_endpoint": 2,     # dynamic endpoints = SSRF vector
    "safe_deserialization": 2, # unsafe deserialization = RCE
    "credential_return": 1,    # credential as return value
    "plaintext_handling": 1,   # plaintext = leak vector
    "permission_check": 1,     # permission boundary
    "owner_check": 1,          # ownership boundary
}

# Max contradictions to return after ranking
_MAX_CONTRADICTIONS = 15


_CONTRADICTION_RULES: list[tuple[str, str, str, str]] = [
    (
        "env_resolution", "opaque_storage",
        "high",
        "秘密管理将值作为不透明字符串存储（{file_a}），但凭据管理将其解析为环境变量（{file_b}）。"
        "若攻击者可控制环境变量名称，则可泄露服务端凭据。"
    ),
    (
        "env_resolution", "plaintext_handling",
        "high",
        "凭据既被解析为环境变量（{file_a}）又以明文处理（{file_b}），"
        "环境变量泄露 = 凭据直接泄露。"
    ),
    (
        "env_resolution", "external_forward",
        "high",
        "凭据从环境变量解析（{file_a}）后被转发到外部 URL（{file_b}）。"
        "若外部 URL 可由攻击者控制，则凭据被直接发送给攻击者。"
    ),
    (
        "env_resolution", "credential_return",
        "medium",
        "环境变量解析的凭据（{file_a}）作为函数返回值传递（{file_b}），"
        "调用方可能将返回值记录日志或转发。"
    ),
    (
        "credential_return", "external_forward",
        "high",
        "凭据作为返回值传递（{file_a}）后最终被转发到外部 URL（{file_b}）。"
        "攻击者可利用此路径截获凭据。"
    ),
    (
        "signature_verification", "expiration_check",
        "medium",
        "token 签名验证存在（{file_a}）但过期检查缺失（{file_b}），"
        "泄露的 token 可被无限期使用。"
    ),
    (
        "permission_check", "owner_check",
        "high",
        "访问控制有权限检查（{file_a}）但缺少所有者确认（{file_b}），"
        "可导致 IDOR — 用户可访问非自身资源。"
    ),
    (
        "trusted_config_source", "safe_deserialization",
        "high",
        "配置从外部来源加载（{file_a}）且使用不安全的反序列化（{file_b}），"
        "可导致任意代码执行。"
    ),
    (
        "safe_deserialization", "no_arbitrary_exec",
        "high",
        "存在不安全反序列化（{file_a}）但缺少执行限制（{file_b}），"
        "反序列化漏洞可直接升级为 RCE。"
    ),
    (
        "server_side_validation", "encoding_consistency",
        "medium",
        "存在服务端验证（{file_a}）但编解码可能不一致（{file_b}），"
        "编码差异可导致验证绕过。"
    ),
    (
        "credential_validation", "logout_invalidation",
        "medium",
        "存在凭据验证（{file_a}）但 session 退出时不失效（{file_b}），"
        "认证 session 可被重复使用。"
    ),
    (
        "credential_validation", "expiration_check",
        "low",
        "存在凭据验证（{file_a}）但缺少会话过期检查（{file_b}），"
        "长期有效的会话可被劫持使用。"
    ),
    (
        "sandbox_isolation", "external_forward",
        "medium",
        "存在沙箱隔离（{file_a}）同时数据被转发到外部 URL（{file_b}），"
        "沙箱的数据外泄保护可能被绕过。"
    ),
    (
        "redaction_coverage", "log_no_sensitive",
        "medium",
        "存在数据脱敏（{file_a}）但审计日志未主动排除敏感字段（{file_b}），"
        "脱敏遗漏的字段可能出现在日志中。"
    ),
    (
        "cert_validation_enabled", "env_resolution",
        "medium",
        "TLS 证书验证存在（{file_a}）但凭据通过环境变量注入（{file_b}），"
        "若环境变量包含 CA 路径或证书，可能被覆盖。"
    ),
]


def _contradiction_proximity_score(a: Assumption, b: Assumption) -> int:
    """Score how closely related two assumptions are by file proximity.

    Returns 0-5 score where higher = more likely to be a real finding.
    """
    score = 0

    # Same file → highly related
    if a.file_path == b.file_path:
        score += 3
    else:
        # Same directory (depth 1) → related
        a_dir = os.path.dirname(a.file_path)
        b_dir = os.path.dirname(b.file_path)
        if a_dir == b_dir:
            score += 2
        else:
            # Share 2+ path components → same subpackage
            a_parts = a_dir.split(os.sep)
            b_parts = b_dir.split(os.sep)
            common = sum(1 for x, y in zip(a_parts, b_parts) if x == y)
            if common >= 2:
                score += 1

    # Label priority
    score += _CONTRADICTION_LABEL_PRIORITY.get(a.label, 0)
    score += _CONTRADICTION_LABEL_PRIORITY.get(b.label, 0)

    return score


def detect_contradictions(assumptions: list[Assumption]) -> list[Contradiction]:
    """Phase 2: Cross-reference all assumptions to find contradictions.

    Pure deterministic — matches assumption labels against known
    contradiction rules.  No LLM calls.

    Only detects contradictions between DIFFERENT anchor types, since
    same-type assumptions are typically consistent with each other.

    Results are ranked by proximity score (same file > same directory >
    same subpackage > different package), so the most relevant
    contradictions appear first.
    """
    contradictions: list[Contradiction] = []

    # Index assumptions by label for O(n) lookup
    by_label: dict[str, list[Assumption]] = {}
    for a in assumptions:
        by_label.setdefault(a.label, []).append(a)

    for label_a, label_b, severity, desc_template in _CONTRADICTION_RULES:
        group_a = by_label.get(label_a, [])
        group_b = by_label.get(label_b, [])
        if not group_a or not group_b:
            continue

        # Cross-domain contradiction: only different anchor types
        for a in group_a:
            for b in group_b:
                if a.anchor_type == b.anchor_type:
                    continue  # Same component — likely consistent, skip

                description = desc_template.format(
                    file_a=f"{os.path.basename(a.file_path)}:{a.line_number} ({a.anchor_name})",
                    file_b=f"{os.path.basename(b.file_path)}:{b.line_number} ({b.anchor_name})",
                )

                contradictions.append(Contradiction(
                    assumption_a=a,
                    assumption_b=b,
                    description=description,
                    severity=severity,
                ))

    # Rank by proximity score and cap
    contradictions.sort(
        key=lambda c: _contradiction_proximity_score(c.assumption_a, c.assumption_b),
        reverse=True,
    )

    # Deduplicate: keep only the highest-scored contradiction per
    # (file_a, label_a, file_b, label_b) pair.  This prevents O(n)
    # blowups where one assumption (e.g. opaque_storage in EncryptedSecret)
    # pairs with every instance of another label (e.g. dynamic_endpoint in
    # every gateway method).
    seen_pairs: set[tuple[str, str, str, str]] = set()
    deduped: list[Contradiction] = []
    for c in contradictions:
        key = (
            c.assumption_a.file_path,
            c.assumption_a.label,
            c.assumption_b.file_path,
            c.assumption_b.label,
        )
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        deduped.append(c)

    return deduped[:_MAX_CONTRADICTIONS]


# ---------------------------------------------------------------------------
# Phase 3: Attack Chain Synthesis (LLM)
# ---------------------------------------------------------------------------

_CHAIN_SYNTHESIS_PROMPT = """你是一个安全分析员，需要根据以下安全假设矛盾推理攻击链。

发现以下安全假设矛盾：

{contradictions_text}

这些矛盾来自不同安全组件的假设碰撞。请分析：

1. 这些矛盾中哪些可以组合成完整的攻击链？
2. 攻击者需要具备什么前提条件？
3. 攻击的具体步骤是什么？
4. 最终影响是什么？

输出格式：
```json
{{
  "attack_chains": [
    {{
      "chain_id": "CVE-like identifier",
      "title": "攻击链标题",
      "prerequisites": ["前提条件1", "前提条件2"],
      "steps": ["步骤1", "步骤2", "步骤3"],
      "impact": "最终影响",
      "confidence": 1-10
    }}
  ]
}}
```"""


def synthesize_chains(
    contradictions: list[Contradiction],
    llm_call: Callable[[str], str | None] | None = None,
) -> str:
    """Phase 3: Synthesize attack chains from confirmed contradictions.

    Only calls LLM when contradictions exist.  Falls back to structured
    text when no LLM callable is provided.
    """
    if not contradictions:
        return ""

    # Group by severity for ranking
    high = [c for c in contradictions if c.severity == "high"]

    # Build contradictions text (prioritize high severity)
    sorted_contradictions = sorted(
        contradictions,
        key=lambda c: {"high": 0, "medium": 1, "low": 2}[c.severity],
    )
    selected = sorted_contradictions[:10]  # limit to top 10

    parts = []
    for i, c in enumerate(selected):
        parts.append(
            f"矛盾 {i+1} [{c.severity.upper()}]:\n"
            f"  假设 A ({c.assumption_a.anchor_type}/{c.assumption_a.label}): {c.assumption_a.assumption}\n"
            f"    证据: {c.assumption_a.evidence}\n"
            f"  假设 B ({c.assumption_b.anchor_type}/{c.assumption_b.label}): {c.assumption_b.assumption}\n"
            f"    证据: {c.assumption_b.evidence}\n"
            f"  矛盾描述: {c.description}\n"
        )

    if llm_call is not None:
        prompt = _CHAIN_SYNTHESIS_PROMPT.format(
            contradictions_text="\n".join(parts),
        )
        try:
            return llm_call(prompt) or ""
        except Exception:
            logger.debug("Chain synthesis LLM call failed", exc_info=True)
            return ""

    # Deterministic fallback
    lines = ["## 安全假设矛盾（无 LLM 合成）", ""]
    for c in selected:
        lines.append(f"- [{c.severity.upper()}] {c.description}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Assumption Agent (rewritten)
# ---------------------------------------------------------------------------


class AssumptionAgent:
    """Three-phase assumption analysis for sink-free vulnerability discovery.

    Replaces the old per-sink-path LLM approach.  Operates on ALL semantic
    anchor findings from Phase B.7.

    Phases
    ------
    Phase 1: AST/regex-based assumption extraction from semantic anchor code
    Phase 2: Cross-finding contradiction detection (deterministic rules)
    Phase 3: LLM attack chain synthesis (only on confirmed contradictions)
    """

    def __init__(self) -> None:
        self._assumptions: list[Assumption] = []
        self._contradictions: list[Contradiction] = []
        self._chain_result: str = ""

    def run_all(
        self,
        anchor_matches: list,
        llm_call: Callable[[str], str | None] | None = None,
    ) -> dict[str, Any]:
        """Run Phases 1-3 on all semantic anchor findings.

        Args:
            anchor_matches: List of SemanticAnchorMatch objects.
            llm_call: Optional LLM callable for Phase 3 synthesis.
                Signature: ``fn(prompt: str) -> str | None``.

        Returns:
            Dict with keys:
              - ``assumptions``: list of Assumption
              - ``contradictions``: list of Contradiction
              - ``attack_chains``: str (LLM output or structured fallback)
        """
        # Phase 1: Extract assumptions
        self._assumptions = extract_all_assumptions(anchor_matches)

        # Phase 2: Detect contradictions
        self._contradictions = detect_contradictions(self._assumptions)

        # Phase 3: Synthesize attack chains (LLM only if contradictions)
        self._chain_result = synthesize_chains(self._contradictions, llm_call)

        return {
            "assumptions": self._assumptions,
            "contradictions": self._contradictions,
            "attack_chains": self._chain_result,
        }

    @property
    def assumptions(self) -> list[Assumption]:
        return self._assumptions

    @property
    def contradictions(self) -> list[Contradiction]:
        return self._contradictions

    @property
    def chain_result(self) -> str:
        return self._chain_result

    def format_for_blackboard(self) -> list[tuple[str, str]]:
        """Format assumptions + contradictions as knowledge entries.

        Records to BlackboardAggregator for cross-phase knowledge sharing.
        """
        entries: list[tuple[str, str]] = []

        for a in self._assumptions:
            fn = a.anchor_name[:60]
            text = (
                f"[ASSUMPTION {a.label}] "
                f"{a.assumption} | "
                f"category={a.category} | "
                f"evidence={a.evidence[:100]}"
            )
            entries.append((fn, text))

        for c in self._contradictions:
            key = f"contradiction:{c.assumption_a.anchor_name}x{c.assumption_b.anchor_name}"
            text = (
                f"[CONTRADICTION {c.severity}] "
                f"{c.description[:200]}"
            )
            entries.append((key, text))

        return entries

    def format_results(self) -> str:
        """Human-readable summary of all findings."""
        lines: list[str] = []

        if self._assumptions:
            # Group by category
            by_cat: dict[str, list[Assumption]] = {}
            for a in self._assumptions:
                by_cat.setdefault(a.category, []).append(a)
            lines.append(f"Assumptions extracted: {len(self._assumptions)}")
            for cat, items in sorted(by_cat.items()):
                lines.append(f"  [{cat}] {len(items)} assumptions")
                for a in items[:3]:
                    lines.append(f"    {a.anchor_name}: {a.assumption}")
                if len(items) > 3:
                    lines.append(f"    ... and {len(items) - 3} more")

        if self._contradictions:
            high = sum(1 for c in self._contradictions if c.severity == "high")
            med = sum(1 for c in self._contradictions if c.severity == "medium")
            lines.append(f"\nContradictions detected: {len(self._contradictions)} ({high} high, {med} medium)")
            for c in self._contradictions:
                lines.append(f"  [{c.severity}] {c.description[:120]}...")

        if self._chain_result:
            lines.append(f"\nAttack chains:\n{self._chain_result[:500]}")

        return "\n".join(lines)
