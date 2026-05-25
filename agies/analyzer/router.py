"""Route analyzer: maps backend endpoints ↔ frontend API calls.

This is the core of P0 improvement — preventing false positives by
understanding which backend endpoints are actually reachable from
which frontend, and which code paths are dead/commented out.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from pydantic import BaseModel


# ── Data Models ───────────────────────────────────────────────────────────

class EndpointParam(BaseModel):
    """A parameter extracted from a controller method."""
    name: str = ""
    source: str = ""  # path / query / body / header
    type_hint: str = ""


class BackendEndpoint(BaseModel):
    """A single backend API endpoint."""
    http_method: str           # GET / POST / PUT / DELETE
    path: str                  # e.g. /system/product/preview/{productId}
    controller_class: str      # e.g. ProductController
    controller_method: str     # e.g. previewProductFile
    java_file: str             # source file path
    line_number: int = 0
    has_pre_authorize: bool = False  # has @PreAuthorize annotation
    has_common_service: bool = False  # @Autowired CommonService (active)
    common_service_commented: bool = False  # CommonService is commented out
    deprecated: bool = False
    comment_says_public: bool = False  # comment says "公开访问" etc
    params: list[EndpointParam] = []


class FrontendApiCall(BaseModel):
    """A frontend API call extracted from JS/TS files."""
    function_name: str        # e.g. previewProduct
    url_pattern: str          # e.g. /system/product/preview/${productId}
    resolved_path: str = ""   # e.g. /system/product/preview/{productId}
    http_method: str = "GET"  # implied or explicit
    source_file: str          # JS/TS file path
    line_number: int = 0


class RouteMapping(BaseModel):
    """Cross-reference between frontend and backend."""
    frontend_call: FrontendApiCall
    backend_endpoint: Optional[BackendEndpoint] = None
    matched: bool = False


class RouteMap(BaseModel):
    """Complete route analysis result."""
    endpoints: list[BackendEndpoint] = []
    frontend_calls: list[FrontendApiCall] = []
    mappings: list[RouteMapping] = []
    unmatched_backend: list[BackendEndpoint] = []   # backend but no frontend
    unmatched_frontend: list[FrontendApiCall] = []   # frontend but no backend


# ── Java Controller Parser ────────────────────────────────────────────────

_CLASS_ANNOT_RE = re.compile(r'@(RequestMapping|RestController|Controller)\b')
_METHOD_MAPPING_RE = re.compile(
    r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)'
    r'\s*\(\s*(?:"([^"]*)"|\'([^\']*)\'|path\s*=\s*"?([^")\s]+))?'
)
_PREAUTHORIZE_RE = re.compile(r'@PreAuthorize')
_AUTOWIRED_RE = re.compile(r'@Autowired\s')
_COMMENTED_AUTOWIRED_RE = re.compile(r'//\s*@Autowired')
_COMMENTED_IMPORT_RE = re.compile(r'//\s*import\s+.*CommonService')
_IMPORT_COMMONSERVICE_RE = re.compile(r'import\s+com\.ruoyi\.system\.service\.CommonService')
_COMMENT_PUBLIC_RE = re.compile(r'公开访问|公开|permitAll|no auth|不需要权限|不需要验证|匿名访问', re.IGNORECASE)
_CLASS_REQ_MAPPING_RE = re.compile(
    r'@RequestMapping\s*\(\s*(?:"([^"]*)"|\'([^\']*)\'|value\s*=\s*"?([^")\s]+))?'
)
_DEPRECATED_RE = re.compile(r'@Deprecated|@deprecated')


def parse_java_controllers(target_dir: str) -> list[BackendEndpoint]:
    """Scan Java files and extract all controller endpoints."""
    endpoints = []
    for root, dirs, files in os.walk(target_dir):
        _skip_dirs(dirs)
        for f in files:
            if f.endswith(".java") or f.endswith(".kt"):
                filepath = os.path.join(root, f)
                endpoints.extend(_parse_controller_file(filepath))
    return endpoints


def _skip_dirs(dirs: list[str]):
    dirs[:] = [d for d in dirs
               if not d.startswith(".") and d not in (
                   "node_modules", "venv", ".venv", "__pycache__",
                   "dist", "build", "target", ".git")]


def _parse_controller_file(filepath: str) -> list[BackendEndpoint]:
    """Parse a single Java/Kotlin controller file."""
    endpoints = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return endpoints

    source_text = "".join(lines)

    # Skip if not a controller
    if not _CLASS_ANNOT_RE.search(source_text):
        return endpoints

    # Class-level @RequestMapping path
    class_path = ""
    for line in lines:
        m = _CLASS_REQ_MAPPING_RE.search(line)
        if m:
            class_path = m.group(1) or m.group(2) or m.group(3) or ""
            break

    # Determine class name
    class_name = _extract_class_name(lines)

    # Check CommonService usage
    autowired_active = bool(re.search(r'@Autowired\s+(?!//)', source_text))
    common_service_imported = bool(_IMPORT_COMMONSERVICE_RE.search(source_text))
    common_service_commented = bool(_COMMENTED_IMPORT_RE.search(source_text)) or \
        bool(re.search(r'//.*CommonService', source_text))

    # Parse each method
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip commented-out lines
        if stripped.startswith("//") or stripped.startswith("*"):
            i += 1
            continue

        m = _METHOD_MAPPING_RE.search(line)
        if m:
            http_method = m.group(1).upper().replace("MAPPING", "").replace("REQUEST", "")
            if not http_method:
                http_method = "GET"
            path_part = m.group(2) or m.group(3) or m.group(4) or ""

            # Collect surrounding lines to find @PreAuthorize, etc.
            pre_auth = False
            deprecated = False
            comment_says_public = False
            method_line = i
            params_list = []

            # Look backwards for annotations
            j = i - 1
            while j >= 0 and j >= i - 8:
                prev = lines[j].strip()
                if _PREAUTHORIZE_RE.search(prev):
                    pre_auth = True
                if _DEPRECATED_RE.search(prev):
                    deprecated = True
                if _COMMENT_PUBLIC_RE.search(prev):
                    comment_says_public = True
                if prev.startswith("//") or prev.startswith("*") or prev.startswith("@") or prev == "" or prev == "{":
                    j -= 1
                else:
                    break

            # Additional: look at the Javadoc/comments
            j = i - 1
            while j >= 0 and j >= i - 15:
                prev_line = lines[j].strip()
                if _COMMENT_PUBLIC_RE.search(prev_line):
                    comment_says_public = True
                j -= 1

            # Build full endpoint path
            full_path = _join_paths(class_path, path_part)

            endpoint = BackendEndpoint(
                http_method=http_method,
                path=full_path,
                controller_class=class_name,
                controller_method=_extract_method_name(lines, i),
                java_file=filepath,
                line_number=i + 1,
                has_pre_authorize=pre_auth,
                has_common_service=common_service_imported and not common_service_commented,
                common_service_commented=common_service_commented,
                deprecated=deprecated,
                comment_says_public=comment_says_public,
                params=params_list,
            )
            endpoints.append(endpoint)

        i += 1

    return endpoints


def _extract_class_name(lines: list[str]) -> str:
    for line in lines:
        m = re.search(r'(?:public\s+)?(?:class|object)\s+(\w+)', line)
        if m:
            return m.group(1)
    return "Unknown"


def _extract_method_name(lines: list[str], idx: int) -> str:
    for i in range(idx, min(idx + 10, len(lines))):
        m = re.search(r'(?:public|private|protected|fun)\s+(?:\w+\s+)*(\w+)\s*\(', lines[i])
        if m:
            return m.group(1)
    return "unknown"


def _join_paths(class_path: str, method_path: str) -> str:
    p1 = class_path.strip("/")
    p2 = method_path.strip("/")
    if not p2:
        return "/" + p1 if p1 else "/"
    if not p1:
        return "/" + p2 if p2 else "/"
    # Avoid duplication
    if p2.startswith(p1):
        return "/" + p2
    return "/" + p1 + "/" + p2


# ── Frontend API Parser ───────────────────────────────────────────────────

_AXIOS_URL_RE = re.compile(r"url\s*:\s*['\"`]([^'\"`]+)['\"`]")
_FETCH_URL_RE = re.compile(r"(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*['\"`]([^'\"`]+)['\"`]")
_TEMPLATE_LITERAL_RE = re.compile(r'\$\{[^}]+\}')
_FUNCTION_EXPORT_RE = re.compile(r'export\s+(?:default\s+)?function\s+(\w+)')
_FUNCTION_CONST_RE = re.compile(r'(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?')
_URL_PARAM_RE = re.compile(r':(\w+)')  # Express-style route params


def parse_frontend_apis(target_dir: str) -> list[FrontendApiCall]:
    """Scan JS/TS/Vue files and extract API call patterns."""
    calls = []
    for root, dirs, files in os.walk(target_dir):
        _skip_dirs(dirs)
        for f in files:
            if f.endswith((".js", ".ts", ".vue")):
                filepath = os.path.join(root, f)
                calls.extend(_parse_frontend_file(filepath))
    return calls


def _parse_frontend_file(filepath: str) -> list[FrontendApiCall]:
    calls = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception:
        return calls

    # Only look at API files or files with URL patterns
    if "/api/" not in filepath.replace("\\", "/") and not re.search(r"url\s*:", source):
        return calls

    lines = source.split("\n")
    current_function = ""

    for i, line in enumerate(lines):
        # Track current function name
        fn_match = _FUNCTION_EXPORT_RE.search(line) or _FUNCTION_CONST_RE.search(line)
        if fn_match:
            current_function = fn_match.group(1)

        # Find URL patterns
        url_match = _AXIOS_URL_RE.search(line) or _FETCH_URL_RE.search(line)
        if url_match:
            raw_url = url_match.group(1)

            # Resolve template literals to Express-style params
            resolved_url = _TEMPLATE_LITERAL_RE.sub(lambda m: f":{_var_name(m.group(0))}", raw_url)

            calls.append(FrontendApiCall(
                function_name=current_function,
                url_pattern=raw_url,
                resolved_path=resolved_url,
                source_file=filepath,
                line_number=i + 1,
            ))

    return calls


def _var_name(template: str) -> str:
    """Extract variable name from ${something}."""
    inner = template.strip("${} ")
    # Handle common patterns: row.productId → productId
    if "." in inner:
        return inner.split(".")[-1]
    return inner


# ── Cross-reference ───────────────────────────────────────────────────────

def normalize_path(path: str) -> str:
    """Normalize path for comparison: lowercase, remove trailing slash."""
    p = path.lower().strip()
    if p.endswith("/"):
        p = p[:-1]
    if not p.startswith("/"):
        p = "/" + p
    return p


def resolve_template_to_param(path: str) -> str:
    """Convert ${id} or {id} style params to {param} for matching."""
    # Handle JS template literals: /product/${id} → /product/{param}
    path = re.sub(r'\$\{[^}]+\}', '{param}', path)
    # Handle Express/Spring params: /product/:id → /product/{param}
    path = re.sub(r':\w+', '{param}', path)
    return path


def cross_reference(endpoints: list[BackendEndpoint],
                    frontend_calls: list[FrontendApiCall]) -> RouteMap:
    """Cross-reference frontend calls against backend endpoints."""
    # Normalize backend paths
    backend_index: dict[str, list[BackendEndpoint]] = {}
    for ep in endpoints:
        key = normalize_path(resolve_template_to_param(ep.path))
        backend_index.setdefault(key, []).append(ep)

    route_map = RouteMap(endpoints=endpoints, frontend_calls=frontend_calls)
    matched_backend = set()

    for fc in frontend_calls:
        fc_key = normalize_path(resolve_template_to_param(fc.resolved_path))
        matches = backend_index.get(fc_key, [])

        if matches:
            # Prefer exact match by method
            best = matches[0]
            route_map.mappings.append(RouteMapping(
                frontend_call=fc,
                backend_endpoint=best,
                matched=True,
            ))
            matched_backend.add(id(best))
        else:
            route_map.unmatched_frontend.append(fc)

    # Collect unmatched backend endpoints
    for ep in endpoints:
        if id(ep) not in matched_backend:
            route_map.unmatched_backend.append(ep)

    return route_map


def build_route_map(target_dir: str, frontend_dirs: list[str] | None = None) -> RouteMap:
    """Full pipeline: parse backend + frontend → cross-reference.

    Args:
        target_dir: Root of the Java project.
        frontend_dirs: List of frontend directories. If None, auto-detect.
    """
    endpoints = parse_java_controllers(target_dir)

    # Auto-detect frontend dirs if not specified
    if frontend_dirs is None:
        frontend_dirs = _detect_frontend_dirs(target_dir)

    all_calls: list[FrontendApiCall] = []
    for fd in frontend_dirs:
        full_path = os.path.join(target_dir, fd) if not os.path.isabs(fd) else fd
        if os.path.isdir(full_path):
            all_calls.extend(parse_frontend_apis(full_path))

    return cross_reference(endpoints, all_calls)


def _detect_frontend_dirs(project_root: str) -> list[str]:
    """Auto-detect frontend directories (ruoyi-ui, new-ui, etc.)."""
    detected = []
    for name in os.listdir(project_root):
        full = os.path.join(project_root, name)
        if os.path.isdir(full) and name.endswith("-ui"):
            detected.append(name)
        # Also check for common frontend indicators
        if os.path.isdir(full):
            has_package = os.path.isfile(os.path.join(full, "package.json"))
            has_src = os.path.isdir(os.path.join(full, "src"))
            if has_package and has_src and name not in ("node_modules",):
                detected.append(name)
    return detected


def format_routes_for_prompt(route_map: RouteMap) -> str:
    """Format route analysis results for LLM system prompt injection."""
    lines = []

    # Active caller routes (frontend → backend)
    matched = [m for m in route_map.mappings if m.matched]
    if matched:
        lines.append("## 前端→后端路由映射（活跃路径）")
        lines.append("以下路径有前端实际调用：")
        for m in matched[:30]:
            be = m.backend_endpoint
            fc = m.frontend_call
            auth = "🔒" if be.has_pre_authorize else "🔓"
            deprecated = " [废弃]" if be.deprecated else ""
            public = " [公开]" if be.comment_says_public else ""
            lines.append(f"  {auth} {be.http_method} {be.path}{deprecated}{public}")
            lines.append(f"     前端: {fc.function_name} ({os.path.basename(fc.source_file)})")
        lines.append("")

    # Unmatched backend (no frontend call — lower priority)
    if route_map.unmatched_backend:
        lines.append("## 后端端点（无前端调用 — 低优先级/可能已废弃）")
        for be in route_map.unmatched_backend[:20]:
            auth = "🔒" if be.has_pre_authorize else "🔓"
            dep = " [废弃]" if be.deprecated else ""
            pub = " [公开]" if be.comment_says_public else ""
            cs = " [⚠️ 依赖CommonService]" if be.has_common_service else ""
            lines.append(f"  {auth} {be.http_method} {be.path}{dep}{pub}{cs}")
        lines.append("")

    # CommonService status
    common_services = [ep for ep in route_map.endpoints if ep.has_common_service]
    commented_services = [ep for ep in route_map.endpoints if ep.common_service_commented]
    if common_services:
        lines.append(f"⚠️ 仍有 {len(common_services)} 个端点活跃使用 CommonService")
    if commented_services:
        lines.append(f"ℹ️ {len(commented_services)} 个端点已注释掉 CommonService")

    return "\n".join(lines)


def format_routes_for_report(route_map: RouteMap) -> str:
    """Format route analysis for the final Markdown report."""
    lines = ["## 路由分析", ""]

    # Endpoint security overview
    total = len(route_map.endpoints)
    authed = sum(1 for ep in route_map.endpoints if ep.has_pre_authorize)
    public = sum(1 for ep in route_map.endpoints if ep.comment_says_public)
    no_auth = total - authed - public

    lines.append(f"**总端点**: {total} | **有@PreAuthorize**: {authed} | **公开设计**: {public} | **裸奔**: {no_auth}")
    lines.append("")

    # Frontend reachability
    matched_count = sum(1 for m in route_map.mappings if m.matched)
    lines.append(f"**前端调用覆盖**: {matched_count}/{len(route_map.frontend_calls)} 路由有后端实现")
    lines.append("")

    # Vulnerable endpoints (no @PreAuthorize AND NOT intentionally public)
    vulnerable = [ep for ep in route_map.endpoints
                  if not ep.has_pre_authorize and not ep.comment_says_public and not ep.deprecated]
    if vulnerable:
        lines.append(f"### 潜在未授权端点 ({len(vulnerable)} 个)")
        lines.append("以下端点既无 @PreAuthorize 也无公开声明，建议人工审核：")
        lines.append("")
        for ep in vulnerable:
            frontend = ""
            for m in route_map.mappings:
                if m.matched and m.backend_endpoint and m.backend_endpoint.path == ep.path:
                    frontend = f" (前端: {m.frontend_call.function_name})"
                    break
            lines.append(f"- `{ep.http_method} {ep.path}` {frontend}")
        lines.append("")

    # Dead code (backend endpoints with no frontend call)
    if route_map.unmatched_backend:
        lines.append(f"### 可能已废弃的端点 ({len(route_map.unmatched_backend)} 个)")
        lines.append("以下后端端点无前端调用，建议确认后清理：")
        lines.append("")
        for ep in route_map.unmatched_backend[:10]:
            lines.append(f"- `{ep.http_method} {ep.path}` ({ep.controller_class})")
        lines.append("")

    return "\n".join(lines)
