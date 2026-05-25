"""Language-level source/sink/sanitizer configuration for taint analysis."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class LanguageAnalysisConfig(BaseModel):
    """Configuration for a single language's taint analysis rules."""
    language: str
    sources: list[str] = []
    sinks: dict[str, str] = {}  # function name -> severity
    sanitizers: list[str] = []


class AnalysisConfig(BaseModel):
    """Top-level configuration for the static analyzer."""
    languages: dict[str, LanguageAnalysisConfig] = {}
    max_call_depth: int = 3
    max_taint_paths: int = 100


def _default_python_config() -> LanguageAnalysisConfig:
    """Return default analysis config for Python."""
    return LanguageAnalysisConfig(
        language="python",
        sources=[
            "request.GET",
            "request.POST",
            "request.data",
            "request.json",
            "request.args",
            "request.form",
            "request.headers",
            "request.cookies",
            "request.files",
            "flask.request",
            "fastapi.Request",
            "django.http.HttpRequest",
            "input",
            "sys.argv",
            "os.environ",
            "open",
        ],
        sinks={
            # Code injection
            "eval": "critical",
            "exec": "critical",
            "compile": "high",
            "__import__": "medium",
            "pickle.loads": "critical",
            "pickle.load": "critical",
            # OS command injection
            "os.system": "critical",
            "os.popen": "critical",
            "subprocess.Popen": "high",
            "subprocess.run": "high",
            "subprocess.call": "high",
            "subprocess.check_output": "high",
            "subprocess.check_call": "high",
            # SQL injection
            "sqlite3.execute": "high",
            "sqlite3.executemany": "high",
            "sqlite3.executescript": "high",
            # Path traversal
            "open": "medium",
            # Unsafe deserialization
            "yaml.load": "high",
            # Debug/leak
            "print": "low",
        },
        sanitizers=[
            "shlex.quote",
            "shlex.escape",
            "html.escape",
            "re.escape",
            "django.utils.html.escape",
            "flask.escape",
            "markupsafe.escape",
        ],
    )


def _default_js_config() -> LanguageAnalysisConfig:
    """Return default analysis config for JavaScript."""
    return LanguageAnalysisConfig(
        language="javascript",
        sources=[
            "req.query",
            "req.body",
            "req.params",
            "req.headers",
            "req.cookies",
            "window.location",
            "document.URL",
            "localStorage.getItem",
            "sessionStorage.getItem",
        ],
        sinks={
            "eval": "critical",
            "innerHTML": "high",
            "outerHTML": "high",
            "insertAdjacentHTML": "high",
            "document.write": "high",
            "Function": "critical",
        },
        sanitizers=[
            "DOMPurify.sanitize",
            "escape",
            "encodeURI",
            "encodeURIComponent",
        ],
    )


def _default_java_config() -> LanguageAnalysisConfig:
    """Return default analysis config for Java/Spring."""
    return LanguageAnalysisConfig(
        language="java",
        sources=[
            "getParameter",
            "getParameterValues",
            "getParameterMap",
            "getQueryString",
            "getHeader",
            "getCookies",
            "javax.servlet.http.HttpServletRequest",
            "jakarta.servlet.http.HttpServletRequest",
            "@RequestParam",
            "@PathVariable",
            "@RequestHeader",
            "@CookieValue",
            "@RequestBody",
            "@ModelAttribute",
        ],
        sinks={
            # OS command injection
            "exec": "critical",
            "Runtime.exec": "critical",
            "ProcessBuilder": "critical",
            "ProcessBuilder.start": "critical",
            # Code injection / reflection
            "Method.invoke": "high",
            "Class.forName": "medium",
            # SQL injection (JDBC)
            "Statement.executeQuery": "high",
            "Statement.executeUpdate": "high",
            "Statement.execute": "high",
            "PreparedStatement.executeQuery": "high",
            "PreparedStatement.executeUpdate": "high",
            "PreparedStatement.execute": "high",
            # JNDI injection
            "InitialContext.lookup": "critical",
            "Context.lookup": "critical",
            # File I/O (path traversal)
            "FileInputStream": "medium",
            "FileOutputStream": "medium",
            "FileReader": "medium",
            "FileWriter": "medium",
            "RandomAccessFile": "medium",
            "Files.readAllBytes": "medium",
            "Files.newInputStream": "medium",
            # Deserialization
            "ObjectInputStream.readObject": "high",
            "ObjectInputStream.readUnshared": "high",
            # SSRF
            "HttpURLConnection.connect": "high",
            "URL.openConnection": "high",
            "URL.openStream": "high",
            "HttpClient.send": "high",
            "RestTemplate.exchange": "high",
            "RestTemplate.postForObject": "high",
            "WebClient.retrieve": "high",
            # JNDI
            "InitialContext.lookup": "critical",
            # Log injection
            "log.info": "low",
            "Logger.info": "low",
            # XXE
            "DocumentBuilder.parse": "high",
            "SAXParser.parse": "high",
            "SAXBuilder.build": "high",
        },
        sanitizers=[
            "HtmlUtils.htmlEscape",
            "StringEscapeUtils.escapeHtml",
            "Encoder.encodeForHTML",
            "Encoder.encodeForSQL",
            "ESAPI.encoder",
            "Pattern.quote",
        ],
    )


def build_default_config() -> AnalysisConfig:
    """Build the default analysis configuration with all language configs."""
    config = AnalysisConfig()
    py = _default_python_config()
    config.languages[py.language] = py
    js = _default_js_config()
    config.languages[js.language] = js
    java = _default_java_config()
    config.languages[java.language] = java
    return config


def merge_configs(base: AnalysisConfig, override: AnalysisConfig) -> AnalysisConfig:
    """Merge an override config into a base config (override wins)."""
    merged = base.model_copy(deep=True)
    for lang, lang_cfg in override.languages.items():
        if lang in merged.languages:
            existing = merged.languages[lang]
            if lang_cfg.sources:
                existing.sources = list(set(existing.sources + lang_cfg.sources))
            existing.sinks.update(lang_cfg.sinks)
            if lang_cfg.sanitizers:
                existing.sanitizers = list(set(existing.sanitizers + lang_cfg.sanitizers))
        else:
            merged.languages[lang] = lang_cfg.model_copy(deep=True)
    if override.max_call_depth != 3:
        merged.max_call_depth = override.max_call_depth
    if override.max_taint_paths != 100:
        merged.max_taint_paths = override.max_taint_paths
    return merged
