"""Language adaptation layer for the v3 pipeline.

Detects the project's dominant language and provides instructions
to adapt Python-centric prompts to other languages (Java, JS/TS, etc.).

Zero changes to the prompt templates — the adaptation is injected
transparently in ``_call_llm()`` before the prompt reaches the LLM.
"""

from __future__ import annotations

import os

# Extension → language key
_EXT_TO_LANG: dict[str, str] = {
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
}

# Directories always skipped when walking for language detection
_EXCLUDED = frozenset({
    ".git", "__pycache__", "node_modules", "venv", ".venv",
    "dist", "build", ".tox", ".eggs", "egg-info",
    ".mypy_cache", ".pytest_cache",
})

LANGUAGE_ADAPTATIONS: dict[str, dict[str, str]] = {
    "java": {
        "label": "Java",
        "adaptation": (
            "NOTE: This project is written in Java, not Python.\n"
            "The security analysis below references Python APIs and patterns.\n"
            "Translate them to Java equivalents when analyzing the code.\n"
            "\n"
            "Python → Java mapping:\n"
            "- exec/eval → Runtime.exec(), ScriptEngine.eval()\n"
            "- os.path.join / posixpath.join → Paths.get(), new File(parent, child)\n"
            "- open() / io.open → FileInputStream, FileReader, Files.newInputStream()\n"
            "- pickle.loads / joblib → ObjectInputStream.readObject(), deserialization\n"
            "- subprocess.* / os.system → ProcessBuilder, Runtime.getRuntime().exec()\n"
            "- requests.get / urllib → HttpURLConnection, java.net.http.HttpClient\n"
            "- shutil.copy / shutil.copytree → Files.copy()\n"
            "- A \"def\" defines a method, not a function\n"
            "- File paths use getPath(), toString(), or Paths.get()\n"
            "- URL connections: HttpURLConnection follows redirects by default (setFollowRedirects)\n"
            "- String concatenation with + works like Python\n"
            "- Variable declarations include types: String x, int y\n"
            "\n"
            "Focus on Java-specific security concerns:\n"
            "- ObjectInputStream.readObject() (deserialization RCE)\n"
            "- DocumentBuilderFactory with XXE-unsafe defaults\n"
            "- JDBC Statement vs PreparedStatement (SQL injection)\n"
            "- ProcessBuilder / Runtime.exec() (command injection)\n"
            "- HttpURLConnection / HttpClient to internal hosts (SSRF)\n"
            "- File.getCanonicalPath() vs getAbsolutePath() (path traversal)\n"
            "- ZipEntry.getName() path traversal in extract operations"
        ),
    },
    "javascript": {
        "label": "JavaScript/TypeScript",
        "adaptation": (
            "NOTE: This project is written in JavaScript or TypeScript, not Python.\n"
            "The security analysis below references Python APIs and patterns.\n"
            "Translate them to JavaScript/TypeScript equivalents.\n"
            "\n"
            "Python → JS/TS mapping:\n"
            "- exec/eval → eval(), Function(), child_process.exec()/execSync()\n"
            "- os.path.join / posixpath.join → path.join(), path.resolve()\n"
            "- open() → fs.readFile(), fs.createReadStream()\n"
            "- pickle.loads → JSON.parse() (safe), or vm.runInThisContext() (dangerous)\n"
            "- subprocess.* / os.system → child_process.exec(), spawn(), execSync()\n"
            "- requests.get / urllib → fetch(), axios.get(), node-fetch, http.get()\n"
            "- import / require → require() (can load arbitrary files!)\n"
            "- print() / logging → console.log(), util.debuglog()\n"
            "- A \"def\" defines a function via function foo() or const foo = ()=>...\n"
            "- File paths use path.join(), path.resolve(), path.normalize()\n"
            "- Template literals: `hello ${name}` (like f-strings, also SQL injection risk)\n"
            "- Objects/dicts: JSON.parse() for deserialization\n"
            "- Asynchronous: async/await, Promises, callbacks\n"
            "\n"
            "Focus on JS/TS-specific security concerns:\n"
            "- Prototype pollution (Object.assign, merge, spread operator)\n"
            "- require() with user input (module loading RCE)\n"
            "- eval() / Function() constructor / vm.runInThisContext()\n"
            "- child_process.exec() (shell injection vs spawn array form)\n"
            "- NoSQL injection with MongoDB ($where, $ne operators)\n"
            "- SSRF via fetch(), axios.get(), http.request()\n"
            "- Path traversal in fs.readFile(), fs.createReadStream()\n"
            "- Regular expression DoS (ReDoS) with vulnerable patterns\n"
            "- Knex.js uses parameterized queries (safe), but .raw() may not\n"
            "- Template injection in EJS, Pug, Handlebars (SSTI)"
        ),
    },
}


def detect_project_language(project_path: str) -> str:
    """Walk *project_path* and return the dominant non-Python language.

    Returns ``"python"`` if:
    - No non-Python source files are found, OR
    - Python files outnumber all other supported languages.

    Returns ``"java"`` if Java files are the majority.
    Returns ``"javascript"`` if JS/TS files are the majority.
    """
    counts: dict[str, int] = {}
    py_count = 0
    total_lang_files = 0

    for root, dirs, fnames in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED]
        for fname in fnames:
            ext = os.path.splitext(fname)[1].lower()
            lang = _EXT_TO_LANG.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
                total_lang_files += 1
            elif ext == ".py":
                py_count += 1

    # Threshold: need at least 5 non-Python files to switch
    if total_lang_files < 5:
        return "python"

    # If python still dominates (>50%), stay with python
    if py_count > total_lang_files:
        return "python"

    # Pick the dominant non-Python language
    best_lang = max(counts, key=counts.get)  # type: ignore[arg-type]
    return best_lang


def get_adaptation(language: str) -> str:
    """Return the language adaptation instruction block for *language*.

    Returns empty string for Python (no adaptation needed).
    """
    entry = LANGUAGE_ADAPTATIONS.get(language)
    if entry is None:
        return ""
    return entry["adaptation"]


def get_label(language: str) -> str:
    """Return a human-readable label for *language*."""
    entry = LANGUAGE_ADAPTATIONS.get(language)
    if entry is None:
        return language.capitalize()
    return entry["label"]
