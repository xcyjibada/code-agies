"""语言底层/标准库不安全行为指南（Cheat Sheet）

在 Logic Agent 的 Prompt 生成阶段，根据当前审计切片的 vuln_type 动态注入。
不包含任何项目特定的 Hack — 写进去的全是 Python 语言标准库和常见不安全 API
的物理运行特性。
"""

VULN_TYPE_GUIDES: dict[str, list[str]] = {
    # ==========================================
    # 1. RCE (Remote Code Execution) - 任意代码执行
    # ==========================================
    "RCE": [
        "- **Unsafe Deserialization (pickle/joblib/shelve/marshal)**: `pickle.loads()`, `pickle.load()`, and `joblib.load()` are fundamentally insecure. During deserialization, Python will automatically execute arbitrary code defined in the pickled object's `__reduce__` or `__setstate__` methods. No sanitization can secure this; if the input stream or file path is attacker-controlled, RCE is guaranteed.",
        "- **Command Injection (subprocess with shell=True)**: When using `subprocess.Popen`, `subprocess.run`, or `subprocess.call` with `shell=True`, Python executes the command through the system shell (e.g., `/bin/sh`). If any part of the command string is constructed using f-string interpolation or concatenation of untrusted input, attackers can escape the intended command using shell metacharacters like `;`, `&&`, `|`, `` ` ``, or `$()`. If `shell=False` is used and the args are passed as a list, command injection is prevented, but argument injection may still be possible.",
        "- **Dangerous Evaluating Functions (eval/exec/compile)**: `eval()` and `exec()` execute arbitrary Python code strings directly. Note that `compile(source, filename, 'exec', ast.PyCF_ONLY_AST)` ONLY parses the AST and does NOT execute the code; however, if the resulting AST is later passed to `exec()`, or if `eval`/`exec` is called on the raw source, RCE is achieved.",
        "- **Unsafe YAML Loading (PyYAML)**: `yaml.load()` with the default loader is vulnerable because it can instantiate arbitrary Python classes via custom tags (e.g., `!!python/object/apply`). Only `yaml.safe_load()` or using the `SafeLoader` is secure.",
    ],

    # ==========================================
    # 2. LFI (Local File Inclusion / Path Traversal) - 任意文件读取与路径穿越
    # ==========================================
    "LFI": [
        "- **Absolute Path Truncation (os.path.join)**: In Python, `os.path.join(base_dir, user_input)` has a dangerous built-in behavior: if `user_input` is an absolute path (e.g., `/etc/passwd` or `C:\\Windows\\win.ini`), `os.path.join` will **completely discard** the `base_dir` and return the absolute path directly. If the application does not explicitly check `os.path.isabs(user_input)` before joining, any prefix/directory restriction is completely bypassed.",
        "- **Symlink Validation Failure (os.path.abspath)**: `os.path.abspath(path)` and `pathlib.Path(path).absolute()` normalize relative paths (resolving `../`) but do **NOT** resolve symbolic links (symlinks) on disk. If the application checks that `abspath(path)` starts with an allowed directory, an attacker can upload/create a symlink inside the allowed directory pointing to a sensitive file (e.g., `/etc/passwd`). The validation will pass because the symlink's own path is inside the allowed directory, but `open()` will follow the symlink and serve the target file. To prevent this, `os.path.realpath()` must be used to resolve symlinks before validation.",
        "- **Directory Copy Traversal (shutil.copytree)**: `shutil.copytree(src, dst)` does not sanitize `src`. If an attacker can control `src` with path traversal sequences, it will copy arbitrary directories from the host filesystem into the destination directory.",
    ],

    # ==========================================
    # 3. SSRF (Server-Side Request Forgery) - 服务端请求伪造
    # ==========================================
    "SSRF": [
        "- **Default Redirect Following**: Python's `requests` library (e.g., `requests.get`, `requests.post`) and `urllib.request.urlopen` follow HTTP redirects (301, 302) by default. Even if the application validates that the initial URL points to a safe public IP or host, an attacker-controlled server can return a redirect pointing to an internal IP (e.g., `http://127.0.0.1:8080`, `http://169.254.169.254/latest/meta-data/`). The HTTP client will fetch the redirect target without re-validating the host, bypassing the SSRF defense. Redirects must be explicitly disabled (`allow_redirects=False` for requests).",
        "- **Missing IP/Host Allowlisting**: Simply checking URL syntax via `urllib.parse.urlparse` or verifying that the URL is 'valid' does not prevent SSRF. A secure validation must resolve the hostname to its IP address and explicitly block private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and cloud link-local metadata IPs (`169.254.169.254`).",
        "- **Parser Differentials**: Different libraries parse URLs differently. A host validation check using `urllib.parse` might approve a URL, but the actual HTTP client (like `yarl`/`aiohttp` or `requests`/`urllib3`) might parse it differently (e.g., treating backslashes `\\` differently), leading to allowlist bypasses like `https://trusted.com@attacker.com`.",
    ],

    # ==========================================
    # 4. SQLI (SQL Injection) - SQL 注入
    # ==========================================
    "SQLI": [
        "- **Raw String Formatting (f-strings/format)**: Constructing SQL queries using f-strings, string concatenation, or `.format()` (e.g., `f\"SELECT * FROM users WHERE name = '{user_input}'\"`) leads directly to SQL injection. All inputs must be parameterized using database driver placeholders (e.g., `%s`, `?`, or `:param`).",
        "- **Identifier Escaping vs. Raw formatting**: Standard parameterized queries only work for column **values**, not column **names** or table names. If column/table names are dynamic, developers often use raw string interpolation. This is unsafe unless they explicitly use libraries like `psycopg2.sql.Identifier` to safely quote and escape identifiers. If they use raw formatting on user-controlled identifiers, SQL injection is possible.",
    ],

    # ==========================================
    # 5. XXE (XML External Entity Expansion) - XML 外部实体注入
    # ==========================================
    "XXE": [
        "- **Python Standard Library Parsers (xml.etree / xml.dom.minidom)**: Python's standard library XML parsers are secure against XXE by default. They do not resolve external entities (though they may still be vulnerable to Entity Expansion DoS / Billion Laughs).",
        "- **lxml Parser (Highly Vulnerable by Default)**: The `lxml.etree` module (and `from lxml import etree`) **enables external entity resolution by default** when using `etree.parse()` or `etree.fromstring()`. If an attacker can control the XML content parsed by `lxml`, they can read arbitrary local files or trigger SSRF. To secure `lxml`, developers must explicitly create a custom `XMLParser(resolve_entities=False)` and pass it to the parsing function.",
    ],

    # ==========================================
    # 6. AFO (Arbitrary File Overwrite) - 任意文件写入/覆盖
    # ==========================================
    "AFO": [
        "- **Path Traversal in Writes**: If `open(filepath, 'w')` or `open(filepath, 'wb')` is called with a path constructed from user input without sanitization, an attacker can use path traversal (`../`) to write or overwrite arbitrary files on the filesystem. This can lead to RCE if the attacker overwrites critical system files (e.g., `/etc/cron.d/malicious`, `~/.bashrc`, or application source code).",
    ],

    # ==========================================
    # 7. REDOS (Regular Expression Denial of Service) - 正则拒绝服务
    # ==========================================
    "REDOS": [
        "- **Catastrophic Backtracking Conditions**: ReDoS only occurs if the regex pattern contains vulnerable constructs such as nested quantifiers (e.g., `(a+)+`), overlapping alternations (e.g., `(a|b|a)+`), or greedy wildcards near string boundaries. If the regex is a simple character class without quantifiers (e.g., `[^a-zA-Z0-9_]` used for sanitization) or a strictly linear pattern (e.g., `^[0-9]+_`), its evaluation complexity is strictly linear $O(n)$ relative to the input length, making catastrophic backtracking impossible.",
    ],
}


def get_stdlib_guide(vuln_type: str) -> str:
    """获取指定漏洞类型的通用行为指南"""
    guides = VULN_TYPE_GUIDES.get(vuln_type.upper(), [])
    if not guides:
        return ""

    return "\n".join([
        "# ── [LANGUAGE STDLIB BEHAVIOR GUIDELINES] ──",
        "When auditing the implementation logic, you MUST evaluate these strict language-level behaviors:",
        *guides,
        "# ── ── ── ── ──\n",
    ])
