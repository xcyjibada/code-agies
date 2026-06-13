agies — auditing /tmp/bounty_test/werkzeug-3.0.1

  Languages: JavaScript, Python
  Files: 295


Phase A: Path Discovery
  Backend: tree-sitter
  Functions: 1306
    Remote Code Execution: 13 sink(s)
    Local File Inclusion: 17 sink(s)
    Server-Side Request Forgery: 1 sink(s)
    SQL Injection: 7 sink(s)
    ReDoS (Regular Expression DoS): 21 sink(s)
    Server-Side Template Injection (SSTI) — template engine with user input: 2 
sink(s)
    Suspicious — requires analysis (path constructor / logic pattern): 15 
sink(s)

Phase B: Slice Sorting (76 raw paths)
  Body-detected orphans: 19 (no call chain)
  Exploit: 30 + Explore: 15
    Explore: lfi-000 add_file score=0.59 (non_std_sink, unusual_naming)
    Explore: redos-001 regex_repr score=0.58 (non_std_sink, unusual_naming)
    Explore: redos-002 render_debugger_html score=0.55 (non_std_sink, 
unusual_naming)
  Project type: app

Phase C: README Understanding
  README: 2000 chars
  Summary: ```json
{
  "project_type": "WSGI web application library — a low-level toolkit for 
building Python web apps, not a stan...
  Token budget: 1,000,000 tokens

Phase D: Intent+Logic Agents (45 slices)
  [1/45] lfi-000 (open)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims LFI via path traversal, but the code path does 
not contain any file read sink. The chain ends at `open` in test.py, which only 
constructs WSGI environ and calls the application; it does not read files from 
the filesystem. The only file-related operation is `start_file_streaming` which 
creates temporary files for uploads, not reading existing files. No 
user-controlled data reaches a filesystem read operation. The vulnerability is 
not exploitable.
    ? pattern match, LLM skeptical (2 match(es))
  [2/45] rce-001 (eval)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The debugger endpoint accepts user input and passes it 
directly to eval() without authentication or input validation. The developer's 
intent to restrict usage to development is not enforced in code, making the 
vulnerability exploitable if the debugger is enabled.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/rce_python_code_execution_eva
l_eval.py
    ✓ evidence found (3 match(es))
      PoC: POST /console HTTP/1.1
Content-Type: application/x-www-form-urlencoded

command=__import__('os').system('id')...
  [3/45] redos-002 (compile)
    ✓ 0/10 — safe
  [4/45] sqli-003 (execute)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The code path does not contain any SQL queries or database 
interactions. The 'execute' function calls the WSGI application, which is 
user-provided and may execute arbitrary code, but the code path itself does not 
involve SQL. Therefore, no SQL injection vulnerability exists in this code path.
    ? pattern match, LLM skeptical (4 match(es))
  [5/45] ssrf-004 (fetch)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims SSRF via user-controlled URLs passed to HTTP 
clients, but the code path does not make any outbound HTTP requests. The sink 
function 'fetch' in ThreadedStream (console.py:70) only reads from a 
thread-local stream and returns its content. No URL, HTTP client, or network 
endpoint is involved. The path involves an interactive debugger console that 
executes arbitrary Python code (RCE), but that is unrelated to SSRF. The data 
flow annotations confirm no HTTP request is made. Therefore, the vulnerability 
is not exploitable as SSRF.
  [6/45] ssti-005 (get_rules)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims SSTI, but the analyzed code path contains no 
template rendering. The call chain includes server startup, reloader logic, and 
routing internals (e.g., `get_rules` is an abstract method returning rule 
objects, not rendered templates). No call to any template engine (Jinja2, Mako, 
etc.) or function like `render_template_string` exists. The debugger is a 
separate concern and not SSTI. The developer warnings about production use are 
accurate. No SSTI vulnerability exists in this code path.
  [7/45] suspicious-006 (secure_filename)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/none_windows_prepending_under
score_reserved_secure_filename.py
  [8/45] rce-007 (restart_with_reloader)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The sink `restart_with_reloader` calls `subprocess.call` with 
arguments from `_get_args_for_reloading()`, which returns `[sys.executable] + 
sys.argv[1:]`. These values are set at process start and are not influenced by 
HTTP requests. The reloader is triggered by file system events or explicit 
restart, not by user input. No untrusted data reaches the sink. The debugger's 
interactive console (evalex) is a separate RCE vector but is not in this code 
path.
    ? pattern match, LLM skeptical (1 match(es))
  [9/45] rce-008 (__init__)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims RCE via unsafe deserialization or command 
execution, but the code path immediately raises a TypeError at the entry 
function 'fromkeys' (line 681 in structures.py), preventing any user input from 
reaching the sink '__init__' in ClosingIterator. The sink itself only wraps an 
iterable and manages callbacks, with no execution of user-controlled code (no 
eval, exec, subprocess, etc.). There is no data flow from untrusted input to any
dangerous function. The static analysis annotations confirm no traceable 
propagation. Therefore, the vulnerability is not exploitable.
  [10/45] rce-009 (runcode)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The finding is straightforward: exec() is called on 
user-supplied code without authentication or input validation. The debugger 
endpoint is accessible if enabled, and there is no access control. This is a 
classic RCE vulnerability.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/rce_python_code_exec_code_run
code.py
    ✓ evidence found (2 match(es))
      PoC: POST /console HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

__import__('os').system('id')...
  [11/45] rce-010 (_get_func_code)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The finding relies on the assumption that an attacker can 
control the URL rule definition, which is typically set by the developer. 
However, if dynamic route registration from user input is possible (e.g., via a 
misconfigured framework), the code path is exploitable. The sink is `exec` on 
dynamically generated code without sanitization.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/rce_ast_code_using_compile__g
et_func_code.py
    ? pattern match, LLM skeptical (5 match(es))
  [12/45] sqli-011 (_get_args_for_reloading)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims SQL injection, but the code path involves no 
SQL queries. The sink is subprocess.call with arguments derived from sys.argv 
and sys.executable, which are not user-controllable. No database interaction 
exists in the call chain.
    ? pattern match, LLM skeptical (1 match(es))
  [13/45] rce-012 (bind)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [14/45] rce-013 (_compile_builder)
    ⚠ 9/10 — 1 contradiction(s)
    ✗ rebutted
      reason: The finding claims that user-controlled URL pattern parts can 
reach `_compile_builder` via `self._trace`. However, `self._trace` is built from
the URL rule string passed to the `Rule` constructor, which is defined by the 
application developer, not by user input. The `Rule` class is used to define URL
patterns statically in the application code (e.g., `Rule('/user/<int:id>')`). 
There is no mechanism for an attacker to control the rule string at runtime. The
`_compile_builder` method is called during `compile()` (line 681), which is 
invoked when the `Rule` is initialized, not on every request. Therefore, the 
attacker cannot inject arbitrary code through URL parameters or request data. 
The data flow annotations do not show any path from user input to `self._trace`.
The finding is based on a misunderstanding of how Werkzeug routing works.
    ? pattern match, LLM skeptical (4 match(es))
  [15/45] redos-014 (__init__)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims a ReDoS vulnerability, but the code path 
contains no regex operations. The entry function 'fromkeys' immediately raises a
TypeError (line 681), preventing any further execution. The sink function 
'__init__' in ClosingIterator only handles iterables and callbacks, with no 
regex matching. No regex pattern is ever compiled or executed, so ReDoS is not 
applicable.
  [16/45] sqli-015 (run_wsgi)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/sqli_sql_queries_database_int
eractions_run_wsgi.py
    ? pattern match, LLM skeptical (3 match(es))
  [17/45] sqli-016 (from_app)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/sqli_code_does_contain_any_fr
om_app.py
    ? pattern match, LLM skeptical (2 match(es))
  [18/45] sqli-017 (addInfoPrompt)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/sqli_javascript_debugger_fron
tend_addInfoPrompt.py
    ? pattern match, LLM skeptical (1 match(es))
  [19/45] rce-018 (eval)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The debugger endpoint is accessible without authentication, 
and the code path from HTTP request to eval() is direct and unguarded. The 
developer intent (empty) does not mitigate the risk; the project context warning
against production use does not prevent accidental exposure. Real-world CVEs 
exist for similar debugger RCE vulnerabilities.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/rce_python_code_execution_eva
l_eval_2.py
    ✓ evidence found (3 match(es))
      PoC: POST /console HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

command=__import__('os').system('id')...
  [20/45] rce-019 (eval)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The debugger's HTTP endpoint directly passes user-supplied 
code to eval() without authentication or input validation. The code path is 
clear and unguarded. Although the debugger is intended for development only, if 
accidentally enabled in production, it allows unauthenticated RCE. This is a 
real vulnerability with practical exploitability.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/rce_python_code_execution_eva
l_eval_3.py
    ✓ evidence found (3 match(es))
      PoC: POST /console HTTP/1.1
Host: target:port
Content-Type: application/x-www-form-urlencoded

code=__import__('os').system('id')...
  [21/45] sqli-020 (run_wsgi_app)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The code path does not contain any SQL query execution. The sink 
function 'run_wsgi_app' only calls the WSGI application and does not interact 
with a database. No SQL injection vulnerability exists.
  [22/45] lfi-021 (put)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The sink function 'put' in werkzeug/test.py is a test utility that
constructs an HTTP PUT request; it does not perform any file I/O or path 
construction. The path argument '/{id}/' is a CouchDB document ID, not a 
filesystem path. No user-controlled data reaches a filesystem read/write 
operation. The code path is for a URL shortener example using CouchDB, not for 
file access. Additionally, the alias input is validated (max 140 chars, no 
slash, uniqueness check), preventing path traversal even if the sink were 
file-related.
    ? pattern match, LLM skeptical (3 match(es))
  [23/45] lfi-022 (make_ssl_devcert)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The function is a public API with no input validation, and the
data flow from base_path to open() is direct and unmitigated. Path traversal via
'..' is straightforward. The developer's assumption of safe usage does not 
prevent exploitation when untrusted callers invoke the function.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_ssl_development_certifica
tes_given_make_ssl_devcert.py
    ✓ evidence found (2 match(es))
      PoC: make_ssl_devcert('../../../tmp/evil', host='example.com') writes to 
../../../tmp/evil.crt and ../../../tmp/evil.key...
  [24/45] lfi-023 (__init__)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding is not exploitable because the entry function 
'fromkeys' immediately raises a TypeError (line 681), preventing any data flow 
to the sink. The sink function '__init__' in ClosingIterator (line 233) does not
perform any file path operations; it only wraps an iterable and manages 
callbacks. No path traversal vulnerability exists.
  [25/45] redos-024 (_make_unquote_part)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/redos_nested_quantifiers_over
lapping_alternations__make_unquote_part.py
    ? pattern match, LLM skeptical (1 match(es))
  [26/45] lfi-025 (_opener)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code in _opener 
directly opens the filename without any path sanitization, and the filename 
originates from user-controlled input via URL path mapping. The absence of 
validation like os.path.realpath or directory checks makes path traversal 
feasible.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_url_mapping__opener.py
    ? pattern match, LLM skeptical (1 match(es))
  [27/45] redos-026 (match)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims ReDoS via user-controlled regex, but the regex 
patterns are compiled from developer-defined URL rules (self.rule, self.host, 
self.subdomain) in Rule.compile() (rules.py:681). User input (URL path) is 
matched against these precompiled regexes in matcher.py:69 via 
re.compile(test_part.content).match(target). Since the regex itself is not 
user-controllable, ReDoS is not feasible. The data flow trace shows no path from
user input to the regex pattern; the sink parameter test_part.content originates
from rule definitions, not HTTP requests.
    ? pattern match, LLM skeptical (7 match(es))
  [28/45] redos-027 (_match)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The regex patterns are compiled from developer-defined URL rules, 
not from user input. The sink `re.compile(test_part.content)` in `matcher.py:79`
uses `test_part.content` which originates from `RulePart.content` set during 
rule compilation in `rules.py`. User-controlled URL path is matched against 
these fixed patterns, but the patterns themselves are not user-controllable. 
Therefore, no ReDoS vulnerability exists.
    ? pattern match, LLM skeptical (8 match(es))
  [29/45] lfi-028 (post)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [30/45] lfi-029 (delete)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_http_method_delete_delega
tes_delete.py
    ? pattern match, LLM skeptical (1 match(es))
  [31/45] lfi-000 (add_file)
    ⚠ 10/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code directly 
opens a file from user-controlled input without any path sanitization, and the 
entry point is reachable via HTTP request parsing in EnvironBuilder.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_environbuilder_constructi
on_supplied_data_add_file.py
    ✓ evidence found (1 match(es))
      PoC: Send a multipart POST request to an endpoint that uses 
`EnvironBuilder` (e.g., test client) with a file field where the filename is 
`../../etc/passwd`...
  [32/45] redos-001 (regex_repr)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [33/45] redos-002 (render_debugger_html)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The regex pattern '-{2,}' is hardcoded and not user-controllable. 
It is a simple quantifier with no nested quantifiers or alternations, making it 
linear in complexity and immune to ReDoS. The input 'plaintext' is derived from 
exception traceback, which is not user-controlled. Even if an attacker could 
influence the exception message, the regex is safe. No exploitability.
    ? pattern match, LLM skeptical (1 match(es))
  [34/45] suspicious-003 (iter_sys_path)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding is not exploitable because the sink function 
`iter_sys_path` uses `sys.path`, which is a list of directories set by the 
Python interpreter at startup and is not influenced by any user input. The 
`test_app` function only accesses `req.environ` for display purposes and does 
not pass any user-controlled data to `iter_sys_path`. There is no data flow from
untrusted sources to the path construction. The static analysis annotations 
confirm no taint propagation to the sink.
  [35/45] suspicious-004 (send_from_directory)
    ⚠ 9/10 — 1 contradiction(s)
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_if_control_root_send_from
_directory.py
  [36/45] suspicious-005 (create_app)
    ? 10/10 — interesting
    ⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/none_flask_like_application_s
etup_create_app.py
  [37/45] lfi-006 (patch)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [38/45] lfi-007 (options)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [39/45] lfi-008 (head)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [40/45] lfi-009 (trace)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [41/45] lfi-010 (save)
    ⚠ 9/10 — 1 contradiction(s)
    ✓ not rebutted
      weak point: The function is a public API (save) that directly uses the dst
parameter in open() without any path validation. The docstring mentions 
secure_filename but does not enforce it, creating a contradiction. An attacker 
controlling dst (e.g., via file upload) can perform path traversal. The data 
flow is clear: dst enters as parameter and reaches open sink.
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/werkzeug-3.0.1/lfi_if_control_dst_save.py
    ✓ evidence found (1 match(es))
      PoC: Assuming a Flask endpoint that uses FileStorage.save() with 
user-controlled filename:

```python
from flask import Flask, request
from werkzeug.datast...
  [42/45] redos-011 (parse_dict_header)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The regex `_charset_value_re` is compiled at module load time and 
is not user-controllable. The pattern `(?P<charset>[^\s]+)''(?P<language>[^']*)`
contains no nested quantifiers or overlapping alternations, making it safe from 
ReDoS. User input is only the header value, which is split and stripped; the 
regex is applied only to the value part after '=' when the key ends with '*'. No
user-controlled regex is used. The finding incorrectly claims a ReDoS 
vulnerability where none exists.
    ? pattern match, LLM skeptical (1 match(es))
  [43/45] redos-012 (get_machine_id)
    ✓ 0/10 — safe
    ? pattern match, LLM skeptical (1 match(es))
  [44/45] redos-013 (parse_etags)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims a ReDoS vulnerability in parse_etags, but the 
regex _etag_re is a fixed constant pattern defined in the source code (not 
user-controllable). ReDoS requires attacker control over the regex pattern, not 
the input string. The input string (HTTP_IF_MATCH header) is user-controlled, 
but the regex is simple and does not contain nested quantifiers or overlapping 
alternations that could cause catastrophic backtracking. The regex is designed 
to match ETag values and is safe. No ReDoS vulnerability exists.
    ? pattern match, LLM skeptical (1 match(es))
  [45/45] redos-014 (dump_cookie)
    ? 10/10 — interesting
    ✗ rebutted
      reason: The finding claims a ReDoS vulnerability in dump_cookie, but the 
regex _cookie_no_quote_re is a fixed, simple pattern without nested quantifiers 
or overlapping alternations. User input is the string being matched, not the 
regex pattern itself. No ReDoS exists. See werkzeug/http.py line 1207: the regex
is not user-controllable.
    ? pattern match, LLM skeptical (2 match(es))

Phase E: Results
  Blackboard: 26 cached intents, 183 knowledge entries, 42 phase results
  High confidence (44):
    lfi-000: ? — ?
      
    rce-001: eval — logic_gap
      POST /console HTTP/1.1 with body: __import__('os').system('id')
    sqli-003: ? — ?
      
    rce-007: ? — ?
      
    rce-009: exec — logic_gap
      POST /console HTTP/1.1\r\n...\r\n__import__('os').system('id')
    rce-010: exec — logic_gap
      
    sqli-011: ? — ?
      
    rce-012: ? — ?
      
    rce-013: compile — logic_gap
      If the application allows user-defined URL rules (e.g., via a config or 
database), an attacker can set a rule like '<__import__("os").system("id")>' to 
execute arbitrary commands.
    sqli-015: ? — ?
      
    sqli-016: ? — ?
      
    sqli-017: ? — ?
      
    rce-018: eval — logic_gap
      Send a POST request to the debugger console endpoint with code parameter: 
__import__('os').system('id')
    rce-019: eval — logic_gap
      Send a POST request to the debugger console endpoint with code parameter 
set to: __import__('os').system('id')
    lfi-021: ? — ?
      
    lfi-022: open — logic_gap
      make_ssl_devcert('../../../tmp/evil', host='example.com') writes to 
../../../tmp/evil.crt and ../../../tmp/evil.key
    redos-024: ? — ?
      
    lfi-025: open — logic_gap
      ../../etc/passwd
    redos-026: ? — ?
      
    redos-027: ? — ?
      
    lfi-028: ? — ?
      
    lfi-029: ? — ?
      
    lfi-000: open — logic_gap
      Send a multipart POST request with a file field where the filename is 
'../../etc/passwd'. The server will open and include that file.
    redos-001: ? — ?
      
    redos-002: ? — ?
      
    suspicious-004: send_from_directory — logic_gap
      If an attacker can control the `_root_path` parameter (e.g., via a Flask 
route that passes user input as `_root_path`), they can set it to `../../../etc`
to read arbitrary files. For example, calling `send_from_directory('/safe/dir', 
'file.txt', _root_path='../../../etc')` would result in the path 
`/safe/dir/../../../etc/file.txt`, which resolves to `/etc/file.txt`.
    lfi-006: ? — ?
      
    lfi-007: ? — ?
      
    lfi-008: ? — ?
      
    lfi-009: ? — ?
      
    lfi-010: open — logic_gap
      If an attacker can control the dst parameter, they can set it to 
'../../tmp/evil.txt' to write outside the intended directory.
    redos-011: ? — ?
      
    redos-012: ? — ?
      
    redos-013: ? — ?
      
    redos-014: ? — ?
      

Pipeline Complete
  Target: /tmp/bounty_test/werkzeug-3.0.1
  Model: deepseek-chat
  Duration: 959.7s
  Paths discovered: 76
  Slices analyzed: 45
  Findings: 44 high, 0 interesting
  Tokens: 546,880 total (472,114 prompt + 74,766 completion)

  Recommended verification targets:
    LFI lfi-000: Code-level pattern evidence (2 matches): ?:return 
self.open(*args, **kw); ?:# ── Call Chain [8] [sin
    RCE rce-001: The data flow starts at the HTTP endpoint that calls 
`execute_command` with user-supplied `command`.
    SQLI sqli-003: Code-level pattern evidence (4 matches): ?:def execute(app: 
WSGIApplication) -> None:; ?:execute(sel
    SSRF ssrf-004: The code path does not make any outbound HTTP requests. The 
sink function 'fetch' only reads from a 
    SSTI ssti-005: No template rendering occurs in the analyzed code path. The 
code path involves a development server 

v3 CodeQL pipeline complete.
