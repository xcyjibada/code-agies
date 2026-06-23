agies — auditing /tmp/langgraph_cli-0.4.30

  Languages: JSON, JavaScript, Python, TypeScript
  Files: 149


Phase A: Path Discovery
  Backend: tree-sitter
  Functions: 273
    Remote Code Execution: 1 sink(s)
    Local File Inclusion: 10 sink(s)
    Server-Side Request Forgery: 4 sink(s)
    ReDoS (Regular Expression DoS): 4 sink(s)
    Suspicious — requires analysis (path constructor / logic pattern): 10 
sink(s)

Phase B: Slice Sorting (29 raw paths)
  Body-detected orphans: 5 (no call chain)
  Exploit: 29 + Explore: 14
    Explore: redos-000 normalize_image_tag score=0.55 (non_std_sink, 
unusual_naming)
    Explore: ssrf-001 _get_pypi_versions score=0.47 (non_std_sink, 
unusual_naming)
    Explore: ssrf-002 __init__ score=0.47  (non_std_sink)
  Project type: app

Phase C: README Understanding
  README: 2000 chars
  Summary: ```json
{
  "project_type": "CLI tool for managing LangGraph applications, providing 
commands to scaffold, develop, buil...

Phase D: Intent+Logic Agents (43 slices)
  [1/43] lfi-000 (validate)
  [2/43] rce-001 (can_build_locally)
  [3/43] redos-002 (_parse_dependency_name)
  [4/43] ssrf-003 (log_data)
  [5/43] suspicious-004 (_validate_uv_lock_source_entry)
  [6/43] lfi-005 (validate_config_file)
  [7/43] redos-006 (_normalize_package_name)
  [8/43] lfi-007 (main)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: lfi-000...
    ? 10/10 — interesting
    Evidence: lfi-007...
    ? 10/10 — interesting
    Evidence: ssrf-003...
    ✓ not rebutted
      weak point: The finding is straightforward: the `validate` function 
directly uses the `config` parameter in `open(config)` without any path 
validation or sanitization. The function is a public API (detected via `__all__`
or module-level definition), making it reachable by external callers. No access 
controls or input validation are present. The data flow is clear and direct, 
with no logical jumps. The vulnerability is authentically exploitable.
    PoC Agent: lfi-000...
    ? pattern match, LLM skeptical (5 match(es))
  [9/43] lfi-008 (dockerfile)
    ✓ 0/10 — safe
    Evidence: rce-001...
    ? pattern match, LLM skeptical (3 match(es))
  [10/43] lfi-009 (_upload_to_gcs)
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: lfi-005...
    ? pattern match, LLM skeptical (8 match(es))
  [11/43] lfi-010 (_read_text)
    ✓ not rebutted
      weak point: The finding is straightforward: user-controlled CLI argument 
flows directly to `open()` without any path validation. No sanitization or 
access control is present. The code is exploitable for arbitrary file read.
    PoC Agent: lfi-005...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_supply_absolute_val
idate.py
    Evidence: lfi-000...
    ? 10/10 — interesting
    Evidence: lfi-008...
    ✓ evidence found (4 match(es))
      PoC: langgraph validate /etc/passwd...
    Verifying lfi-000...
    ? 10/10 — interesting
    Evidence: redos-002...
    ? pattern match, LLM skeptical (8 match(es))
  [12/43] lfi-011 (_get_node_pm_install_cmd)
    ✓ verification confirmed
  [13/43] lfi-012 (_load_pyproject)
    ✓ 1/10 — safe
    Evidence: lfi-009...
    ? pattern match, LLM skeptical (1 match(es))
  [14/43] lfi-013 (get_pkg_manager_name)
    ? 10/10 — interesting
    Evidence: redos-006...
    ? pattern match, LLM skeptical (6 match(es))
  [15/43] redos-014 (normalize_name)
    ? 9/10 — interesting
    Evidence: suspicious-004...
  [16/43] redos-015 (normalize_image_tag)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: lfi-010...
    ? pattern match, LLM skeptical (1 match(es))
  [17/43] ssrf-016 (_get_pypi_versions)
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code uses 
os.path.join without checking for absolute paths, and the attacker can control 
dep_path via config_json['dependencies']. The data flow is clear and no 
sanitization exists.
    PoC Agent: lfi-010...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_cli_arguments_valid
ate_config_file.py
    Evidence: lfi-005...
    ? 10/10 — interesting
    Evidence: redos-014...
    ✓ evidence found (5 match(es))
      PoC: langgraph up --config /etc/passwd...
    Verifying lfi-005...
    ✓ verification confirmed
  [18/43] ssrf-017 (__init__)
    ? 10/10 — interesting
    Evidence: redos-015...
    ? pattern match, LLM skeptical (1 match(es))
  [19/43] suspicious-018 (_download_repo_with_requests)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_resolved_dep_base_f
unction__read_text.py
    Evidence: lfi-010...
    ? pattern match, LLM skeptical (1 match(es))
  [20/43] suspicious-019 (_docker_config_for_token)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: lfi-012...
    ⚠ 8/10 — 1 contradiction(s)
    Adversary: lfi-011...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code in 
`_plan_uv_lock_workspace` (uv_lock.py:623) constructs `project_root = 
(config_root / root).resolve()` where `root` is user-controlled from 
`source.root` in the config file. There is no validation to ensure the resolved 
path stays within an allowed directory. The `resolve()` call only normalizes the
path but does not prevent traversal outside the project root. The resulting 
`pyproject_path` is passed to `_load_pyproject` which opens the file without any
further checks. An attacker can set `source.root` to an absolute path like 
`/etc` or use `../` to read arbitrary files.
    PoC Agent: lfi-012...
    ⚠ 8/10 — 1 contradiction(s)
    Adversary: ssrf-017...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the sink function 
`_get_node_pm_install_cmd` directly uses `project_dir` (derived from 
user-controlled `config_path.parent`) to open `package.json` without any path 
traversal protection. The only guard is an existence check on `config_path`, 
which does not prevent reading arbitrary files via absolute paths or symlinks. 
The data flow from CLI arguments to the sink is clear and unbroken.
    PoC Agent: lfi-011...
    ✓ evidence found (10 match(es))
      PoC: Create a `langgraph.json` with:
```json
{
  "dependencies": ["/etc/passwd"]
}
```
Run `langgraph deploy`. The tool will attempt to read `/etc/passwd/u...
    Verifying lfi-010...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code directly 
passes user-controlled base_url to httpx.Client without any validation, and 
httpx follows redirects by default. The developer intent shows no security 
requirements, and the data flow is clear from CLI input to sink.
    PoC Agent: ssrf-017...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: lfi-013...
    ✓ verification confirmed
  [21/43] suspicious-020 (create_archive)
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: suspicious-018...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code directly uses
user-controlled `config_path.parent` to construct a file path for `open()` 
without any path traversal protection. The validation only checks existence, not
containment, and symlinks are not resolved. This is a classic path traversal 
vulnerability.
    PoC Agent: lfi-013...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: ssrf-016...
    ? 10/10 — interesting
    Evidence: suspicious-019...
  [22/43] suspicious-021 (python_config_to_docker_uv_lock)
    ✓ not rebutted
      weak point: The finding relies on the assumption that the ZIP archive 
could be malicious, either via a compromised repository or MITM attack. While 
the URL is hardcoded, the code does not validate archive entries, making it 
vulnerable if the source is compromised. The lack of entry sanitization in 
ZipFile.extractall() is a known issue.
    PoC Agent: suspicious-018...
    ✗ rebutted
      reason: The SSRF finding is not exploitable because the URL is hardcoded 
to 'https://pypi.org/pypi/langgraph-api/json' and the package_name parameter is 
not user-controllable. The data flow trace shows that user input (config) 
propagates to api_version, but api_version is only used to filter the response, 
not to construct the URL. The function _get_pypi_versions is called with a fixed
string 'langgraph-api'. While httpx follows redirects by default, exploitation 
would require compromising PyPI or performing a MITM attack, which is outside 
the threat model. The lack of redirect disabling is a weakness but does not make
the vulnerability exploitable by an attacker controlling the config.
    Evidence: ssrf-016...
    ? pattern match, LLM skeptical (4 match(es))
  [23/43] suspicious-022 (_uv_lock_package_copy_items)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_get_node_pm_install
__get_node_pm_install_cmd_2.py
    Evidence: lfi-011...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/ssrf_http_client_base_u
rl___init.py
    Evidence: ssrf-017...
    ⚠ 8/10 — 1 contradiction(s)
    Adversary: suspicious-020...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_originates_controll
ed_source__load_pyproject.py
    Evidence: lfi-012...
    ✓ not rebutted
      weak point: The finding is based on a clear data flow from user-controlled
config to _read_text via _assemble_local_deps, where _resolved_dep_base uses 
os.path.join which discards base on absolute paths, enabling path traversal. No 
sanitization is evident in the provided code snippets.
    PoC Agent: suspicious-020...
    ✓ evidence found (4 match(es))
      PoC: ```python
import httpx
from langgraph_cli.host_backend import HostBackend

# Attacker-controlled base_url pointing to cloud metadata endpoint
maliciou...
    Verifying ssrf-017...
    ✓ evidence found (10 match(es))
      PoC: 1. Create a symlink inside the project directory pointing to 
/etc/passwd: `ln -s /etc/passwd package.json`
2. Run: `langgraph up --config /path/to/pro...
    Verifying lfi-011...
    ✓ evidence found (14 match(es))
      PoC: Create a langgraph.json with:
{
  "source": {
    "kind": "uv",
    "root": "/etc/passwd"
  }
}
Then run `langgraph dev` or any command that triggers ...
    Verifying lfi-012...
    ✓ verification confirmed
  [24/43] suspicious-023 (_add_directory)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/afo_zip_archive_url_ext
racts__download_repo_with_requests.py
    Evidence: suspicious-018...
  [25/43] suspicious-024 (_container_workspace_root)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_get_node_pm_install
_get_pkg_manager_name_2.py
    Evidence: lfi-013...
    ✓ verification confirmed
  [26/43] suspicious-025 (iter_entries)
    ⚠ 8/10 — 1 contradiction(s)
    Adversary: suspicious-021...
    ✓ verification confirmed
  [27/43] suspicious-026 (_build_dockerignore_negation_hints)
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code shows a clear
taint path from user-controlled CLI argument `--config` to 
`_get_node_pm_install_cmd` which opens `package.json` from `config_path.parent` 
without path sanitization. The `validate_config_file` only checks existence, not
canonicalization, allowing path traversal. The sink is a path constructor, which
is a common source of real vulnerabilities.
    PoC Agent: suspicious-021...
    ✓ evidence found (11 match(es))
      PoC: 1. Create a symlink: `ln -s /etc /tmp/fake_config_dir`
2. Create a dummy config file at `/tmp/fake_config_dir/config.yml` (must exist 
and be valid YAM...
    Verifying lfi-013...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_traversal_vulnerabi
lity_read_text_create_archive.py
    Evidence: suspicious-020...
  [28/43] lfi-027 (read)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-022...
    ✓ verification confirmed
  [29/43] ssrf-028 (__init__)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-023...
    ✓ not rebutted
      weak point: The finding relies on the assumption that an attacker can 
control the project root or workspace member paths via config file. While the 
config file is user-provided, in typical usage it is part of the repository and 
not attacker-controlled. However, if the config file is sourced from an 
untrusted location (e.g., user upload), the vulnerability is exploitable. The 
symlink traversal issue is real and not mitigated by the existing guards.
    PoC Agent: suspicious-022...
    ✓ not rebutted
      weak point: The finding relies on the assumption that 
`_assemble_local_deps` does not validate dependency paths. The source code for 
`_assemble_local_deps` is not provided, so we cannot confirm or deny the 
presence of validation. However, the data flow trace shows untrusted input from 
`config` (which includes `langgraph.json`) reaching `_add_directory` without 
explicit sanitization in the shown code. The path traversal risk is plausible if
`_assemble_local_deps` returns paths from user-controlled config without 
restriction.
    PoC Agent: suspicious-023...
    ✓ 0/10 — safe
    Evidence: ssrf-028...
    ? pattern match, LLM skeptical (2 match(es))
  [30/43] redos-000 (normalize_image_tag)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-024...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: lfi-027...
    ✓ not rebutted
      weak point: The code does not validate that the resolved path stays within
the intended project directory. An attacker can set `source.root` to an absolute
path or use `../` to traverse outside the project root, leading to arbitrary 
file read.
    PoC Agent: suspicious-024...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-025...
    ✓ not rebutted
      weak point: The finding is valid because ZipFile.extractall() is used 
without sanitizing entry names, allowing path traversal. The template URL is 
derived from a hardcoded dictionary, but the interactive selection 
(_choose_template) may fetch from a remote source, and a man-in-the-middle or 
compromised repository could supply a malicious ZIP. The code lacks any 
validation of ZIP entry names, making it exploitable if an attacker can control 
the ZIP content.
    PoC Agent: lfi-027...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code in 
`_load_pyproject` (not shown but referenced) constructs a path using 
`config_path.parent / source.root / 'pyproject.toml'` without sanitization, and 
`source.root` is user-controlled. The data flow trace shows untrusted input 
reaches this sink via a clear call chain. No validation or access control is 
evident in the provided code snippets.
    PoC Agent: suspicious-025...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-026...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_docker_build_contex
t__uv_lock_package_copy_items.py
    Evidence: suspicious-022...
  [31/43] ssrf-001 (_get_pypi_versions)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_function_get_node_p
m_python_config_to_docker_uv_lock.py
    Evidence: suspicious-021...
  [32/43] ssrf-002 (__init__)
    ? 10/10 — interesting
    Evidence: redos-000...
    ✓ not rebutted
      weak point: The finding is supported by a clear taint path from 
user-controlled config input to file opening without path traversal protection. 
The sink `_load_pyproject` uses `pyproject_path` constructed from `config_root /
source.root / 'pyproject.toml'` where `source.root` is attacker-controlled. No 
sanitization is evident in the provided code snippets. The vulnerability is a 
classic path traversal leading to arbitrary file read.
    PoC Agent: suspicious-026...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_traversal_vulnerabi
lity_add_directory__add_directory.py
    Evidence: suspicious-023...
  [33/43] suspicious-003 (_download_repo_with_requests)
    ? pattern match, LLM skeptical (1 match(es))
  [34/43] suspicious-004 (_docker_config_for_token)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_set_source__contain
er_workspace_root.py
    Evidence: suspicious-024...
  [35/43] suspicious-005 (create_archive)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: ssrf-002...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_zip_archive_url_ext
racts_read.py
    Evidence: lfi-027...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code directly 
passes user-controlled input to httpx.Client without any validation, and httpx 
follows redirects by default. The static analysis correctly identifies the taint
path and the lack of security controls.
    PoC Agent: ssrf-002...
    ? pattern match, LLM skeptical (7 match(es))
  [36/43] suspicious-006 (python_config_to_docker_uv_lock)
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_originates_controll
ed_source_iter_entries.py
    Evidence: suspicious-025...
  [37/43] suspicious-007 (_uv_lock_package_copy_items)
    ? 9/10 — interesting
    Evidence: suspicious-004...
  [38/43] suspicious-008 (_add_directory)
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: suspicious-003...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_originates_controll
ed_source__build_dockerignore_negation_hints.py
    Evidence: suspicious-026...
  [39/43] suspicious-009 (_container_workspace_root)
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code uses 
ZipFile.extractall() without any validation of entry names, and the template URL
can be influenced by the user (via template argument or interactive selection). 
The developer intent does not mention any sanitization, and the data flow shows 
untrusted input reaching the sink.
    PoC Agent: suspicious-003...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-005...
    ? 10/10 — interesting
    Evidence: ssrf-001...
    ✓ not rebutted
      weak point: The finding relies on the assumption that `dep_path` is 
user-controlled and that `_resolved_dep_base` uses `os.path.join` without 
sanitization. The source code for `_resolved_dep_base` and `_read_text` is not 
provided, but the data flow trace shows user input reaching `_read_text` via 
`_assemble_local_deps`. The static analysis annotations indicate untrusted data 
flow, and the reasoning about `os.path.join` discarding base on absolute paths 
is a well-known vulnerability pattern. Without counter-evidence in the provided 
code, the finding appears plausible.
    PoC Agent: suspicious-005...
    ? pattern match, LLM skeptical (4 match(es))
  [40/43] suspicious-010 (iter_entries)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-008...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/ssrf_url_pointing_inter
nal_service___init.py
    Evidence: ssrf-002...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code lacks 
validation of the source_dir path, and the attacker can control the path via 
config files. The data flow from config to _add_directory is clear, and no 
sanitization is present.
    PoC Agent: suspicious-008...
    ✓ evidence found (4 match(es))
      PoC: Run the CLI tool with `--base-url 
http://169.254.169.254/latest/meta-data/` and observe that requests are made to 
the internal metadata endpoint....
    Verifying ssrf-002...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-006...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-007...
    ✓ not rebutted
      weak point: The finding is supported by a clear data flow from 
user-controlled config input to a file open sink without path traversal 
validation. The developer's assumption that source.root is safe is contradicted 
by the lack of sanitization in _plan_uv_lock_workspace.
    PoC Agent: suspicious-006...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_traversal_vulnerabi
lity_read_text_create_archive_2.py
    Evidence: suspicious-005...
  [41/43] suspicious-011 (_build_dockerignore_negation_hints)
    ✓ verification confirmed
  [42/43] lfi-012 (read)
    ✓ not rebutted
      weak point: The finding is well-supported by the data flow trace and code 
analysis. The path construction in `_plan_uv_lock_workspace` uses `config_root /
source.root / 'pyproject.toml'` without sanitization, and `source.root` is 
user-controlled. Python's pathlib does not resolve `..`, enabling path 
traversal. The sink `_load_pyproject` reads the file, leading to LFI. No 
validation or access control mitigates this.
    PoC Agent: suspicious-007...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/afo_zip_archive_url_ext
racts__download_repo_with_requests_2.py
    Evidence: suspicious-003...
  [43/43] ssrf-013 (__init__)
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-009...
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code in 
`_plan_uv_lock_workspace` directly uses user-controlled `source.root` from the 
config to construct a path without validation, and the path is used to open 
files. The `resolve()` call normalizes but does not prevent traversal. The data 
flow from `config_path` to `source.root` is clear, and the sink 
(`pyproject_path.exists()`) is a file access. No sanitization is present.
    PoC Agent: suspicious-009...
    ? 10/10 — interesting
    Evidence: ssrf-013...
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: lfi-012...
    ? pattern match, LLM skeptical (2 match(es))
    ✓ not rebutted
      weak point: The finding is hard to disprove because the code uses 
ZipFile.extractall() without any validation of entry names, and the template URL
is user-controlled via the 'template' parameter. An attacker can provide a 
malicious ZIP archive that overwrites arbitrary files via path traversal in 
entry names.
    PoC Agent: lfi-012...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-010...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_traversal_vulnerabi
lity_add_directory__add_directory_2.py
    Evidence: suspicious-008...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_provide_source__uv_
lock_package_copy_items.py
    Evidence: suspicious-007...
    ✗ rebutted
      reason: The finding claims a path traversal vulnerability in 
`_load_pyproject` via `source.root`. However, the provided source code does not 
contain a function named `_load_pyproject`. The sink in the taint path is 
`_load_pyproject` with param `pyproject_path`, but this function is not present 
in the code. The actual file operations in the code use `config_path.parent` and
`config_root` derived from it, but `config_path` is validated to exist (line 
931: `assert config_path.exists()`). The `source.root` field is not used in any 
path construction in the shown code; the only path construction involving 
`config_root` is in `python_config_to_docker_uv_lock` (line 868) where 
`config_root = config_path.parent.resolve()`, but this is used to compute 
relative paths for Docker build, not for file reading. There is no evidence that
`source.root` is used to open a file. The finding is based on a non-existent 
function and lacks code evidence.
    Evidence: suspicious-010...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_then_opens_without_
any__container_workspace_root.py
    Evidence: suspicious-009...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: suspicious-011...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_local_inclusion_lfi
_vulnerability_python_config_to_docker_uv_lock.py
    Evidence: suspicious-006...
    ✗ rebutted
      reason: The finding claims a path traversal vulnerability in 
`_load_pyproject` via user-controlled `source.root`. However, the provided 
source code does not contain a `_load_pyproject` function. The sink in the taint
path is `_load_pyproject`, but the actual code shows `_plan_uv_lock_workspace` 
and `_uv_lock_package_copy_items` as the deepest functions. The 
`_load_pyproject` function is not present in the code snippet, and the path 
construction logic is not shown. Without the actual sink code, the vulnerability
cannot be verified. Additionally, the taint path includes many functions where 
data flow is not explicitly traced (e.g., `config_to_compose`, 
`python_config_to_docker`), and the claim that `source.root` is user-controlled 
without validation is unsupported by the provided code. The finding lacks 
concrete evidence of the vulnerable code path.
    Evidence: suspicious-011...
    📄 PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_cli-0.4.30/lfi_zip_archive_url_ext
racts_read_2.py
    Evidence: lfi-012...
    ✓ evidence found (7 match(es))
      PoC: Create a malicious ZIP archive with an entry named 
'../../../tmp/evil' containing arbitrary content. Host it at a URL that the 
template lookup can poi...
    Verifying lfi-012...
    ✓ verification confirmed

Phase E: Results
  Blackboard: 13 cached intents, 267 knowledge entries, 41 phase results
  High confidence (40):
    lfi-000: open — logic_gap
      `langgraph validate /etc/passwd` or `langgraph validate ../../etc/passwd`
    redos-000: ? — ?
      
    ssrf-001: ? — ?
      
    redos-002: ? — ?
      
    ssrf-002: httpx.Client.__init__ — logic_gap
      http://169.254.169.254/latest/meta-data/
    ssrf-003: ? — ?
      
    suspicious-003: _download_repo_with_requests — logic_gap
      An attacker hosts a ZIP archive where one entry is named '../../evil.py' 
(or similar). When the victim runs `langgraph new` with a template URL pointing 
to this archive, the extractall() call writes evil.py outside the target 
directory, potentially overwriting critical files (e.g., in /tmp or home 
directory).
    lfi-005: open — logic_gap
      `langgraph up --config /etc/passwd` or `langgraph dev --config 
../../etc/passwd`
    suspicious-005: _read_text — logic_gap
      An attacker can provide a `dep_path` like '/etc/passwd' in the 
langgraph.json configuration. The `_resolved_dep_base` function will return 
'/etc/passwd' (ignoring the intended base directory), and `_read_text` will open
and read that file, potentially leaking sensitive information.
    redos-006: ? — ?
      
    suspicious-006: _load_pyproject — logic_gap
      Create a config file with `source.kind = 'uv'` and `source.root = 
'../../etc/passwd'`. When the CLI processes this config, 
`_plan_uv_lock_workspace` will construct a path to `pyproject.toml` that 
traverses outside the project root, and `_load_pyproject` will read the 
attacker-specified file.
    lfi-007: ? — ?
      
    suspicious-007: _load_pyproject — logic_gap
      Set `source.root` to `../../etc/passwd` in the config file. The resulting 
path becomes `<config_root>/../../etc/passwd`, which resolves to `/etc/passwd` 
and is read by `_load_pyproject`.
    lfi-008: ? — ?
      
    suspicious-008: _add_directory — logic_gap
      Create a `langgraph.json` with a dependency path like `../etc/passwd` or a
symlink pointing to `/etc/passwd`. When `_assemble_local_deps` resolves this 
path, it will be included in `extra_contexts`. Then `_add_directory` will 
traverse and add the file to the archive, which is uploaded to the remote build 
service, leaking its contents.
    suspicious-009: _load_pyproject — logic_gap
      Set `source.root` to `../../etc/passwd` in langgraph.json. The resulting 
path becomes `/some/config/dir/../../etc/passwd`, which resolves to 
`/etc/passwd`. The code will attempt to open this file, leading to local file 
inclusion.
    lfi-010: open — logic_gap
      Set `dep_path` to `/etc/passwd` in `langgraph.json` dependencies to read 
arbitrary files.
    suspicious-010: _load_pyproject — logic_gap
      Create a config file (e.g., `langgraph.json`) with `{"source": {"root": 
"../../etc/passwd"}}`. When the CLI processes this config via `langgraph up 
--config langgraph.json`, the `_load_pyproject` function will open `/etc/passwd`
instead of the intended project file, leaking its contents.
    lfi-011: open — logic_gap
      Provide a config file path that points to an existing file outside the 
project root, e.g., `--config /etc/passwd` (if the file exists and is valid 
JSON). Alternatively, use a symlink inside the project directory pointing to 
`/etc/passwd`.
    suspicious-011: _load_pyproject — logic_gap
      Create a config file with `source.root = '../../etc/passwd'`. When 
`_load_pyproject` is called, it will open `/etc/passwd` instead of the intended 
project file.
    lfi-012: tomllib.load — logic_gap
      Set `source.root` to `/etc/passwd` or `../../../../etc/passwd` in 
langgraph.json to read arbitrary files.
    lfi-012: ZipFile.extractall — logic_gap
      A malicious ZIP archive containing an entry named '../../../etc/passwd' 
would extract to /etc/passwd, overwriting the system password file.
    lfi-013: open — logic_gap
      Create a symlink at a valid config path pointing to /etc/passwd, or supply
a config path that is an absolute path to a sensitive file (e.g., --config 
/etc/passwd) if the file exists and is parseable as JSON (though it will fail 
JSON parsing, the open() still occurs). More practically, use a config path that
traverses directories: --config ../../etc/passwd (if the file exists and is 
valid JSON, but the open() call happens before JSON parsing).
    ssrf-013: ? — ?
      
    redos-014: ? — ?
      
    redos-015: ? — ?
      
    ssrf-016: httpx.get — logic_gap
      If an attacker can perform a man-in-the-middle attack or compromise PyPI, 
they could redirect the request to internal services like 
http://169.254.169.254/latest/meta-data/.
    ssrf-017: httpx.Client.__init__ — logic_gap
      
    suspicious-018: _download_repo_with_requests — logic_gap
      An attacker hosts a malicious repository that, when downloaded as a ZIP, 
contains an entry like '../../evil.sh' that overwrites a critical file outside 
the target directory. The user runs `langgraph new` with a template name that 
points to the attacker's repository URL (if the URL mapping is compromised) or 
the attacker compromises the legitimate template repository.
    suspicious-020: _read_text — logic_gap
      If an attacker can control the `dep_path` parameter (e.g., via a malicious
`langgraph.json` file), they can set it to an absolute path like `/etc/passwd` 
or a relative path with `../` to escape the intended base directory and read 
arbitrary files.
    suspicious-021: _get_node_pm_install_cmd — logic_gap
      Create a config file at `/tmp/exploit/langgraph.json` with `node_version` 
set and `ui` set, then run `langgraph up --config /tmp/exploit/../etc/passwd`. 
The `_get_node_pm_install_cmd` will attempt to open `package.json` at 
`/etc/passwd.parent/package.json`, but the path traversal can be used to read 
arbitrary files if the file exists.
    suspicious-022: _uv_lock_package_copy_items — logic_gap
      Create a symlink inside the project root pointing to `/etc/passwd`. The 
symlink will be followed by `iterdir` and included in the build context, leaking
sensitive files into the Docker image.
    suspicious-023: _add_directory — logic_gap
      Attacker provides a `langgraph.json` with a local dependency path like 
`../../etc` (or a symlink pointing to `/etc`). `_assemble_local_deps` resolves 
this path and includes it in `extra_contexts`. `create_archive` then adds `/etc`
to the archive, uploading sensitive system files (e.g., `/etc/passwd`) to the 
remote build service.
    suspicious-024: _load_pyproject — logic_gap
      Set `source.root` to `/etc/passwd` or `../../etc/passwd` in 
`langgraph.json`. The code will resolve `project_root = config_root / root` and 
then open `pyproject.toml` at that location, reading arbitrary files.
    suspicious-025: _load_pyproject — logic_gap
      Create a config file with `source.root = '../../etc/passwd'`. When the 
config is processed, `_load_pyproject` will open `/etc/passwd` instead of the 
intended pyproject.toml, leaking file contents.
    suspicious-026: _load_pyproject — logic_gap
      Set `source.root` to `../../etc/passwd` in the config file. The resulting 
`pyproject_path` will be `<config_path.parent>/../../etc/passwd`, which resolves
to `/etc/passwd`. The file will be read and its contents may be included in the 
Docker build context or error messages.
    lfi-027: ZipFile.extractall — logic_gap
      Provide a ZIP archive with an entry named '../../../etc/passwd' that 
overwrites the system's password file.

Pipeline Complete
  Target: /tmp/langgraph_cli-0.4.30
  Model: deepseek-chat
  Duration: 174.7s
  Paths discovered: 29
  Slices analyzed: 43
  Findings: 40 high, 3 interesting
  Tokens: 1,068,285 total (956,720 prompt + 111,565 completion)

  Recommended verification targets:
    LFI lfi-000: The `validate` function at line 873 directly opens the file 
path provided by the `config` parameter 
    REDOS redos-000: Code-level pattern evidence (1 matches): ?:if not 
re.fullmatch(r"[A-Za-z0-9_.-]+", value):
    SSRF ssrf-001: Code-level pattern evidence (4 matches): ?:response = 
httpx.get(; ?:except httpx.HTTPError as exc:; 
    REDOS redos-002: Code-level pattern evidence (1 matches): ?:match = 
re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", dep
    SSRF ssrf-002: The `__init__` function receives `base_url` from CLI input 
(user-controlled). It directly assigns it

v3 CodeQL pipeline complete.
