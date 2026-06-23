# Security Advisory: Newline Injection Bypass in CodingTools.run_shell

**Product**: agno (https://github.com/agno-agi/agno)  
**Version**: main branch (latest commit 5cf1ed7 at time of discovery)  
**Type**: Security Feature Bypass → Remote Code Execution (RCE)  
**Severity**: High  
**CVE Status**: Pending  
**Discovered**: 2026-06-15

---

## Description

`CodingTools.run_shell()` in `agno/tools/coding.py` provides a shell execution tool
protected by `_check_command()`, which blocks dangerous shell metacharacters
(`;`, `&&`, `||`, `|`, `$(`, `` ` ``, `>`, `<`) and restricts commands to an allowlist
(`DEFAULT_ALLOWED_COMMANDS`).

**The newline character `\n` (0x0a) is not included in the blocked patterns.**
Since `subprocess.run(command, shell=True)` treats newlines as command separators,
an attacker can inject arbitrary commands after a newline character.

**Additionally, injected commands after the newline are NOT validated against the
allowed commands list.** The allowlist check (`tokens[0] in allowed_commands`)
only examines the first token, so any command after a newline executes freely.

## Vulnerable Code

**File**: `agno/tools/coding.py`, line 249

```python
_DANGEROUS_PATTERNS: List[str] = ["&&", "||", ";", "|", "$(", "`", ">", ">>", "<"]
# \n (newline, 0x0a) is MISSING from this list
```

**File**: `agno/tools/coding.py`, lines 520-527

```python
result = subprocess.run(
    command,       # original string, includes injected \n
    shell=True,    # shell interprets \n as command separator
    capture_output=True,
    text=True,
    timeout=effective_timeout,
    cwd=str(self.base_dir),
)
```

## Proof of Concept

### Direct verification (no API key needed):

```python
from agno.tools.coding import CodingTools
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    tools = CodingTools(base_dir=Path(tmp), restrict_to_base_dir=True)

    # Blocked: semicolon injection
    tools.run_shell("echo hello; id")
    # → "Error: Shell operator ';' is not allowed"

    # Bypassed: newline injection
    tools.run_shell("echo hello\nid")
    # → Executes BOTH "echo hello" AND "id"
```

### Full chain via prompt injection (requires LLM API):

Attacker crafts input containing prompt injection → LLM agent with CodingTools
is tricked into calling `run_shell("echo hello\nevil_command")` → RCE.

See `poc_standalone.py` and `poc_full_chain.py` in this folder.

## Impact

An attacker who can control input to an LLM agent configured with `CodingTools`
(via prompt injection) can achieve arbitrary command execution with the full
privileges of the running process.

Since the second command is not validated against the allowlist, any system
command can be executed (limited only by the requirement that the command
string not contain the 9 blocked metacharacters — easily bypassed via Python's
`urllib.request` or `os.system`).

## Remediation

### Option 1 (minimal): Add newline to blocked patterns

```python
_DANGEROUS_PATTERNS: List[str] = [
    "&&", "||", ";", "|", "$(", "`", ">", ">>", "<",
    "\n", "\r",
]
```

### Option 2 (recommended): Parse command before execution

Use `shlex.split()` to parse the command into a list, validate tokens, then
call `subprocess.run(args, shell=False)`:

```python
args = shlex.split(command)
error = self._check_command_tokens(args)
if error:
    return error
result = subprocess.run(args, shell=False, capture_output=True, text=True)
```

This eliminates shell injection entirely regardless of metacharacter filtering.

## Timeline

- 2026-06-15: Vulnerability discovered via agies (AI code audit tool)
- 2026-06-15: Live sandbox verification confirming RCE
- 2026-06-15: Advisory drafted, PoC prepared
