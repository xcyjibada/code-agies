#!/usr/bin/env python3
"""
h1-agno-hunter.py — HackerOne 赏金计划 Agno 框架探测

三步猎杀:
  1. 从 H1 数据集加载所有有赏金项目，按 ROI 排序
  2. 关键词筛选 + 域名猜测 → 自动探测 Agno
  3. 输出命中结果，按赏金排序

用法:
  python3 h1-agno-hunter.py                               # 全量扫描
  python3 h1-agno-hunter.py --keyword ai,agent             # 只扫 AI 相关
  python3 h1-agno-hunter.py --keyword ai --min-bounty 500  # 最低 $500
  python3 h1-agno-hunter.py -l my-targets.txt              # 自备 target 列表
  python3 h1-agno-hunter.py -l my-targets.txt -o hits.json # 保存结果

-l 文件格式 (每行一个):
  https://api.target.com Vercel Platform Protection
  https://app.company.com Company Name
  # 程序名可选，用来关联 H1 赏金数据

依赖:
  pip install httpx
"""

import argparse
import json
import os
import random
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin

try:
    import httpx
except ImportError:
    print("[!] 需要 httpx: pip install httpx")
    sys.exit(1)


H1_DATA_PATH = "/tmp/bug-bounty-roi/research/hackerone-full-dataset.json"

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


def probe_agno(client, base_url, timeout=8):
    """三指纹检测"""
    hits = {}
    evidence = {}

    # 指纹 1: openapi.json → /agui + RunAgentInput + AGUI
    try:
        r = client.get(urljoin(base_url.rstrip("/") + "/", "openapi.json"), timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            paths = data.get("paths", {})
            if "/agui" in paths or "RunAgentInput" in str(data):
                hits["openapi"] = True
                evidence["openapi"] = list(paths.keys())[:5]
    except Exception:
        pass

    # 指纹 2: /status → {"status":"..."}
    try:
        r = client.get(urljoin(base_url.rstrip("/") + "/", "status"), timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if "status" in data:
                hits["status"] = True
                evidence["status"] = data["status"]
    except Exception:
        pass

    # 指纹 3: POST /agui (空body) → 422 + threadId/runId
    try:
        r = client.post(urljoin(base_url.rstrip("/") + "/", "agui"), json={}, timeout=timeout)
        if r.status_code == 422:
            body = r.text
            if "threadId" in body and "runId" in body:
                hits["422"] = True
                evidence["422"] = "AGUI+FastAPI"
    except Exception:
        pass

    return len(hits) >= 1, {
        "detected": len(hits) >= 1,
        "fingerprints": list(hits.keys()),
        "evidence": evidence,
    }


def make_domain_candidates(handle, name):
    """从 H1 项目信息生成候选域名"""
    candidates = set()

    def add(domain):
        for proto in ["https://", "http://"]:
            candidates.add(f"{proto}{domain}")

    slug = handle.lower().replace("_", "-").replace(" ", "-")
    add(f"{slug}.com")
    add(f"api.{slug}.com")
    add(f"app.{slug}.com")

    # 去停用词
    stop = {"bug", "bounty", "platform", "protection", "security", "hackerone",
            "program", "infosec", "disclosure", "bbp", "h1c", "h1c3"}
    parts = [p for p in slug.split("-") if p not in stop]
    if parts:
        base = "-".join(parts)
        add(f"{base}.com")
        add(f"api.{base}.com")

    # 从 name 取第一个有意义的词
    name_clean = re.sub(r'[^a-zA-Z0-9\s]', '', name).lower()
    words = [w for w in name_clean.split() if w not in stop and len(w) > 2]
    if words:
        add(f"{words[0]}.com")
        add(f"api.{words[0]}.com")

    return list(candidates)


def load_h1_programs():
    """从本地数据集加载 H1 项目"""
    if os.path.exists(H1_DATA_PATH):
        with open(H1_DATA_PATH) as f:
            data = json.load(f)
        progs = data.get("programs", [])
        return [p for p in progs if p.get("offers_bounties")]
    return []


def load_targets(filepath):
    """从文件加载手动指定的 target
    格式:
      https://target.com Program Name
      https://api.target.com
    """
    targets = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            url = parts[0]
            name = parts[1] if len(parts) > 1 else ""
            targets.append({"url": url, "name": name})
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="h1-agno-hunter — HackerOne 赏金计划 Agno 框架探测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-l", "--list", help="目标URL列表 (每行一个URL)")
    parser.add_argument("--keyword", help="筛选关键词 (逗号分隔)")
    parser.add_argument("--min-bounty", type=int, default=0, help="最低赏金")
    parser.add_argument("--workers", type=int, default=10, help="并发数")
    parser.add_argument("-o", "--output", help="输出 JSON")
    parser.add_argument("--no-probe", action="store_true", help="只列项目不探测")
    parser.add_argument("--demo", action="store_true", help="仅前3个")
    args = parser.parse_args()

    print(f"""{BOLD}
  ╔════════════════════════════════════════╗
  ║       H1 Agno Hunter v1.0              ║
  ╚════════════════════════════════════════╝{RESET}
    """)

    # ============================================
    # Phase 1: 加载目标
    # ============================================
    targets_to_probe = {}  # {url: program_info}

    if args.list:
        # 用户自己提供 target URL
        manual = load_targets(args.list)
        info(f"手动指定 {len(manual)} 个 target")
        # 尝试匹配 H1 赏金数据
        h1_progs = load_h1_programs()
        for t in manual:
            prog_info = {"name": t["name"], "minimum_bounty": 0, "source": "manual"}
            if h1_progs and t["name"]:
                match = [p for p in h1_progs if t["name"].lower() in p.get("name", "").lower()]
                if match:
                    prog_info["minimum_bounty"] = match[0].get("minimum_bounty", 0)
                    prog_info["name"] = match[0]["name"]
            targets_to_probe[t["url"]] = prog_info
    else:
        # 从 H1 数据集
        h1_progs = load_h1_programs()
        if not h1_progs:
            fail("无法加载 H1 数据集（需要 bug-bounty-roi 项目）")
            info(f"请先 clone: git clone https://github.com/TommyClawd/bug-bounty-roi /tmp/bug-bounty-roi")
            info("或使用 -l 手动指定 target 列表")
            sys.exit(1)

        info(f"H1 有赏金项目: {len(h1_progs)}")

        # 筛选
        if args.keyword:
            keywords = [k.strip().lower() for k in args.keyword.split(",")]
            h1_progs = [p for p in h1_progs
                        if any(k in (p.get("name", "") or "").lower() for k in keywords)]
            info(f"关键词筛选: {len(h1_progs)}")

        if args.min_bounty > 0:
            h1_progs = [p for p in h1_progs if (p.get("minimum_bounty") or 0) >= args.min_bounty]
            info(f"最低赏金筛选: {len(h1_progs)}")

        if args.demo:
            h1_progs = h1_progs[:3]

        # 按 ROI 排序
        h1_progs.sort(key=lambda p: p.get("roi_score", 0) or 0, reverse=True)

        # 打印前 20 个
        print(f"\n{'=' * 72}")
        print(f"  {'排名':5s} {'项目':45s} {'赏金':>10s}")
        print(f"{'=' * 72}")
        for i, p in enumerate(h1_progs[:20]):
            name = (p.get("name", "") or "")[:44]
            bounty = f"${p.get('minimum_bounty', 0):,}" if p.get("minimum_bounty") else "—"
            print(f"  {i+1:3d}.  {name:45s} {bounty:>10s}")
        if len(h1_progs) > 20:
            print(f"  ... 还有 {len(h1_progs) - 20} 个")
        print()

        if args.no_probe:
            if args.output:
                with open(args.output, "w") as f:
                    json.dump({"programs": h1_progs}, f, indent=2)
            return

        # 生成候选域名
        for p in h1_progs:
            candidates = make_domain_candidates(p.get("handle", ""), p.get("name", ""))
            for url in candidates:
                if url not in targets_to_probe:
                    targets_to_probe[url] = {
                        "name": p["name"],
                        "handle": p.get("handle", ""),
                        "minimum_bounty": p.get("minimum_bounty", 0),
                        "roi_score": p.get("roi_score", 0),
                        "source": "h1_dataset",
                    }

        info(f"生成候选域名: {len(targets_to_probe)} 个")

    # ============================================
    # Phase 2: 探测
    # ============================================
    print(f"\n{BOLD}═══ Agno 框架探测 ═══{RESET}")
    print(f"  并发: {args.workers}\n")

    import concurrent.futures
    client = httpx.Client(timeout=8, verify=False,
                          headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    results = []
    target_list = list(targets_to_probe.items())
    random.shuffle(target_list)

    def probe(url, prog):
        try:
            detected, detail = probe_agno(client, url)
            if detected:
                return {**prog, "detected_url": url, **detail}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(probe, url, prog) for url, prog in target_list]
        done = 0
        total = len(futures)
        for f in concurrent.futures.as_completed(futures):
            done += 1
            result = f.result()
            if result:
                bounty = result.get("minimum_bounty", 0)
                bounty_str = f" ${bounty:,}" if bounty else ""
                print(f"  {GREEN}🔥 AGNO{RESET} {result['name']:40s} "
                      f"{result['detected_url']:40s}  {bounty_str}")
                results.append(result)

            if done % 50 == 0:
                info(f"进度: {done}/{total}")
                time.sleep(0.5)

    client.close()

    # ============================================
    # Phase 3: 报告
    # ============================================
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"  {'猎杀报告':^68s}{RESET}")
    print(f"{'=' * 72}")
    print(f"  扫描域名: {len(targets_to_probe)}")
    print(f"  Agno 命中: {GREEN}{len(results)}{RESET}")

    if results:
        results.sort(key=lambda r: r.get("minimum_bounty", 0) or 0, reverse=True)
        print(f"\n{BOLD}命中清单 (按赏金排序):{RESET}")
        for r in results:
            b = r.get("minimum_bounty", 0)
            b_str = f"💰 ${b:,}" if b else ""
            print(f"  {GREEN}[{b_str}]{RESET} {r['name']}")
            print(f"         URL: {r['detected_url']}")
            print(f"         指纹: {', '.join(r['fingerprints'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_scanned": len(targets_to_probe),
                "agno_hits": len(results),
                "results": results,
            }, f, indent=2, ensure_ascii=False)
        print(f"\n  结果已保存: {args.output}")


if __name__ == "__main__":
    main()
