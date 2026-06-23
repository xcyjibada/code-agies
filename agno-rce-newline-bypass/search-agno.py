#!/usr/bin/env python3
"""
search-agno.py — 全网搜索 Agno 框架实例

搜索方法 (按优先级):
  1. GitHub 依赖者 → 找实际用 agno 的产品/公司
  2. H1 赏金项目 → crt.sh 查域名 → 探测
  3. 全网搜指纹 → FOFA/搜索引擎搜 agno 特征

用法:
  python3 search-agno.py                                    # 默认: GitHub + H1
  python3 search-agno.py --keyword ai                       # 只看 AI 相关
  python3 search-agno.py --github-only                      # 只看 GitHub 衍生
  python3 search-agno.py --h1-only                          # 只看 H1 赏金项目
  python3 search-agno.py -o hits.json                       # 保存结果

依赖:
  pip install httpx beautifulsoup4
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    import httpx
except ImportError:
    print("[!] 需要 httpx: pip install httpx")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


H1_DATA_PATH = "/tmp/bug-bounty-roi/research/hackerone-full-dataset.json"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
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


# ============================================================
# Agno 指纹探测
# ============================================================

def probe_agno(client, url, timeout=8):
    """三点指纹检测 agno"""
    base = url.rstrip("/")
    hits = {}
    evidence = {}

    # 指纹 1: openapi.json
    for endpoint in ["/openapi.json", "/openapi"]:
        try:
            r = client.get(f"{base}{endpoint}", timeout=timeout, follow_redirects=True)
            if r.status_code == 200:
                data = r.json()
                paths = data.get("paths", {})
                if "/agui" in paths:
                    hits["openapi"] = True
                    evidence["openapi"] = list(paths.keys())[:5]
                    break
                if "RunAgentInput" in str(data):
                    hits["openapi"] = True
                    evidence["openapi"] = "RunAgentInput"
                    break
        except Exception:
            pass

    # 指纹 2: /status
    if not hits:
        try:
            r = client.get(f"{base}/status", timeout=timeout, follow_redirects=True)
            if r.status_code == 200:
                d = r.json()
                if "status" in d:
                    hits["status"] = True
                    evidence["status"] = d["status"]
        except Exception:
            pass

    # 指纹 3: 422 格式
    if not hits:
        try:
            r = client.post(f"{base}/agui", json={}, timeout=timeout)
            if r.status_code == 422 and "threadId" in r.text and "Field required" in r.text:
                hits["422"] = True
                evidence["422"] = "AGUI"
        except Exception:
            pass

    return len(hits) >= 1, hits, evidence


# ============================================================
# 搜索方法 1: GitHub 依赖者
# ============================================================

def scrape_github_dependents(client):
    """抓 GitHub 上依赖 agno 的仓库"""
    repos = set()
    url = "https://github.com/agno-agi/agno/network/dependents"

    try:
        r = client.get(url, timeout=15,
                       headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        if r.status_code == 200:
            # 提取所有仓库链接
            for m in re.finditer(r'/([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)', r.text):
                repo = m.group(1)
                # 过滤
                if (repo.count("/") == 1 and
                    not any(x in repo.lower() for x in
                            ["github", "orgs/", "users/", "topics/", "sponsors",
                             "community", "features", "industry", "docs.", "api.",
                             "www.w3"]) and
                    repo != "agno-agi/agno" and
                    len(repo) > 5):
                    repos.add(repo)
    except Exception as e:
        warn(f"GitHub 抓取失败: {e}")

    return sorted(repos)


def get_repo_info(client, repo_full):
    """获取仓库的元信息 (homepage, description)"""
    try:
        r = client.get(
            f"https://api.github.com/repos/{repo_full}",
            timeout=10,
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": "search-agno"},
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "repo": repo_full,
                "description": data.get("description") or "",
                "homepage": data.get("homepage") or "",
                "stars": data.get("stargazers_count") or 0,
                "topics": data.get("topics") or [],
            }
    except Exception:
        pass
    return {"repo": repo_full, "description": "", "homepage": "", "stars": 0, "topics": []}


# ============================================================
# 搜索方法 2: H1 + crt.sh
# ============================================================

def load_h1_programs(keyword=None):
    if not os.path.exists(H1_DATA_PATH):
        return []
    with open(H1_DATA_PATH) as f:
        data = json.load(f)
    progs = [p for p in data.get("programs", []) if p.get("offers_bounties")]
    if keyword:
        ks = [k.strip().lower() for k in keyword.split(",")]
        progs = [p for p in progs if any(k in (p.get("name", "") or "").lower() for k in ks)]
    progs.sort(key=lambda p: p.get("roi_score", 0) or 0, reverse=True)
    return progs


def try_common_domains(program):
    """从 program name/handle 生成常见域名"""
    name = program.get("name", "") or ""
    handle = program.get("handle", "") or ""

    domains = set()
    slug = re.sub(r'[^a-z0-9.-]', '', handle.lower().replace("_", "-").replace(" ", "-"))
    parts = [p for p in slug.split("-") if p not in
             {"bug", "bounty", "platform", "protection", "security",
              "hackerone", "program", "bbp", "h1c", "h1c3", "infosec"}]

    candidates = []
    if parts:
        candidates.append(parts[0])
        if len(parts) > 1:
            candidates.append(f"{parts[0]}-{parts[1]}")
            candidates.append(f"{parts[0]}{parts[1].capitalize()}")

    # 也试 name 的第一个词
    name_word = name.split()[0].lower() if name.split() else ""
    name_word = re.sub(r'[^a-z0-9]', '', name_word)
    if name_word and name_word not in candidates:
        candidates.append(name_word)

    for c in candidates:
        if len(c) >= 3:
            domains.add(f"https://{c}.com")
            if c != "api":
                domains.add(f"https://api.{c}.com")
                domains.add(f"https://app.{c}.com")
                domains.add(f"https://www.{c}.com")

    return list(domains)


# ============================================================
# 搜索方法 3: FOFA / 搜索引擎 (需 token)
# ============================================================

def fofa_search_agno(client, token):
    """FOFA 搜 agno 指纹"""
    if not token:
        return []
    urls = []
    for query in ['body="/agui" && body="openapi.json"', 'body="RunAgentInput"']:
        try:
            encoded = __import__("base64").b64encode(query.encode()).decode()
            r = client.get("https://fofa.info/api/v1/search/all",
                           params={"key": token, "qbase64": encoded, "size": 100,
                                   "fields": "host,title"},
                           timeout=30)
            if r.status_code == 200:
                for item in r.json().get("results", []):
                    host = item[0] if isinstance(item, list) else item
                    if host:
                        urls.append(f"https://{host}" if not host.startswith("http") else host)
        except Exception:
            pass
    return urls


# ============================================================
# 搜索方法 4: 从 repository 提取可能的域名
# ============================================================

def extract_domain_from_repo(repo_info):
    """从 GitHub 仓库信息提取可能的产品域名"""
    domains = set()
    homepage = repo_info.get("homepage", "") or ""
    desc = repo_info.get("description", "") or ""
    repo = repo_info.get("repo", "")

    # 从 homepage 取
    if homepage and homepage.startswith("http"):
        domains.add(homepage.rstrip("/"))

    # 从 owner 名猜测: "company/product" → company.com
    owner = repo.split("/")[0] if "/" in repo else ""
    if owner and len(owner) >= 3:
        domains.add(f"https://{owner}.com")
        domains.add(f"https://{owner}.io")

    # 从描述中提取域名
    for m in re.finditer(r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', desc):
        domains.add(f"https://{m.group(1)}")

    return list(domains)


# ============================================================
# 主逻辑
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="search-agno.py — 全网搜索 Agno 框架实例")
    parser.add_argument("--keyword", help="H1 关键词筛选")
    parser.add_argument("--github-only", action="store_true", help="只看 GitHub 依赖者")
    parser.add_argument("--h1-only", action="store_true", help="只看 H1 赏金项目")
    parser.add_argument("--fofa", help="FOFA API Key (搜全网)")
    parser.add_argument("--workers", type=int, default=20, help="并发数")
    parser.add_argument("-o", "--output", default=None, help="输出 JSON")
    parser.add_argument("--demo", action="store_true", help="演示模式")
    args = parser.parse_args()

    print(f"""{BOLD}
  ╔═══════════════════════════════════════════╗
  ║     Search-Agno — 全网 Agno 框架探测      ║
  ╚═══════════════════════════════════════════╝{RESET}
    """)

    client = httpx.Client(timeout=15, verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
    all_targets = {}  # url -> source info
    results = []

    # ============================================
    # 方法 1: GitHub 依赖者
    # ============================================
    if not args.h1_only:
        print(f"{BOLD}═══ [1/3] GitHub 依赖者搜索 ═══{RESET}")
        repos = scrape_github_dependents(client)
        info(f"发现 {len(repos)} 个依赖仓库")

        # 获取详情
        repo_infos = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(get_repo_info, client, r): r for r in repos}
            for f in concurrent.futures.as_completed(futures):
                ri = f.result()
                if ri:
                    repo_infos.append(ri)
                    stars = ri.get("stars", 0)
                    if stars > 10 or ri.get("homepage"):
                        print(f"  {GREEN}+{RESET} {ri['repo']:45s} ★{stars:4d}  {(ri.get('homepage') or '')[:40]}")

        # 提取域名
        for ri in repo_infos:
            for domain in extract_domain_from_repo(ri):
                if domain not in all_targets:
                    all_targets[domain] = {"source": f"github:{ri['repo']}", "type": "github"}

    # ============================================
    # 方法 2: H1 赏金项目
    # ============================================
    if not args.github_only:
        print(f"\n{BOLD}═══ [2/3] H1 赏金项目搜索 ═══{RESET}")
        h1_progs = load_h1_programs(args.keyword)
        if h1_progs:
            info(f"H1 有赏金项目: {len(h1_progs)}")
            for p in h1_progs[:15]:
                name = (p.get("name", "") or "")[:40]
                bounty = f"${p.get('minimum_bounty', 0):,}" if p.get("minimum_bounty") else "—"
                print(f"     {name:42s} {bounty}")

            # 生成域名
            for p in h1_progs:
                for domain in try_common_domains(p):
                    if domain not in all_targets:
                        all_targets[domain] = {
                            "source": f"h1:{p.get('name','')}",
                            "type": "h1",
                            "bounty": p.get("minimum_bounty", 0),
                            "program": p.get("name", ""),
                        }

    # ============================================
    # 方法 3: FOFA 全网搜索
    # ============================================
    if args.fofa:
        print(f"\n{BOLD}═══ [3/3] FOFA 全网搜索 ═══{RESET}")
        fofa_urls = fofa_search_agno(client, args.fofa)
        info(f"FOFA 发现 {len(fofa_urls)} 个可能实例")
        for url in fofa_urls:
            if url not in all_targets:
                all_targets[url] = {"source": "fofa", "type": "fofa"}

    if args.demo:
        all_targets = dict(list(all_targets.items())[:10])

    info(f"待探测域名: {len(all_targets)}")

    if not all_targets:
        fail("没有找到待探测目标")
        warn("建议: 该方法依赖网络环境，可尝试 --fofa <API_KEY> 或")
        warn("      手动编辑 target 列表用 agno-hunter.py -l 跑")
        client.close()
        sys.exit(0)

    # ============================================
    # 探测阶段
    # ============================================
    print(f"\n{BOLD}═══ Agno 框架探测 ═══{RESET}")

    def probe(url, meta):
        try:
            detected, hits, evidence = probe_agno(client, url)
            if detected:
                return {
                    "url": url,
                    "source": meta.get("source", "?"),
                    "program": meta.get("program", ""),
                    "bounty": meta.get("bounty", 0),
                    "fingerprints": list(hits.keys()),
                    "evidence": evidence,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe, url, meta): url for url, meta in all_targets.items()}
        done = 0
        total = len(futures)
        for f in concurrent.futures.as_completed(futures):
            done += 1
            result = f.result()
            if result:
                results.append(result)
                bounty = ""
                if result.get("bounty"):
                    bounty = f" 💰${result['bounty']:,}"
                print(f"  {GREEN}🔥 AGNO{RESET} {result['url'][:60]:60s}{bounty}")

            if done % 30 == 0:
                info(f"进度: {done}/{total}")

    client.close()

    # ============================================
    # 报告
    # ============================================
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"  猎杀报告")
    print(f"{'=' * 60}")
    print(f"  探测域名: {len(all_targets)}")
    print(f"  Agno 命中: {GREEN}{len(results)}{RESET}")

    if results:
        print(f"\n{BOLD}命中清单:{RESET}")
        for r in results:
            bounty = f" [💰 ${r['bounty']:,}]" if r.get("bounty") else ""
            print(f"  {GREEN}+{RESET} {r['url']}{bounty}")
            print(f"    来源: {r['source']}  指纹: {', '.join(r['fingerprints'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_scanned": len(all_targets),
                "agno_hits": len(results),
                "results": results,
            }, f, indent=2, ensure_ascii=False)
        print(f"\n  结果已保存: {args.output}")


if __name__ == "__main__":
    main()
