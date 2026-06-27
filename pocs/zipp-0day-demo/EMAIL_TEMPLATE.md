To: Tidelift Security Team (tidelift.com/security)
Subject: [VULN] ReDoS vulnerability in zipp.Path.glob() — CWE-1333, all versions ≤ 4.1.0

---

Dear Tidelift Security Team,

I am disclosing a Regular Expression Denial of Service (ReDoS) vulnerability
in the zipp library (jaraco/zipp), for which Tidelift is the designated
security contact per the project's SECURITY.md.

This finding was discovered using **agies**, my AI-native code audit
pipeline that combines static analysis with LLM-driven path exploration.

### Summary

A ReDoS vulnerability (CWE-1333) exists in `zipp.Path.glob()`. The glob
translator converts patterns like `*a*a*a*a*a*a` into regexes with
repeated greedy quantifiers (`[^/]*a[^/]*a...`), causing catastrophic O(N^K)
backtracking when matching against ZIP entries with long 'a' sequences.

### Affected Versions

- zipp 3.0.0 through 4.1.0 (latest stable) — all versions affected
- CPython zipfile.Path (Python ≥3.12) — shares the same code via backport
- Monthly PyPI downloads: ~500M

### Impact

A single HTTP request with pattern `*a×7` against a crafted ZIP consumes
~19 seconds of CPU at 100% utilization. Four concurrent requests against
a gunicorn deployment with 4 sync workers blocks all workers for the
duration, causing complete denial of service for legitimate users.

Normal request latency degrades from ~2ms to ~18,000ms during attack.

### Root Cause

`zipp/glob.py` — `Translator.replace()` converts `*` to `[^/]*`.
When the pattern `*a` is repeated K times, the regex engine must
partition N 'a' characters among K groups, yielding C(N-1, K-1)
backtracking paths — O(N^K) complexity.

This is specific to zipp's regex-based glob implementation.
Python's standard `pathlib.Path.glob()` uses `fnmatch` and is not affected.

### Remedy

No fix is currently available. Potential approaches:
1. Limit repetition of `*X` sub-patterns in the glob translator
2. Use atomic groups `(?>...)` to eliminate backtracking
3. Add a pattern complexity check before regex compilation

### PoC (copy-paste and run)

```bash
pip install zipp==4.1.0 && python3 -c "
import zipfile, io, time
from zipp import Path
data = io.BytesIO()
with zipfile.ZipFile(data, 'w') as zf:
    for i in range(50):
        zf.writestr(f\"{'a'*(i%50+1)}/file{i}.txt\", 'data')
    zf.writestr('a'*50, 'data')
p = Path(zipfile.ZipFile(data, 'r'))
start = time.time()
list(p.glob('*a'*7))
print(f'DoS: {time.time()-start:.1f}s')
"
```

Pattern scaling (on 50-char entries):
  *a×4 → 0.07s    *a×6 → 3.4s
  *a×5 → 0.50s    *a×7 → 19s   *a×8 → 96s

A full reproduction sandbox (Docker + Flask + gunicorn) is available on
request.

### CVE Status

No CVE has been assigned. This vulnerability has no public record and
no available fix. It is distinct from CVE-2024-5569 (which addressed an
infinite loop in resolve_dir(), not the glob regex issue).

### Request

1. Please assign a CVE ID for this issue
2. Please coordinate disclosure and fix timeline with the maintainer
3. I am happy to provide additional reproduction materials if needed

Thank you,

xcy
2694667938x@gmail.com
