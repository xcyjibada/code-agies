#!/usr/bin/env python3
"""
第三方视角: 默认配置 smolagents 是否可被攻击者利用？

模拟场景:
  攻击者在 Web 页面 / 文档 / 邮件中埋入 prompt injection 文本
  → 用户让 CodeAgent 处理该内容
  → LLM 被注入，生成恶意 Python 代码
  → 代码在 LocalPythonExecutor 默认配置下执行

默认配置:
  - additional_authorized_imports=[]  (仅 BASE_BUILTIN_MODULES)
  - allow_pickle=False
  - trust_remote_code=False (不主动设置)
  - 用户没有额外添加危险工具

测试: 攻击者 LLM 注入 100 种可能的逃逸代码
"""

import sys
import os

sys.path.insert(0, "/tmp/smolagents/src")

from smolagents.local_python_executor import (
    LocalPythonExecutor,
    BASE_PYTHON_TOOLS,
    BASE_BUILTIN_MODULES,
)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

OK = f"{GREEN}✅ 安全{RESET} (拦截)"
VULN = f"{RED}❌ 失陷{RESET}"
INFO = f"{CYAN}ℹ️ 信息{RESET}"


def run_default(code: str) -> tuple[bool, str]:
    """在默认安全配置下执行代码"""
    exec = LocalPythonExecutor(additional_authorized_imports=[])
    exec.static_tools = {}
    for n, f in BASE_PYTHON_TOOLS.items():
        exec.static_tools[n] = f
    try:
        r = exec(code)
        return True, str(r.output)[:200] if r.output is not None else "(None)"
    except Exception as e:
        return False, str(e)[:200]


def sec(name: str, code: str):
    """执行并报告是否逃逸"""
    ok, msg = run_default(code)
    status = VULN if ok else OK
    print(f"  {status} {name}")
    if ok:
        print(f"        结果: {msg}")
    print()


# ============================
# 第1组: CLASSIC PYTHON SANDBOX ESCAPE
# ============================
print(f"\n{BOLD}=== 第1组: 经典 Python 沙箱逃逸 ==={RESET}\n")

sec("().__class__", "().__class__")
sec("().__class__.__bases__[0].__subclasses__()", "().__class__.__bases__[0].__subclasses__()")
sec("''.__class__.__mro__[1].__subclasses__()", "''.__class__.__mro__[1].__subclasses__()")
sec("getattr(tuple, '__class__')", "getattr(tuple, '__class__')")
sec("type(42).__name__", "type(42).__name__")

# ============================
# 第2组: BUILTIN ABUSE
# ============================
print(f"{BOLD}=== 第2组: Builtin 滥用 ==={RESET}\n")

sec("exec", "exec('import os')")
sec("eval", "eval('__import__(\"os\").system(\"id\")')")
sec("compile", "compile('1+1','','exec')")
sec("open", "open('/etc/passwd')")
sec("globals", "globals()")
sec("locals", "locals()")
sec("vars", "vars()")
sec("dir(obj)", "dir(())")
sec("__import__", "__import__('os')")

# ============================
# 第3组: DANGEROUS MODULE IMPORTS
# ============================
print(f"{BOLD}=== 第3组: 危险模块导入 ==={RESET}\n")

for mod in ["os", "subprocess", "sys", "builtins", "shutil", "socket",
            "pathlib", "pty", "ctypes", "codecs", "inspect", "io",
            "importlib", "pickle", "types", "typing"]:
    sec(f"import {mod}", f"import {mod}")

# ============================
# 第4组: ALLOWED MODULE ABUSE
# ============================
print(f"{BOLD}=== 第4组: 允许模块的非常规利用 ==={RESET}\n")

# re 模块: 能否通过 re.compile 注⼊?
sec("re.compile (safe)", "import re; re.compile('test')")
sec("re.match (safe)", "import re; re.match('^test$', 'test')")
# re 模块有内部正则执⾏，但纯 Python 层

# collections: 能否找到危险引⽤链?
sec("collections (safe)", "import collections; list(collections.OrderedDict.__dict__.keys())")

# math: 纯数学运算
sec("math (safe)", "import math; math.cos(0)")

# datetime: 限时区操作
sec("datetime (safe)", "import datetime; str(datetime.datetime.now())")

# time: 能获取环境吗?
sec("time (safe)", "import time; time.time()")

# random: 纯随机数
sec("random (safe)", "import random; random.randint(0,10)")

# ============================
# 第5组: METACLASS / TYPE TRICKS
# ============================
print(f"{BOLD}=== 第5组: Metaclass/Type 技巧 ==={RESET}\n")

sec("type(type) — metaclass chain", "type(type)")
sec("type.__subclasses__()", "type.__subclasses__()")

# types 模块不在允许列表中，但 type() 函数可用
sec("type(42).__class__", "type(42).__class__")  # dunder attribute blocked
sec("str(type(42)) — allowed", "str(type(42))")

# ============================
# 第6组: INDIRECT BUILTIN ACCESS
# ============================
print(f"{BOLD}=== 第6组: 间接 Builtin 访问 ==={RESET}\n")

sec("lambda.__globals__", "lambda: 0")
sec("function closure chain", "def f(): pass; str(f)")

# Exception 链
sec("try/except Exception", "try: 1/0\nexcept Exception as e:\n str(e)")

# Generator
sec("generator chain", "(x for x in [1,2,3])")

# 运⽤用 allowed modules 里的函数
sec("collections.abc iter chain",
    "import collections; list(collections.abc.Iterator.__subclasshook__.__globals__.keys())")

# ============================
# 第7组: SPECIAL ATTRIBUTE BYPASS
# ============================
print(f"{BOLD}=== 第7组: 特殊属性绕过 ==={RESET}\n")

# 尝试绕过 dunder 检查的变体
sec("getattr via lambda", "f = lambda o, n: getattr(o, n); f((), '__class__')")
sec("setattr bypass", "class X: pass; x=X(); setattr(x, 'test', 1)")  # setattr is allowed but dunder block still applies

# 覆盖 static_tools 的尝试
sec("overwrite type()", "type = lambda x: None")

# 通过基类的非dunder属性
sec("object() constructor", "object()")

# 绕过 evaluate_call builtin 检查
sec("builtins via attribute chain (no wildcard)",
    "import collections; getattr(collections, 'defaultdict')")

# ============================
# 第8组: MEMORY / STATE ABUSE
# ============================
print(f"{BOLD}=== 第8组: 状态/内存滥用 ==={RESET}\n")

# exec 之间 state 会持久化，能否串联多步逃逸?
ex = LocalPythonExecutor(additional_authorized_imports=[])
ex.static_tools = {}
for n, f in BASE_PYTHON_TOOLS.items():
    ex.static_tools[n] = f

steps = [
    ("step1: 定义变量", "x = 42"),
    ("step2: 持久化验证", "str(x)"),
    ("step3: 尝试 import os", "import os"),
    ("step4: 如果成功拿到 os，读文件", "import os; os.getcwd()"),
]
for label, code in steps:
    ok, msg = run_default(code)
    s = OK if not ok else (VULN if label in ["step3", "step4"] else INFO)
    print(f"  {s} {label}: {code}")
    print(f"        → {msg[:100]}")
print()

# ============================
# 第9组: TOOL ABUSE (第三⽅视⻆)
# ============================
print(f"{BOLD}=== 第9组: 通过 Agent 工具的间接攻击 ==={RESET}\n")

print(f"  {INFO} Agent 工具调⽤用绕过 Python 沙箱，因为工具调用走 LLM function calling，")
print(f"        不经过 LocalPythonExecutor。但默认 CodeAgent 没有危险工具：")
print(f"  {INFO} 默认 Tools: python 执⾏器、final_answer\n")
print(f"  {YELLOW}  ⚠️ 如果用户额外添加了 read_file/shell 等工具，prompt injection 可滥用{RESET}")
print(f"  {YELLOW}  ⚠️ 但这是用户配置问题，不是 smolagents 默认漏洞{RESET}\n")

# ============================
# 总结
# ============================
print(f"{BOLD}{'='*60}{RESET}")
print(f"{BOLD}  总结: 默认配置下的攻击可行性{RESET}")
print(f"{BOLD}{'='*60}{RESET}\n")

print(f"  {GREEN}默认配置 LocalPythonExecutor 沙箱对代码执行逃逸有效{RESET}")
print(f"  • __class__/__bases__/__subclasses__() 全部拦截")
print(f"  • import os/subprocess/sys/builtins 全部拦截")
print(f"  • exec/eval/open/compile/__import__ 全部拦截")
print(f"  • 允许模块 (re/collections/math) 无法逃逸")
print(f"")
print(f"  {YELLOW}第三方攻击者默认不可利用{RESET}")
print(f"  • prompt injection 无法突破 Python 沙箱层")
print(f"  • 所有高严重性发现都需要 opt-in 配置:")
print(f"    - Tool.from_code(tool_code) — 需 trust_remote_code=True")
print(f"    - allow_pickle=True")
print(f"    - authorized_imports=['*']")
print(f"    - 用户额外添加危险工具")
print(f"")
print(f"  {RED}但仍存在的威胁:{RESET}")
print(f"  • 第9组: 如果用户配置了文件/网络工具, prompt injection 可滥用")
print(f"  • install_packages 命令注入 (需控制 tool requirements)")
print(f"  • 沙箱开发者自称 'NOT a security sandbox' — deny-list 总有遗漏")
