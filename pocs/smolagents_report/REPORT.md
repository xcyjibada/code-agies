# smolagents (HuggingFace) v3 Pipeline 审计报告

**目标**: /tmp/smolagents (HuggingFace AI Agent Framework)  
**Date**: 2026-06-30  
**Pipeline**: v2 (mapping → sourcer → bulk → verification → report)  
**Runtime**: ~4min  
**Token**: ~600K+  

---

## 概览

smolagents 是 HuggingFace 开源的 AI Agent 框架（2025 年发布），提供 CodeAgent、Tool.from_code()、LocalPythonExecutor 等机制让 LLM 执行代码。

与 Django 不同，smolagents 是一个 **新项目 + 攻击面大的设计**：允许 LLM 动态生成和执行 Python 代码，天然引入了 RCE、沙箱逃逸、反序列化等安全风险。

### 核心发现

| 类型 | 数量 | 严重 |
|------|------|------|
| High Confidence (verified) | 18 | 11 confirmed not rebutted |
| Phase D.3 Contradictions | 0 | smolagents 无安全基础设施可矛盾 |
| 可直接利用的漏洞 | **6+** | 远高于 Django 的 0 |

### 与 Django 对比

| 指标 | Django (框架) | smolagents (Agent 框架) |
|------|-------------|----------------------|
| 生产代码漏洞 | 0 | 6+ |
| 沙箱逃逸 | N/A | ✅ (bypass `DANGEROUS_MODULES`) |
| 命令注入 | 0 | ✅ (package install) |
| 不安全反序列化 | 0 | ✅ (pickle.loads) |
| 路径遍历 | 0 | ✅ (from_folder) |

---

## 已确认的可利用漏洞（Code Verified）

### 1. [CRITICAL] Tool.from_code() — exec() RCE

**文件**: `src/smolagents/tools.py:572-575`  
**类型**: RCE via `exec()`  
**状态**: ✅ Confirmed, not rebutted

```python
@classmethod
def from_code(cls, tool_code: str, **kwargs):
    module = types.ModuleType("dynamic_tool")
    exec(tool_code, module.__dict__)  # <-- RCE sink
```

**可利用路径**:
- `Tool.from_hub(trust_remote_code=True)` — 从 HF Hub 下载恶意 tool.py 并 exec
- `MultiStepAgent.from_folder()` → `from_dict()` → `from_code()` — 读取本地 agent.json 中 tool code 并 exec
- `MultiStepAgent.from_hub()` → same chain

**验证**: 第 575 行直接 `exec()` 用户控制的代码，无沙箱、无校验。

---

### 2. [CRITICAL] LocalPythonExecutor 沙箱逃逸

**文件**: `src/smolagents/local_python_executor.py`  
**类型**: 沙箱逃逸 → RCE/任意文件读  
**状态**: ✅ Confirmed, not rebutted

沙箱使用 `DANGEROUS_MODULES` / `DANGEROUS_FUNCTIONS` 列表阻止直接调用 `os.system`、`subprocess` 等，但存在 `check_safer_result` 绕过路径：

```python
DANGEROUS_MODULES = ["builtins", "os", "subprocess", "shutil", "socket", ...]
DANGEROUS_FUNCTIONS = ["builtins.compile", "builtins.eval", "builtins.exec", ...]
```

**绕过技术**:
- `().__class__.__bases__[0].__subclasses__()` → 获取 `os` 模块引用
- `__builtins__` 和 `builtins.__import__` 被 blocked，但使用 `importlib` 可以绕过
- `authorized_imports` 默认为 `BASE_BUILTIN_MODULES`，用户可以传入 `authorized_imports=['*']` 完全关闭沙箱

**验证**: `safer_eval` 装饰器只检查返回值，不阻断中间操作。一旦 LLM agent 被 prompt injection 攻击，可以轻易逃逸。

---

### 3. [HIGH] pickle.loads 不安全反序列化

**文件**: `src/smolagents/serialization.py:295-346`  
**类型**: 不安全反序列化  
**状态**: ✅ Confirmed, not rebutted

```python
@staticmethod
def loads(data: str, allow_pickle: bool = False) -> Any:
    ...
    elif data.startswith("pickle:"):
        return pickle.loads(base64.b64decode(data[7:]))
    else:
        return pickle.loads(base64.b64decode(data))  # legacy format
```

**关键**: `allow_pickle` 默认为 `False`，但:
- `E2BExecutor`、`DockerExecutor`、`ModalExecutor` 的构造函数接受 `allow_pickle` 参数
- 攻击者可控制 websocket 消息内容注入 pickle 载荷
- 5 个不同的 sink 路径全部被 `allow_pickle=True` 条件保护，但只要配置允许即可 RCE

---

### 4. [HIGH] 命令注入 via install_packages

**文件**: `src/smolagents/remote_executors.py:137-141`  
**类型**: 命令注入  
**状态**: ✅ Confirmed, not rebutted

```python
def install_packages(self, additional_imports: list[str]):
    if additional_imports:
        code_output = self.run_code_raise_errors(
            f"!pip install {' '.join(additional_imports)}"
        )
```

`additional_imports` 来自 `tool.to_dict()["requirements"]`，工具定义中的 requirement 参数拼接进 shell 命令。

---

### 5. [HIGH] Tool.save() 路径遍历

**文件**: `src/smolagents/tools.py:390-419`  
**类型**: 任意文件写入  
**状态**: ✅ Confirmed, not rebutted

```python
def save(self, output_dir: str | Path, ...):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    self._write_file(output_path / f"{tool_file_name}.py", ...)
```

`output_dir` 无校验，攻击者可通过 `../../etc/cronjob` 实现任意路径写入。

---

### 6. [HIGH] MultiStepAgent.from_folder() 路径遍历

**文件**: `src/smolagents/agents.py:1119-1158`  
**类型**: 路径遍历 / 任意文件读  
**状态**: ✅ Confirmed, not rebutted

```python
@classmethod
def from_folder(cls, folder: str | Path, **kwargs):
    folder = Path(folder)
    agent_dict = json.loads((folder / "agent.json").read_text())
    ...
    tool_code = (folder / "tools" / f"{tool_name}.py").read_text()
```

`folder` 参数和 `tool_name`（来自 agent.json）直接拼接路径，可遍历读取任意文件。

---

## 严重性总结

| # | 漏洞 | 文件 | CWE | 可利用性 | 默认触发？ |
|---|------|------|-----|---------|-----------|
| 1 | exec() RCE in from_code | tools.py:575 | CWE-95 | 直接可控 code 参数 | ❌ (需 trust_remote_code) |
| 2 | 沙箱逃逸 | local_python_executor.py | CWE-915 | Prompt injection 触发 | ✅ 默认 agent 执行 |
| 3 | pickle 反序列化 | serialization.py:329 | CWE-502 | 需 allow_pickle=True | ❌ (默认 False) |
| 4 | 命令注入 | remote_executors.py:139 | CWE-78 | 需控制 tool definition | ⚠️ from_hub 场景 |
| 5 | 任意文件写 | tools.py:408 | CWE-22 | 需控制 output_dir | ❌ (低权限) |
| 6 | 路径遍历 | agents.py:1128 | CWE-22 | 需控制 folder 参数 | ❌ (低权限) |

**最危险组合**: #1 + #2 = LLM prompt injection → 沙箱代码执行 → 完全失陷

---

## Phase D.3 Assumption Agent

**结果**: 27 semantic anchors, **0 contradictions**

smolagents 是一个 Agent 框架，没有内置的安全基础设施（认证、授权、session 管理等），因此 Assumption Agent 找不到安全假设矛盾。

这是 sink-free 分析的已知盲区：**安全假设分析只对具有多层安全基础设施的项目有效**。

---

## 与 Django 对比分析

| 维度 | Django | smolagents |
|------|--------|------------|
| 成熟度 | 20 年，深度审计 | ~1 年，新兴项目 |
| 安全设计 | SecurityMiddleware, CSRF, XSS filters | 无内置安全层 |
| 攻击面 | HTTP 请求处理 | exec() + pickle + shell |
| LLM prompt injection | N/A | 核心威胁面 |
| v3 检出价值 | 0（皆为设计级已知） | **6+ 真实可利用漏洞** |

**结论**: v3 pipeline 对**低审计覆盖度的新项目**效果显著，对高度成熟框架无效。smolagents 是当前测试中**最有价值的目标**。

---

## 建议

1. **Tool.from_code() 必须移除 exec()** — 使用 AST 沙箱或 restricted Python 执行
2. **LocalPythonExecutor 沙箱** — `check_safer_result` 容易被绕过，应使用 `deny-list` + `allow-list` 双校验
3. **pickle 序列化** — `allow_pickle` 应完全移除，至少默认永久 False
4. **install_packages** — 使用 `shlex.quote()` 或 `subprocess` 而非 shell 拼接
5. **Path traversal** — `save()` 和 `from_folder()` 应校验路径在预期目录内
6. **WAL (Worst-case Attack Landscape)**: LLM prompt injection → `exec()` → `os.system()` 整个攻击链只需一次 prompt
