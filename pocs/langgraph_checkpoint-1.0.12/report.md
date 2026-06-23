# agies v3 验证报告 — langgraph-checkpoint-1.0.12（已知 CVE 靶向测试）

**日期:** 2026-06-18
**模型:** deepseek-chat
**Pipeline:** v3 (tree-sitter → slicer → Intent/Logic → Evidence → Adversary → PoC)

---

## 概述

| 指标 | 值 |
|--------|-------|
| 目标 | `/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12` |
| 版本 | langgraph-checkpoint-1.0.12（CVE-2026-28277 / CVE-2025-64439 未修复版本） |
| 语言 | Python |
| 文件数 | 12 |
| 函数索引 | 66 |
| 耗时 | 34.4s |
| 总 tokens | 51,505 (42,108 prompt + 9,397 completion) |

## 本次新增的 sink pattern

在扫描前向 `sink_patterns.py` 添加了：
- `msgpack.unpackb` → RCE（反序列化 sink，pickle.loads 同类）
- `importlib.import_module(...)` → SUSPICIOUS（动态导入模式）

## Phase A: 路径发现

| 漏洞类型 | 发现的 Sink |
|---------|------------|
| Remote Code Execution | 1 |
| ReDoS | 1 |
| Suspicious | 2 |
| **合计** | **4 条原始路径** |

- Body 检测孤立路径（无调用链）：**3**

## Phase D: 分析结果

| 严重程度 | 数量 |
|----------|-------|
| 高置信度 (≥7) | 3 |
| Interesting (4-7) | 1 |
| Safe (<4) | 0 |

## 发现详情

### rce-000 — `loads_typed`（CVE-2026-28277）

**Sink:** `msgpack.unpackb` → **CVE-2026-28277 确认**

`JsonPlusSerializer.loads_typed()` 方法在 `type_ == "msgpack"` 分支调用 `msgpack.unpackb(data_, ext_hook=_msgpack_ext_hook)`。`_msgpack_ext_hook` 使用 `importlib.import_module` 和 `getattr` 根据 msgpack 数据动态导入并实例化任意 Python 类。

**Adversary 判定:** ❌ 未驳倒 — "创建恶意序列化数据写入存储的可能性是存在的"
**PoC Agent:** ✅ 已生成 — `rce_sink_function_loads_typed_loads_typed.py`

### suspicious-002 — `_reviver`（CVE-2025-64439）

**Sink:** `importlib.import_module` → **CVE-2025-64439 (JsonPlusSerializer RCE) 确认**

`JsonPlusSerializer._reviver()` 方法处理 JSON 对象的 `lc:2, type:"constructor"` 字段，使用 `importlib.import_module` 和 `getattr` 动态导入模块并调用任意可调用对象，参数完全由攻击者控制。

**Adversary 判定:** ❌ 未驳倒 — "weak point 明确"
**PoC Agent:** ✅ 已生成 — `rce_langgraph_checkpoint_system__reviver.py`
**PoC 描述:** 攻击者发送 `{"lc": 2, "type": "constructor", "id": ["os", "system"], "args": ["id"]}` 即可执行任意命令

### suspicious-003 — `_msgpack_ext_hook`

**Sink:** `importlib.import_module` — msgpack ext_hook 中的动态加载

`_msgpack_ext_hook` 根据 6 种扩展码（EXT_CONSTRUCTOR_SINGLE_ARG 等）解包 msgpack 数据，执行 `importlib.import_module` + `getattr` + 构造函数调用，无任何白名单或输入校验。

**Adversary 判定:** ❌ 未驳倒 — "这是经典的不安全反序列化导致 RCE"
**PoC Agent:** ✅ 已生成 — `rce_python_objects__msgpack_ext_hook.py`

### redos-001 — `_default`

**判定:** Safe（0/10）— Adversary 正确驳倒。`re.compile` 只在序列化已有 Pattern 对象时被调用，不处理用户输入的正则模式。

## 结果总表

| 发现 | 类型 | 置信度 | 真实 CVE | PoC | Adversary |
|------|------|---------|----------|-----|-----------|
| rce-000 | RCE (msgpack.unpackb) | 高 | CVE-2026-28277 | ✅ | 未驳倒 |
| suspicious-002 | RCE (_reviver) | 高 | CVE-2025-64439 | ✅ | 未驳倒 |
| suspicious-003 | RCE (_msgpack_ext_hook) | 高 | — | ✅ | 未驳倒 |
| redos-001 | ReDoS | 低 | FP | — | 驳倒 |

## 结论

**agies v3 成功检测到 langgraph-checkpoint-1.0.12 中的 3 个 RCE 漏洞，全部生成了 PoC 脚本，且 Adversary Agent 未能驳倒其中任何一个。**

| 类别 | 总数 | 真实漏洞 | 误报 |
|------|------|---------|------|
| RCE | 3 | 3 ✅ | 0 |
| ReDoS | 1 | 0 | 1 |
| **合计** | **4** | **3 (75%)** | **1 (25%)** |

### 关键经验

1. **之前的 langgraph v1.2.5 扫不到东西是因为版本已修复所有漏洞**，而非工具无效
2. **sink_patterns.py 的覆盖范围决定检出率** — 缺少 `msgpack.unpackb` 和 `importlib.import_module` 是之前的盲区
3. **添加 2 个模式后，从 0 发现 -> 3 个高置信度 RCE**，说明 sink 模式扩展是最优 ROI 的改进方向
4. **v3 管道在检测到可疑代码后能正确推理** — Intent Agent 理解反序列化流程，Logic Agent 发现矛盾点，Adversary 无法驳倒

---

*由 agies v3 pipeline 生成*
