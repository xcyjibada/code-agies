# Sandyaa Bug Report — Phase 2 JSON Parsing Failure

## 基本信息

- **项目**: SecureLayer7/sandyaa
- **问题类型**: Bug / 核心功能不可用
- **严重性**: Critical
- **影响范围**: Phase 2（systematic coverage）全部失败，`All JSON parsing attempts failed`

---

## 问题描述

Sandyaa 的两阶段架构中，**Phase 2（systematic coverage，系统全覆盖）完全不可用**。当 Phase 1 完成后用户选择继续扫描剩余文件时，每个分块的漏洞检测均显示：
```
All JSON parsing attempts failed
```
结果降级为"未发现漏洞"，不产出具分析结果的输出。

Phase 1（高优先级目标）正常工作，能发现高质量漏洞。

---

## 复现步骤

1. 准备一个大于 1000 个文件的项目（如 `service-platform`）
2. 运行：`npx sandyaa /path/to/target`
3. 等待 Phase 1 完成
4. 终端提示 `Continue with full codebase scan? (y/n):` **输入 y**
5. 观察 Phase 2 每个分块的输出，均无任何漏洞发现

### 复现环境

- sandyaa 版本: 最新 (commit 2026-04-14)
- Claude CLI: 已安装
- 操作系统: Linux
- 目标代码库大小: ~1296 个文件

---

## 根因分析

### 直接原因：`stream-json` 输出格式与解析器不兼容

在 `agent-executor.ts:336-339`，`_spawnCLI()` 使用以下参数调用 Claude CLI：

```typescript
const args = [
  '--dangerously-skip-permissions',
  '--verbose',
  '--output-format', 'stream-json',  // ← 关键问题
  '--model', modelMap[model],
  '--print',
  '--append-system-prompt', '...'
];
```

`--output-format stream-json` 格式产生的是**流式 NDJSON（Newline-Delimited JSON）事件**，而非单个完整的 JSON 文档。每个事件对应一个消息块的流式产出。

当 Claude 在分析过程中使用工具（tool_use）——如读取文件、搜索代码——时，输出流会包含交错的：

- `assistant` 事件（含 `text` 块和 `tool_use` 块）
- `tool_result` 事件（工具执行结果）
- 后续的 `assistant` 事件

### 解析器的根本缺陷

`parseStreamJsonOutput()`（`agent-executor.ts:468-516`）试图通过拼接所有 `assistant` 事件的 `text` 块来重建最终输出：

```typescript
// agent-executor.ts:506-511 —— 只提取 text 块
for (const block of content) {
  if (block.type === 'text' && block.text) {
    assistantText += block.text + '\n';
  }
}
```

但存在两个问题：

**问题 A：缺少 `tool_use` 块的处理**。当 Claude 使用工具时，助手消息的内容块包括 `tool_use` 类型。最终的结构化 JSON 输出（包含 `vulnerabilities` 数组）可能出现在 `tool_use` 块的 `input` 字段中，或在多次工具调用后被 Claude 输出在文本中。解析器只拼接 `text` 块，错过了关键数据。

**问题 B：缺少 `tool_result` 事件的处理**。`tool_result` 是流式输出中独立的事件类型（NDJSON 行），其 `type` 字段值为 `tool_result`，但当前解析器的 switch 逻辑（line 480-512）没有包含对 `tool_result` 的任何处理——它既不跳过这些行（会被 line 513-515 的 `catch` 静默忽略），也不提取其内容。

**问题 C：文本内容不包含有效 JSON**。即使拼接了所有 `text` 块，这些文本通常是 Claude 的推理过程（如"让我先读取这个文件"、"发现 63 个文件有相似的 import 模式——这是系统性问题"），而非结构化 JSON。当 `parseResponse()` 接收这些文本时，无法从中提取出有效的 `{ analyses: [...], vulnerabilities: [...] }` 结构。

### 为什么 Phase 1 能工作

Phase 1 的 `file-prioritization` 任务类型相对简单 —— Claude 只需要分析文件名列表和 metadata，不需要频繁调用工具读取文件内容。因此流式输出中 `text` 内容能包含 JSON 格式的输出。

Phase 2 的 `vulnerability-detection` 任务需要 Claude 读取每个源文件的完整内容去检测漏洞，这触发了大量的工具调用，导致最终输出结构中混合了大量工具调用事件，超出了当前解析器的处理能力。

---

## 影响的代码路径

### 关键代码

| 文件 | 行号 | 影响 |
|------|------|------|
| `src/agents/agent-executor.ts` | 339 | `--output-format stream-json` 参数选择 |
| `src/agents/agent-executor.ts` | 468-516 | `parseStreamJsonOutput()` 解析器 |
| `src/agents/agent-executor.ts` | 690-773 | `parseResponse()` 兜底解析（也无法处理推理文本） |
| `src/agents/agent-executor.ts` | 439-449 | 解析失败后的错误处理和降级逻辑 |
| `src/orchestrator/orchestrator.ts` | 690-706 | Phase 2 中调用 `this.detector.detect()` |
| `src/detector/vulnerability-detector.ts` | 374-425 | `detect()` 检查 `result.success` 和 `result.output.vulnerabilities`，当两者都不满足时返回 `[]` |

### 执行流程

```
orchestrator Phase 2 chunk
  → analyzer.analyze(chunk)          # 上下文构建（成功）
  → detector.detect(context)          # 漏洞检测
    → executor.execute({type: 'vulnerability-detection', ...})
      → executeViaCLI()               # _spawnCLI 调用 claude --output-format stream-json
        → parseStreamJsonOutput()      # 只能提取推理文本，不能提取结构化 JSON
          → parseResponse()             # 所有 JSON 解析尝试全部失败
            → return {success: false, output: null}
    → result.output = null
    → result.success = false
    → detect() 返回 []                # 空数组
  → "No vulnerabilities in this chunk" # 错误地报告无漏洞
```

---

## 建议修复方案

### 方案 A（推荐）：改用 `--output-format text`

将 `--output-format stream-json` 改为 `--output-format text`，并在系统提示词中明确要求 Claude 以 markdown JSON 代码块格式输出结构化结果。

**修改位置**: `agent-executor.ts:339`

```typescript
// 修改前
'--output-format', 'stream-json',

// 修改后
'--output-format', 'text',
```

**同时修改 `parseStreamJsonOutput()`**: 当输出格式为 `text` 时，`_spawnCLI` 返回的 `stdout` 直接是文本内容，可以直接传入 `parseResponse()`：

```typescript
// agent-executor.ts:439-449 退出分支
// 修改：使用 text 格式时，stdout 直接是纯文本
const parsed = this.parseResponse(stdout);
```

**优点**: Claude CLI 的 `text` 格式成熟可靠，配合结构化提示词可稳定产出 JSON。
**缺点**: 失去流式输出的实时性（但 sandyaa 当前代码并未使用流式特性）。

### 方案 B：实现完整的 NDJSON 流解析器

为 `stream-json` 格式实现一个完整的状态机解析器，追踪工具调用和结果之间的关联：

```
状态: IDLE → COLLECTING_TEXT → TOOL_PENDING → COLLECTING_RESULT → ...
```

需要处理的事件类型：
- `message_start` / `message_delta` / `message_stop`
- `content_block_start` / `content_block_delta` / `content_block_stop`
- `type: tool_use` 的 input 字段

**优点**: 保留 stream-json 的全部结构化信息。
**缺点**: 实现复杂；且 Claude CLI 的 `stream-json` 格式是非官方/实验性的，文档不完善。

### 方案 C：使用 Anthropic SDK 直接调用 API

`executeViaAPI()`（`agent-executor.ts:560-643`）已实现通过 Anthropic SDK 直接调用 Claude API 的路径，`--output-format stream-json` 的问题只出现在 `executeViaCLI()` 路径中。可以让 `vulnerability-detection` 类型的任务强制走 API 路径。

**修改位置**: `agent-executor.ts:127-132` 或 `_spawnCLI` 调用前的分支

**前提**: 用户需要设置 `ANTHROPIC_API_KEY`
**优点**: API 调用的响应格式是标准化的，`parseResponse()` 可以直接处理
**缺点**: 需要 API key，不能仅依赖 Claude CLI

---

## 附加问题：Phase 2 的代码重复

Phase 2 的代码（`orchestrator.ts:677-744`）几乎是 Phase 1 分析循环（`orchestrator.ts:318-645`）的完整复制粘贴，缺少递归验证、回归检测、POC 生成等关键步骤。建议重构为共享函数，减少维护负担。

---

## 补充材料

运行 sandyaa 时保存的原始 Claude CLI 输出文件示例（位于 `.sandyaa/tasks/` 目录）。这些文件内容显示 Claude 输出了有价值的分析内容，但 sandyaa 解析器无法提取：

```
# 保存的原始输出中的部分内容（stream-json 格式）：
{"type":"assistant","message":{"content":[{"type":"text","text":"I'll analyze these files for vulnerabilities..."},{"type":"tool_use",...}]}}
{"type":"tool_result",...}
{"type":"assistant","message":{"content":[{"type":"text","text":"Found 63 files with similar import patterns — this is systemic. Let me check the key files..."}]}}
```

而期望的输出应该是：

```json
{
  "vulnerabilities": [
    {
      "type": "Permission Bypass",
      "severity": "high",
      "location": { "file": "...", "line": 42 },
      "attackerControlled": { "isControlled": true, ... },
      "evidenceChain": [...]
    }
  ]
}
```

---

*如需我提供原始的 Claude CLI 输出文件以协助调试，请告知。报告基于 2026 年 5 月在 `service-platform` 项目上的实际运行测试。*
