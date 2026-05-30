# Xint 类 CLI 审计工具讨论记录

日期：2026-05-05

---

## 对话背景

基于 `cahe.md`（关于 Xint Code、Claude Code 架构和 AI 代码审计工具开发的研究记录），进一步深入讨论了如何构建一个 Xint 类似的 AI 原生 CLI 审计工具。

---

## 关键讨论点

### 1. 记忆系统（Memory）

Claude Code 的记忆系统基于磁盘文件存储，关闭重启后仍然存在。只保存"精选"的关键信息（技术决策、偏好、项目方向），普通对话不会自动沉淀为记忆。

### 2. LangGraph 与 CLI 的适配性

LangGraph 本质是状态机框架，核心逻辑是：
```
LLM → 输出 tool_call JSON → 解析执行 → 结果喂回 LLM → 循环
```

LangGraph 对 CLI 来说偏重。实际的 Agent 循环只需 30-50 行 `while True`。LangGraph 在产品化阶段可能需要剥离，但原型阶段省事。

### 3. Claude Code 为什么用 TypeScript 而不用 Python

不是因为框架生态（LangChain/LangGraph），而是因为：

| 需求 | 原因 |
|------|------|
| 终端交互 UI | Ink (React for terminal)，Python 无替代品 |
| MCP 协议 | Anthropic 自定协议，TS SDK 官方维护 |
| LSP 集成 | TS 原生支持，Python 需额外适配 |
| 跨平台分发 | Bun 打包单文件，Python 需用户自装环境 |
| 团队背景 | Anthropic infra 团队偏 JS 生态 |

LangGraph 解决的是 Agent 循环中最简单的部分（~50 行），Claude Code 真正的复杂度在其余 29,000 行基础设施中。你的审计 Agent 不需要这些复杂度。

### 4. Agent 工具执行机制

核心流程：

```
第 1 步：开发者定义工具列表（name + JSON Schema）传给 LLM API
第 2 步：LLM 返回结构化 JSON（tool_call），包含 name 和 arguments
第 3 步：开发者代码做 if/else 根据 name 分发到对应函数执行
第 4 步：执行结果放回 messages，继续循环
```

外层 JSON 格式一致（name + arguments），内层每个工具 arguments 结构不同。

### 5. Agent 循环（自动触发机制）

```python
def agent_loop(task):
    messages = [{"role": "user", "content": task}]
    while True:
        response = llm.chat(messages, tools=tool_defs)
        if response.stop_reason == "tool_use":
            # 执行工具，结果追加回 messages，自动进入下一轮
            continue
        elif response.stop_reason == "end_turn":
            return response.content  # LLM 主动决定完成
```

- **触发**：用户给初始任务 → while 开始
- **自动连续**：tool_call → 执行 → 结果追加 → continue → 下一轮，无人参与
- **终止**：LLM 不再返回 tool_call，返回 end_turn

### 6. Xint 与 Claude Code 的本质区别

| 维度 | Claude Code | Xint Code |
|------|-------------|-----------|
| 模式 | 人领着走 | 全自主 |
| 范围 | 用户指定文件 | 自己规划攻击面 |
| 验证 | 报告问题 | PoC 验证后才确认 |
| 管线 | 单次调用 | 多阶段递进 |

CC 能审计是因为人帮它缩小了范围，Xint 难在从百万行代码自主定位漏洞路径。

### 7. Xint 核心算法推测

推测的多阶段管线：

```
阶段 1：攻击面建模
  → 读项目结构、Makefile、入口点
  → 识别"哪些子系统处理外部输入"
  → 输出：[crypto/splice接口, 网络协议栈, 文件系统...]

阶段 2：安全语义提取
  → 理解每个模块的"安全约定"
  → 读函数注释、commit message、调用约定
  → 输出："output buffer不应与页缓存共享"

阶段 3：违反检测
  → 数据流追踪 + LLM 推理
  → 找代码路径是否违反约定
  → 输出：splice() 映射到文件页缓存 → 漏洞

阶段 4：可利用性验证
  → LLM 写 PoC → Docker 沙箱执行
  → 输出：能实际触发的 PoC
```

核心不是"LLM 多聪明"，而是**管线设计**——每个阶段有独立的 prompt、工具集、上下文窗口。阶段 1 只看目录结构，阶段 3 拿到的是精确定位的几百行代码。

### 8. Xint 与 CC 的关键差异（项目定位）

| | CC | 你的工具 |
|---|---|---|
| 审计范围 | 用户指定文件 | 自己规划攻击面 |
| 推理深度 | 一次调用，模式匹配 | 多阶段递进验证 |
| 结论 | 报告问题 | PoC 验证后才确认 |
| 自主性 | 人在回路 | 全自主 |

差异化优势在管线架构，不在 LLM 能力本身。

---

## 技术栈决定

- **语言**：Python（已有基础）
- **Agent 框架**：LangGraph（原型阶段）
- **LLM**：Claude API 或 OpenAI API
- **沙箱**：Docker SDK（Python docker 包）
- **代码解析**：tree-sitter
- **搜索**：ripgrep（rg）
- **不用**：向量数据库、Kubernetes、自部署 LLM

## 市场切入策略

不直接对标 Xint 做通用代码审计，而是切入垂直领域：
- 智能合约审计
- LLM 应用安全（Prompt Injection、Agent 权限）
- 业务逻辑漏洞（IDOR/BFL）

---

## 参考开源项目

| 项目 | 定位 |
|------|------|
| Sandyaa | 自主审计 Agent，RLM 递归分析，PoC 验证 |
| DeepAudit | 多 Agent 审计系统，4 个 Agent 协作 |
| Security Advisor | Claude Code 技能，轻量安全审计 |
| Cyber Neo | Claude Code 技能，11 个安全域 |
| KCode | 确定性 SAST + LLM 验证 |
| Vulnhalla | CodeQL + LLM，误报降低 96% |
| Augur | 符号执行 + LLM 混合 |
