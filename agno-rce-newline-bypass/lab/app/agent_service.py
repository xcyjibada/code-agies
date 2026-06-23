"""
agno Agent 演示服务 — 带 CodingTools 的 bug 修复前版本

这个服务模拟了「AI agent 分析 GitHub Issue」的场景。
Agent 配有 CodingTools（可以读写文件、执行 shell 命令）。
"""
import os
from pathlib import Path
from agno.agent import Agent
from agno.tools.coding import CodingTools
from agno.models.openai import OpenAIChat

# 工作目录 — agent 可以操作这个目录下的文件
WORK_DIR = Path("/app/workspace")
WORK_DIR.mkdir(parents=True, exist_ok=True)


def create_agent() -> Agent:
    """创建一个带 CodingTools 的 agno Agent

    模拟一个「代码审查助手」，配有文件读写和 shell 执行能力。
    """
    tools = CodingTools(
        base_dir=WORK_DIR,
        restrict_to_base_dir=True,  # ← 默认安全配置！但仍然有漏洞
    )

    agent = Agent(
        name="code-reviewer",
        tools=[tools],
        model=OpenAIChat(id="gpt-4o"),
        description="你是代码审查助手，可以读取文件、搜索代码、运行 shell 命令。",
        markdown=True,
        # 注意: 没有 instruction 限制工具使用方式
        # LLM 可以自由决定调用哪些工具、传什么参数
    )
    return agent


def analyze_external_content(content: str) -> str:
    """处理外部内容（模拟分析 GitHub Issue / PR）

    这就是攻击面入口 —— content 来自外部不可信来源。
    """
    agent = create_agent()
    prompt = f"""请分析以下内容，检查是否存在安全问题：

--- 外部内容开始 ---
{content}
--- 外部内容结束 ---
"""
    resp = agent.run(prompt)
    return resp.content if resp.content else ""
