Hybrid Call Graph + 选择性展开（最推荐立即实施）
用 tree-sitter + NetworkX 构建完整调用图（静态为主）。
Director 层先用 PageRank / Centrality 找出高风险路径。
只对高优先级路径做 LLM 深度分析（例如只展开前 3-5 层调用链）。
好处：大幅减少 token，但能覆盖大部分跨函数场景。

On-Demand Context Slicing（上下文切片）
当发现一个潜在 Sink 时，自动向上回溯调用者（Callers），提取相关数据流上下文。
使用程序切片（Program Slicing）技术，只把真正相关的代码片段喂给 LLM，而不是整个函数或文件。
这能显著降低 token 消耗，同时提升跨函数理解能力。

Multi-Agent 分层调用链分析
Tracer Agent：负责沿着调用链追踪污点传播。
Validator Agent：验证某条路径是否真正可达 + 可触发。
Summarizer Agent：把长调用链总结成简洁的“攻击路径描述”。

中长期更强方案（参考最新研究）
参考 PacVD、CTX-Coder、SemTaint 等论文：用 LLM 辅助生成 taint specification（污点规格），然后用确定性引擎做跨过程分析。
或者学习 RepoAudit 的做法：Agent 带 Memory，按需探索路径，而不是一次性喂巨大上下文。