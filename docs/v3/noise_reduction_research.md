# 静态分析去噪技术调研

> 调研日期：2026-05-30
> 背景：agies v2 的 Joern 调用图在 mlflow Java 项目上提取到 13K 方法、1,850 条内部调用边，其中 95% 是 protobuf
> 生成代码的 Builder 样板。需要系统的去噪方法来聚焦真正有安全价值的路径。

---

## 一、论文

### 1.1 OriginPruner — 方法起源调用图剪枝

- **论文**: [OriginPruner: Leveraging Method Origins for Guided Call Graph Pruning](https://arxiv.org/abs/2412.09110) (2024.12)
- **思路**: 利用"方法起源"（method origin）裁剪调用图。每个方法签名在类继承链中首次出现的位置称为 origin，派生的覆写调用基本都是局部的，可以安全剪掉。
- **效果**: Top-1 起源方法（`Iterator.next`）剪掉 ~14% 边；Top-1000 剪掉 ~58%。
- **优点**: 纯静态，无需 ML，计算开销接近零。
- **对我们的意义**: protobuf 的 `setX → build → mergeFrom` 全是同一个 origin 的派生调用，可以直接剪掉。

### 1.2 ML-based Call Graph Pruning (MSR'24)

- **论文**: [On the Effectiveness of Machine Learning-based Call Graph Pruning: An Empirical Study](https://arxiv.org/abs/2402.07294) (2024.02)
- **对比方法**: CGPruner（结构特征 ML）、AutoPruner（CodeBERT 语义 + 结构）、1-CFA（传统上下文敏感分析）
- **效果**:
  - ML 剪枝：精度 +25%，召回 -9%，图缩小 69%，分析加速 3.5x
  - 下游安全分析：**< 2% 漏报**，**5 倍加速**
- **局限**: ML 方法提升精度但牺牲召回率，不适合安全场景的"宁可误报不可漏报"要求。

### 1.3 ZeroFalse — LLM + 静态契约去噪

- **论文**: [ZeroFalse: Improving Precision in Static Analysis with LLMs](https://arxiv.org/abs/2510.02534) (2025.10)
- **思路**: 用结构化契约（structured contracts）增强静态分析输出，结合流敏感追踪 + 上下文证据 + CWE 专属知识。
- **效果**: F1 = 0.912（OWASP Java Benchmark），0.955（OpenVuln）。
- **关键发现**: CWE 专属提示词显著优于通用提示词；推理型 LLM 的精确率-召回率平衡最好。

### 1.4 LLM4PFA — 工业级 LLM 误报消除 (Tencent)

- **来源**: [Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry](https://ar5iv.labs.arxiv.org/html/2601.18844)
- **背景**: 企业静态分析告警中 **>90% 是误报**，每条人工审核需 10-20 分钟
- **方案**: LLM + 静态分析混合（hybrid）
- **效果**: 消除 **94-98% 误报**，每条成本 $0.0011-$0.12，比人工审核便宜 1-2 个数量级
- **最佳模型**: Claude-Opus-4, GPT-4o, DeepSeek-R1, Qwen-3-Coder

---

## 二、工具

### 2.1 Aikido 可达性引擎

- **文档**: [Reachability engine to remove false positives](https://help.aikido.dev/general-information/reachability-engine-to-remove-false-positives)
- **思路**: 构建轻量级调用/依赖图，从入口点追踪到漏洞锚点是否真实可达
- **三层可达性**:

| 类型 | 范围 | 问题 |
|------|------|------|
| 依赖级 | SCA | 项目是否调用了漏洞函数？ |
| 函数级 | SAST | 不可信输入能否流入危险 sink？ |
| 运行时上下文 | 构建/运行时 | 代码在实际运行时是否执行？ |

- **保守下近似**: 只有在高置信度时才标记为不可达，动态特性（反射、元编程）导致无法判断时保留告警
- **效果**: 内部评估显示可发现"约 2 倍"的额外误报

### 2.2 Semgrep Assistant

- **文档**: [Announcing an AI AppSec engineer that users agree with 95% of the time](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories/)
- **方案**: 确定性 SAST + LLM 后处理
- **效果**: 开箱滤掉 ~20% 误报，95% 用户同意率，96% 专家同意率
- **策略栈**: Pro 规则 → 跨文件分析 → AI 去噪 → 路径排除

---

## 三、去噪技术全景

| 层次 | 技术 | 代表 | 效果 |
|------|------|------|------|
| **文件级** | 按路径排除生成代码 / vendor / test | `.pb.cc`, `node_modules`, `test/` | 减少 30-50% 噪音 |
| **调用图级** | 方法起源剪枝 | OriginPruner | 减少 58% 边 |
| **调用图级** | ML 语义剪枝 | AutoPruner (CodeBERT) | 69% 更小 + 3.5x 加速 |
| **可达性** | 从入口点追踪可达路径 | Aikido Reachability | 消除大部分不可达告警 |
| **告警级** | LLM 语义去噪 | Semgrep Assistant, ZeroFalse | 消除 94%+ 误报 |
| **混合** | LLM + 静态契约 | ZeroFalse, LLM4PFA | F1 > 0.91 |

## 四、对我们 v3 的启示

1. **OriginPruner 的思路可以直接用在 Joern CPG 上** — protobuf 的 `setX → build → mergeFrom` 是典型的多态派生调用，按 origin 聚类后可以整体剪掉
2. **Aikido 的三层可达性最值得参考** — 我们目前只有"入口点"概念，没有系统做"函数是否真实可达"的判断
3. **先规则剪枝 + LLM 语义去噪**是当前业界 gold standard — agies 已经在走这个方向（SAST → bulk → verification），但具体算法需要跟上论文水平
4. **CWE 专属知识**能显著提升 LLM 去噪精度 — 在 verifier prompt 中对不同 CWE 使用不同的分析模板
