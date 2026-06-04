# op.md 技术批评回顾与采纳记录

> 日期：2026-06-03
> 用途：记录 op.md 两轮技术批评的分析结论、采纳/不采纳决策及理由。
> 对应修订：见 `plan.md` 头部修订记录表。

---

## 第 1 轮批评（原 op.md — 4 个致命瓶颈）

### 1. 编译屏障

**原文**：CodeQL database create 对 Java/C++ 成功率极低 → 80% 的项目会在第一步卡死。

**分析结论**：成立。Python/JS/TS 纯静态建库 ≈100%，Java 依赖 mvn/gradle 环境，实战确实不可靠。

**采纳**：✅ `plan.md` 发现 6 增加语言可行性分级表。P1 实现时优先验证 Python/JS。

### 2. Sanitizer 降权盲区

**原文**：`score *= 0.5 if has_validation` 是逻辑漏洞——高价值 0-day 往往是 sanitizer bypass，不是"没有校验"。

**分析结论**：完全成立。之前的排序算法结构性惩罚了最有价值的路径。这是我（Claude）自己 review 时也没发现的问题。

**采纳**：✅ 改为 `score += 0.2`，并在 Top K 策略中增加 `[BYPASS_TARGET]` 标记，确保这些路径优先进入分析。

### 3. Extractor 多语言脆弱性

**原文**：tree-sitter 对 Java 匿名内部类、Lambda、TS 装饰器提取可能不完整，导致 LLM 幻觉。

**分析结论**：真实存在，但影响程度取决于目标语言。Python/JS 上问题不大，Java 上可能需要 fallback。

**采纳**：✅ 回退方案中增加"extractor 输出少于 10 行或括号不闭合 → 读取 ±30 行"的兜底逻辑。

### 4. 缺乏动态沙箱验证

**原文**：Phase F 只到"LLM 确认"，但 bounty 审核要求实际运行 PoC 拿到回显。

**分析结论**：对 bounty 场景成立，对通用漏洞发现场景不必须。不应作为核心管线的一部分。

**采纳**：✅ 新增 Phase F.5，作为 `--sandbox-verify` 可选步骤。不影响核心管线完整性。

---

## 第 1.5 轮 — 架构讨论中发现的额外问题

### 5. 评分模型确认偏误（Explore/Exploit 分离）

**发现过程**：讨论非标准 sink 时意识到——评分模型只偏好已知 sink，低权重 sink（0.3）的路径无论多危险都被压在 Top K 之外。

**分析结论**：这不是调权重能解决的。你不知道奇怪的 sink 叫什么，无法提前给它高分。

**采纳**：✅ Top K 选择中增加 Explore 槽（5 条），用 `is_anomalous()` 平行筛选"反常路径"。

### 6. Verification Agent token 放大器效应

**发现过程**：估算 v3 pipeline token 消耗时发现。

**分析结论**：Verification Agent 占 ~50% 总 token 消耗（~180K in），远高于 Phase D 路径分析。plan.md 对此没有预估。

**采纳**：⚠️ 加入"需要验证的假设"第 5 条，P10 调优时实测。暂不改架构。

---

## 第 2 轮批评（新 op.md — 论文推荐）

### 7. CPRVul 结构化推理

**原文**：CPRVul (2026) 提出 Context Profiling + Structured Reasoning（4 步推理链），显著提升跨函数漏洞检测的 F1。

**分析结论**：Structured Reasoning prompt（数据流→sanitization→bypass→impact）是 v3 当前 prompt 的明确改进，可以直接抄，不改架构只改文本。

**采纳**：✅ 替换 Phase D 的 `build_agent_prompt` 为 4 步推理链格式。保留 VulnHuntr bypass 示例作为 Step 3 的参考材料。

### 8. Bridging CPG + LLM（LLM 自己写 CodeQL 查询）

**原文**：让 LLM Agent 生成/优化 CPGQL 查询，而不是只消费固定查询的结果。

**分析结论**：有启发性但工程成本高，且不一定比 Explore 槽 + 局部后向追踪效果好。需要 LLM 生成合法 QL 语法，新增 execute_query 工具，处理查询失败。

**采纳**：❌ 暂不采纳。如果 P10 调优发现 Explore 槽不足以覆盖非标准 sink，再重新考虑。

### 9. 学术方向验证

**原文**：CPRVul 的 Context Profiling + Selector + 路径切片 + 多 Agent 架构与 v3 高度一致。

**分析结论**：v3 的架构被 2026 年 SOTA 论文验证了方向正确。不需要修改，但值得记录。

**采纳**：✅ 确认 v3 架构方向正确，无需修改。

---

## 未采纳意见汇总

| 意见 | 原因 |
|------|------|
| LLM 自主写 CodeQL 查询 | 工程成本高，收益不确定 |
| PageRank 剪枝（原 op.md 第 1 版） | 已改用 CodeQL 路径穷举，不需要图级剪枝 |
| 基础模式检测增强（原 op.md 第 1 版） | v2 SAST 规则已有 |

---

## 关键认知更新

两次 op.md 批评 + 讨论带来的核心认知变化：

1. **Bounty 市场的残酷性**：不是"找到漏洞 → $1,500"，是**"第一个找到的人 → $1,500，其他人 → Duplicate → $0"**。这改变了 v3 的策略定位——"先发优势"比"挖掘深度"更重要。

2. **CVE 补丁遗漏模式不可持续**：在 llama-index 上已被多人多轮扫过，大部分 Duplicate。但方法论（多项目 × 多 sink 类型的地毯扫描）仍有效。

3. **评分模型的确认偏误是架构问题**：不是调参数能解决的，需要平行的 Explore 管道。这是 v3 架构学到的最大教训。

4. **结构化推理 > 自由发挥**：CPRVul 的 4 步推理链比 VulnHuntr 的单轮 prompt 在实际效果上更可靠。Prompt 工程值得投入。
