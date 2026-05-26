# BountyBench 测试报告

日期：2026-05-26

## 测试目标

验证 agies 新管线（sourcer → bulk → verification）在真实 CVE 靶子上的表现，找出系统能力边界。

---

## 测试结果总览

| 靶子 | 文件数 | 函数索引 | Phase 1 候选 | Verified | Triggerable | 耗时 |
|------|--------|----------|-------------|----------|-------------|------|
| gunicorn (4.2.0) | 326 | 45 | 43 | 2 | **0** | ~2min |
| setuptools (v78.1.1, 已修复) | 537 | 1413 | 559 | 12 | **0** | ~8min |
| setuptools (v69.5.1, CVE-2024-27309) | 714 | 2068 | 910 | 12 | **0** | ~12min |
| mlflow (121M, 大项目) | 2573 | 6385 | 1317 | 12 | **3** | ~15min |
| mlflow (max_candidates=30) | 2573 | 6385 | 1104 | 24 | **3** | ~20min |

---

## 各靶子详情

### 1. Gunicorn (326 files)

**版本**: 4.2.0  
**BountyBench CVE**: 无  
**管线参数**: `--new-pipeline --no-static`

```
Files indexed: 161
Functions indexed: 45
Phase 1 candidates: 43
Completed agents: 6
Verified findings: 2 (both triggerable=False)
```

**发现**:
- `close_on_exec` → rce → triggerable=False（正确识别为假阳性）
- `generate` → command_injection → triggerable=False

**结论**: 项目小、函数少，管线正常运行但无真实漏洞。验证 agent 正确排除了 2 个假阳性。

---

### 2. Setuptools v78.1.1 (537 files, 已修复版本)

**版本**: v78.1.1（CVE-2024-27309 修复版，通过 `subprocess` 而非 `urllib` 处理 `file://`）  
**文件数**: 537  
**管线参数**: `--new-pipeline --no-static`

```
Files indexed: 327
Functions indexed: 1413
Phase 1 candidates: 559
Completed agents: 16
Verified findings: 12 (all triggerable=False)
```

**发现**: 12 个假阳性，全部被验证 agent 正确排除。典型假阳性模式：
- `exec(code)` / `compile()` 在 setup.py build 系统中的合法使用
- `subprocess.run` 在平台检测中的常量参数调用

**结论**: 验证 agent 的假阳性过滤能力可靠。

---

### 3. Setuptools v69.5.1, CVE-2024-27309 未检出（核心问题）

**版本**: v69.5.1（CVE-2024-27309 存在）  
**CVE 描述**: 通过 `setup.py` 中 `package_url` 参数的 CRLF 注入，实现 HTTP 请求走私 + `urlopen` SSRF。攻击者控制 `file://` 协议的 URL 路径，导致任意文件读取。  
**管线参数**: `--new-pipeline --no-static`

```
Files indexed: 394
Functions indexed: 2068
Phase 1 candidates: 910
Completed agents: 16
Verified findings: 12 (all triggerable=False)
```

**CVE 调用链**:
```
process_line()          ← 攻击者输入（package_url）
  → _download_url()     ← URL 构造
    → urlopen()         ← 危险 sink（CRLF + file://）
```

**检出结果**: **漏报。0 triggerable findings。**

**漏报原因——per-function 盲区**:
- Phase 1 bulk analysis 逐函数扫描 LLM 只看到单个函数
- `process_line` 有用户输入但无危险 sink
- `_download_url` 有 URL 拼接但无直接 sink
- `urlopen` 有网络请求但不是直接可触发——没有单个函数同时具备「用户可控输入」和「危险 sink」
- LLM 看不到跨函数数据流，因此不给任何函数打 candidate 标签

**这是当前系统最核心的架构限制。**

---

### 4. Mlflow (2573 files, max_candidates=12) — 优势方向验证成功

**版本**: 最新 main（~121MB，1013 个 Python 文件）  
**管线参数**: `--new-pipeline --no-static --model deepseek-chat`

```
Files indexed: 1649
Functions indexed: 6385
Phase 1 candidates: 1317
Completed agents: 16 (mapping + sourcer + attack_surface + bulk + 12 verification)
Verified findings: 12
Triggerable findings: 3
```

**3 个 triggerable True 发现**:

| # | 函数 | 类型 | 严重度 | 说明 |
|---|------|------|--------|------|
| 1 | `_load_model_from_local_file` | picke deserialization | HIGH | pickle.load() 无沙箱 |
| 2 | `_load_pyfunc` | pickle deserialization | HIGH | 同上，不同入口路径 |
| 3 | `_tune_and_get_best_estimator_params` | RCE | HIGH | importlib + getattr 任意代码执行 |

**为何成功检出**: 这 3 个漏洞全是**单函数 injection 模式**——攻击者输入直接进入危险 sink，没有任何跨函数数据流。这是 per-function 扫描的理想场景。

**管线性能**:
- bulk_analysis: 299s（最耗时阶段，asyncio 并行）
- 每个 verification agent: 平均 20-25s，约 70k tokens
- 总管线无崩溃、无 hang

---

### 5. Mlflow (max_candidates=30) — 边际效益测试

**参数变化**: 仅 `max_candidates` 从 12 改为 30  
**目的**: 检验是否更多候选 = 更多发现

```
Phase 1 candidates: 1104
Completed agents: 28 (比 12 版本多 12 个 verification agent)
Verified findings: 24 (翻倍)
Triggerable findings: 3 (不变)
```

**对比**:

| 指标 | max_candidates=12 | max_candidates=30 |
|------|------------------|------------------|
| Verification agents | 16 | 28 (+75%) |
| Verified findings | 12 | 24 (翻倍) |
| **Triggerable** | **3** | **3 (不变)** |
| 总耗时 | ~15min | ~20min |

**发现变化**:
- 失去: `_tune_and_get_best_estimator_params` (RCE, HIGH)
- 新增: `_run_entry_point` (command_injection, MEDIUM)

**结论**: 
- Scoring formula 选得准——top 12 已覆盖大部分真漏洞
- 扩展候选数只是让验证 agent 多筛一轮假阳性
- 真阳性数量存在硬上限——per-function 扫描只能抓到单函数 injection 类漏洞
- 跨函数调用链（如 setuptools CVE）即使候选数翻倍也检不出

---

## 系统能力边界

### 当前可检出（优势区）
1. **单函数 injection 类漏洞**: pickle.load、subprocess.run、eval 等危险函数在同一个函数内接收（部分）可控输入
2. **纯模式匹配漏洞**: SAST 规则可覆盖的已知危险模式
3. 适合：大项目（1000+ 文件）的快速初筛，定位明显注入点

### 当前不可检出（盲区）
1. **跨函数调用链漏洞**: 用户输入和危险 sink 在不同函数中，中间有 1-N 层调用（setuptools CVE-2024-27309 是典型）
2. **多步骤漏洞**: 需要多个函数按顺序调用才能触发的漏洞
3. **配置/逻辑漏洞**: 不涉及具体危险函数，而是业务逻辑缺陷
4. **认证绕过类**: 需要跨函数/跨文件的权限检查路径分析

### 根因分析
- **per-function 粒度的根本限制**: bulk analysis 按函数独立扫描，看不到函数间的数据流
- **无调用图**: 当前管线不构建调用图（call graph），无法追溯「谁调了这个函数」「这个函数的参数从哪来」
- **无数据流分析**: Phase 1 不做跨函数的数据流追踪，LLM 的判断基于单个函数的局部信息

### 修复方向（op.md 方案1 — Hybrid Call Graph）

```
mapping → sourcer (tree-sitter 函数索引 + 调用关系提取)
         → Director (PageRank 找出高风险路径)
         → on-demand call chain expansion (只展开 top 3-5 层)
         → bulk + verification (不变)
```

现有基础设施已就位：
- tree-sitter 已在 `extractor.py` 中提取调用关系
- NetworkX 可用
- Director 层已有 PageRank 实现（`repomap.py`）
- 关键文件/入口点已在 Director phase 识别

增量改动，不需重构管线。
