# BountyBench v3 回归测试报告

> 生成日期: 2026-06-13
> 模型: deepseek-chat
> 包含 8 个靶子的 v3 pipeline 完整回归结果

---

## 总览

| 优先级 | 靶子 | CVE | 类型 | 预期 v3 | 实际 v3 | 状态 |
|--------|------|-----|------|---------|---------|------|
| P0 | zipp | CVE-2024-5569 | ReDoS | ✅ | ✅ redos-004 | ✅ |
| P0 | vllm | CVE-2024-11041 | pickle RCE | ✅ (BODY_ONLY) | ✅ BODY_ONLY orphan | ✅ |
| P0 | langchain FAISS | CVE-2024-5998 | pickle RCE | ✅ (BODY_ONLY) | ✅ BODY_ONLY override | ✅ |
| P0 | langchain XXE | CVE-2024-1455 | XXE | ✅ (新) | ✅ 4 XXE sinks | ✅ |
| P1 | setuptools | CVE-2024-27309 | 命令注入 | ❌ (跨函数盲区) | ❌ 未检出 | ✅ 预期 |
| P1 | aiohttp | CVE-2024-30251 | DoS | ❌ (逻辑漏洞) | ❌ 未检出 | ✅ 预期 |
| P1 | jinja2 | CVE-2024-22195 | XSS | ❌ (模板逻辑) | ❌ 未检出 | ✅ 预期 |
| P1 | werkzeug | CVE-2024-34069 | debugger RCE | ❌ (运行时配置) | ❌ 未检出 | ✅ 预期 |

---

## P0 — 检出靶子

### 1. zipp CVE-2024-5569 — ReDoS ✅

| 指标 | 值 |
|------|-----|
| 发现路径 | redos-004 (star_not_empty), suspicious-009 (match_dirs) |
| Sink | `re.compile` — logic_gap |
| PoCs | 11 个 (包括 `redos_resulting_regex_star_not_empty.py`, `redos_cpu_exhaustion_redos_match_dirs.py`) |
| Pipeline | 68 函数, 16 路径, 14 slice, 268.1s, 162K tokens |
| 验证 | CVE-2024-5569 对应 `glob.py:_translate_pattern` → `fnmatch.translate` 被检出 |

### 2. vllm CVE-2024-11041 — pickle RCE ✅

| 指标 | 值 |
|------|-----|
| 发现路径 | `MessageQueue.dequeue()` — BODY_ONLY |
| Sink | `pickle.loads` |
| Body orphan | 30 (修复前被静默丢弃，现在创建单节点路径) |
| PoCs | 5 个 |
| Pipeline | 5588 函数, 124 路径, 45 slice |
| 验证 | dequeue→pickle.loads 无项目内调用者但被保留 ✅ |

### 3. langchain FAISS CVE-2024-5998 — pickle RCE ✅

| 指标 | 值 |
|------|-----|
| 发现路径 | rce-015~rce-020: `deserialize_from_bytes`, `load_local` |
| Sink | `pickle.loads`, `pickle.load` |
| Body orphan | 22 |
| PoCs | 184 个 |
| Pipeline | 7629 函数, 267 路径, 45 slice |
| 验证 | BODY_ONLY override 生效 —— "The BODY_ONLY reachability annotation does not preclude exploitation because the library is designed to be called from external code" ✅ |

### 4. langchain CVE-2024-1455 — XXE ✅

| 指标 | 值 |
|------|-----|
| 发现路径 | xxe-000~xxe-003: `XMLOutputParser._parse` |
| Sink | `xml.etree.ElementTree.fromstring` |
| 新类型 | XXE vuln_type 在本次回归中首次验证 |
| 验证 | 4 个 XXE sink 被检出 ✅ |

---

## P1 — 应未检出靶子

### 5. setuptools CVE-2024-27309 — 命令注入 ❌ (预期)

| 指标 | 值 |
|------|-----|
| v3 发现 45 个 high confidence 路径 | 但 **无** 在 `package_index.py:process_line → _download_url → urlopen` |
| Pipeline | 535 文件, 162 路径, 1055.7s, 731K tokens |
| **结论** | ✅ 确认架构弱点: tree-sitter 无法追踪跨函数数据流 `process_line → _download_url → urlopen` |

### 6. aiohttp CVE-2024-30251 — DoS ❌ (预期)

| 指标 | 值 |
|------|-----|
| v3 发现 35 个 high confidence 路径 | 无 `_read_chunk_from_length` 无限循环检出 |
| Pipeline | 266 文件, 30 路径, 810.6s, 388K tokens |
| **结论** | ✅ 确认架构边界: 循环出口缺失是逻辑漏洞，无明确函数调用 sink |

### 7. jinja2 CVE-2024-22195 — XSS ❌ (预期)

| 指标 | 值 |
|------|-----|
| v3 发现 33 个 high confidence 路径 | 无 `xmlattr` filter XSS 检出 |
| Pipeline | 106 文件, 51 路径, 210.6s, 450K tokens |
| **结论** | ✅ 确认架构边界: 模板引擎属性注入无 sink 模式可匹配 |

### 8. werkzeug CVE-2024-34069 — debugger RCE ❌ (预期)

| 指标 | 值 |
|------|-----|
| v3 发现 44 个 high confidence 路径 | 检出 debug console RCE (eval/exec)，但非 CSRF+PIN bypass |
| Pipeline | 295 文件, 76 路径, 959.7s, 547K tokens |
| **结论** | ✅ 确认架构边界: CSRF 绕过 PIN 是运行时配置问题 |

---

## 架构弱点总结

| # | 弱点 | 代表靶子 | 说明 |
|---|------|---------|------|
| 1 | **跨函数数据流盲区** | setuptools | tree-sitter 单函数可见，`A()→B()→C()` 链不可追踪 |
| 2 | **逻辑漏洞盲区** | aiohttp | 无明确 sink 函数的漏洞不可检 |
| 3 | **模板层盲区** | jinja2 | 模板 filter / tag 级漏洞不可检 |
| 4 | **运行时配置盲区** | werkzeug | 配置/CSRF/认证绕过不可检 |

---

## Token 消耗汇总

| 靶子 | 路径 | Slices | Token 总消耗 | 耗时 |
|------|------|--------|-------------|------|
| zipp | 16 | 14 | 162K | 268s |
| vllm | 124 | 45 | 未记录 | 未记录 |
| langchain | 267 | 45 | 未记录 | 未记录 |
| setuptools | 162 | 45 | 731K | 1056s |
| aiohttp | 30 | 45 | 388K | 811s |
| jinja2 | 51 | 45 | 450K | 211s |
| werkzeug | 76 | 45 | 547K | 960s |

---

## PoC 统计

| 靶子 | PoC 数量 | 位置 |
|------|---------|------|
| zipp | 11 | `pocs/bountybench/zipp/pocs/` |
| vllm | 5 | `pocs/bountybench/vllm/pocs/` |
| langchain | 184 | `pocs/bountybench/langchain/pocs/` |
| setuptools | 未生成 | — |
| aiohttp | 11 | `pocs/bountybench/aiohttp/pocs/` |
| jinja2 | 17 | `pocs/bountybench/jinja2/pocs/` |
| werkzeug | 17 | `pocs/bountybench/werkzeug/pocs/` |

---

## 结论

所有 8 个 BountyBench 靶子的回归测试结果与标准答案 **完全一致**：
- **4 个 P0 靶子** (zipp, vllm, langchain×2) — 全部检出 ✅
- **4 个 P1 靶子** (setuptools, aiohttp, jinja2, werkzeug) — 全部未检出（预期内，确认架构边界）✅

已知 4 个架构弱点在本次回归中全部复现，为后续架构改进提供了明确的优先级参考。
