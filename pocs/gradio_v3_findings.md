# Gradio v3 Pipeline 扫描报告

**日期**: 2026-06-28  
**模型**: deepseek-chat  
**目标**: gradio-app/gradio (3,935 函数, 1,087 文件)  
**耗时**: 175.8s  
**Token 消耗**: 788,201 total (693,657 prompt + 94,544 completion)

---

## 统计

| 指标 | 值 |
|------|-----|
| Paths discovered | 148 |
| Slices analyzed | 45 |
| High confidence findings | 30 |
| Interesting findings | 8 |
| Assumptions collected | 280 (268 violable) |
| LLM-discovered sinks | 22 |

## 漏洞类型分布

| Type | Sinks | High |
|------|-------|------|
| RCE (Remote Code Execution) | 25 | 13 |
| LFI (Local File Inclusion) | 32 | 3 |
| SSRF (Server-Side Request Forgery) | 29 | 6 |
| SQLI (SQL Injection) | 12 | 1 |
| AFO (Arbitrary File Overwrite) | 6 | 1 |
| ReDoS (Regular Expression DoS) | 20 | 1 |
| SSTI (Template Injection) | 21 | 0 |
| Suspicious | 21 | — |

## 关键发现

### RCE
- `_install_command` / `_install_to` / `_install_hf_gradio_to` / `_install_space_skill` — pip install 命令拼接，用户可控包名
- `trimVideo` — subprocess/ffmpeg 命令注入
- `createLatexTokenizer` / `createMermaidTokenizer` — matplotlib LaTeX `\write18` RCE
- `parse_css_vars` — CSS 变量正则解析可能被利用

### LFI
- `file` — path.read_bytes() / open 无路径校验
- `load_manifest` / `load_totals` / `load_processes` — 文件读取
- `_tiny_wav_path` — 音频文件路径构造

### SSRF
- `space_exists` / `fetch_space_info` / `fetch_space_runtime` — HuggingFace Spaces API 调用
- `_do_analytics_request` / `_download_from_hub` / `_fetch_curated_from_hub` — 用户可控 URL → requests/httpx
- `make_request` / `_hf_request` — 通用请求转发

### 其他
- AFO: `cleanup_files` — 文件删除/写入操作
- SQLI: `execute` — SQL 执行
- ReDoS: `_clean_content` — 正则用户可控

## PoC 状态

v3 PoC Agent 有已知 bug（`"success"` 字符串被误认为错误），故本次无自动 PoC 生成。
上一次扫描的 PoC 保留在 `pocs/gradio_src/`，涵盖 LFI/RCE/SSRF 三类。

## 修复的 Bug

扫描过程中发现 `enrich_paths` 在处理超大函数体（`create_app`: 84K 字符）时因正则回溯导致无限卡死。
已在 `dataflow.py:match_call_to_params` 中修复：超过 5K 字符的函数体跳过正则匹配，改用 `str.find()`。
