# Hugging Face Transformers v3 Pipeline 扫描报告

**日期**: 2026-06-28  
**模型**: claude-sonnet-4-6  
**目标**: huggingface/transformers (2,823 Python 文件)  
**模式**: --all-paths（全路径 LLM 审核，不过滤）  
**耗时**: 4102.7s (~68 分钟)  
**Token 消耗**: 7,085,185 total (5,258,313 prompt + 1,826,872 completion)

---

## 统计

| 指标 | 值 |
|------|-----|
| Paths discovered | 207 |
| Slices analyzed | 207 (全部) |
| High confidence findings | 87 |
| Interesting findings | 90 |
| Adversary rebutted | ~40 |
| Not rebutted（最可信） | 14 |
| **沙箱验证通过** | **2** |

---

## 沙箱验证结果 — 新发现的漏洞

### ⭐ CVE-2026-XXXX（待申请）: SSRF in `load_image` / `read_video` / `load_audio_as`

| 项目 | 值 |
|------|-----|
| **类型** | SSRF（服务端请求伪造） |
| **位置** | `src/transformers/image_utils.py:486` |
| **代码** | `httpx.get(image, timeout=timeout, follow_redirects=True)` |
| **CVE 覆盖** | **无** — CVE-2025-3777 修的是 URL startswith 绕过（`http://youtube.com@evil.com`），不是 SSRF；TGI 的 SSRF CVEs 是独立 Rust 代码库，非 Python transformers |
| **影响函数** | `load_image()`、`read_video()`、`load_audio_as()` 三个核心工具函数 |
| **影响** | 云元数据窃取（`169.254.169.254`）、内网端口扫描、内部服务探测 |
| **攻击入口** | 所有接受图片/视频/音频 URL 的 pipeline（image-classification、VQA、ASR、text-to-image 等） |
| **验证结果** | ✅ 沙箱中 `load_image("http://127.0.0.1:18888/internal/admin")` → 内部 HTTP 服务收到请求 |
| **版本** | `5.13.0.dev0` (commit 4fd7f1a, 2026-06-27) — 最新版 |

**漏洞详情**:
`load_image()` 接受字符串参数时，仅检查是否以 `http://` 或 `https://` 开头，就直接调用 `httpx.get(url, follow_redirects=True)` 获取。**无 host 白名单、无 IP blocklist、无 redirect 限制**。攻击者可通过 pipeline API 传入任意 URL，触发服务端向内网/云元数据端点发起请求。`follow_redirects=True` 允许通过外部跳转到内网地址绕过基础 URL 检查。

**SSRF 攻击路径**:
```
用户 → pipeline(image="http://169.254.169.254/latest/meta-data/")
     → load_image()
     → httpx.get("http://169.254.169.254/latest/meta-data/", follow_redirects=True)
     → AWS IAM 凭证泄露
```

**现有 CVE 对照**:
| 引用 | 代码库 | 与本发现关系 |
|------|--------|------------|
| CVE-2025-3777 (Low) | Python transformers | 修的是 URL startswith 绕过，**不涉及 SSRF 无校验问题** |
| TGI SSRF (CVSS 8.6-9.8) | Rust text-generation-inference | 独立代码库，非 Python transformers |
| **本发现（无 CVE）** | **Python transformers** | **`load_image/read_video/load_audio_as` 三个函数 SSRF，无 host 校验** |

### LFI via `load_image` 本地文件读取

| 项目 | 值 |
|------|-----|
| **位置** | `src/transformers/image_utils.py:487-488` |
| **代码** | `elif os.path.isfile(image): image = PIL.Image.open(image)` |
| **验证** | ✅ `load_image('/tmp/test_secret_image.png')` 成功读取 |
| **限制** | 仅限有效图片文件 |
| **影响** | 读取服务器上任意图片文件 |

---

## Adversary Agent 无法驳斥的其他发现

### 3. SSRF via `httpx.get` 多路径（ssrf-093/094/095）
- pipeline 级别的用户可控 URL → `httpx.get()`，同样 `follow_redirects=True`
- **Adversary**: "Lack of any host validation or redirect restriction"

### 4. `download_and_unzip` zip slip（afo-129）
- tarfile/zipfile 文件名未经路径校验直接解压
- **Adversary**: "The attacker controls both the archive contents and the extraction path"
- ⚠️ 位于转换脚本中（nemo/marian），非公开 API

### 5. `apply_chat_template` audio 路径读取（suspicious-206）
- `apply_chat_template` 中 `maybe_path` 直接传入 `load_audio_as()` → 读取本地文件
- 但需要是有效音频文件（SoundFile 解码），**实际影响有限**

---

## Adversary 成功驳斥的典型模式

| 模式 | 驳斥原因 |
|------|---------|
| `torch.load` pickle RCE via `convert_model` | `convert_model` 是离线转换脚本，非网络暴露端点 |
| `subprocess.run` with list form | 无 `shell=True` |
| Synthetic web wrapper | 扫描器构造的 `[SYSTEM WRAPPER]` 不在实际代码中 |
| `apply_chat_template` SSTI | 系统模板非用户可控 |

---

## 已知问题

1. **PoC Agent bug**: `"success"` 字符串被误认为错误，所有自动 PoC 生成失败
2. **库项目大量误报**: Library 项目缺少明显入口点，导致 scanner 构造大量人工 wrapper 产生误报
3. **跨文件流追踪不完整**: 静态分析标注了多处 "Static engine could not trace variable propagation"

---

## 文件

- 扫描日志: `pocs/transformers_v3_pipeline_log.txt`
- 完整报告: `pocs/transformers_v3_report.md`
- PoC 脚本: `pocs/transformers_ssrf_lfi_poc.py`

---

## Pipeline Complete

- **Target**: `/tmp/transformers_src`
- **Duration**: 4102.7s
- **Paths discovered**: 207 (all analyzed)
- **Findings**: 87 high, 90 interesting
- **沙箱验证**: 2/87 high findings confirmed exploitable
- **Tokens**: 7,085,185 total
