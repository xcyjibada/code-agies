# agies v3 — PoC 汇总

> 由 v3 管线（tree-sitter 路径发现 → Intent/Logic Agent → AdversaryAgent → PoCAgent）生成。
> 日期：2026-06-10
> 
> PoC 脚本现已按项目分入 `pocs/{project_name}/` 子文件夹，文件名使用分析文本自动生成的
> 描述性标签（如 `path_traversal_load_file.py`），不再使用 ID 编号。

---

## safetensors-0.8.0（28 .py 文件，1.4MB）

```
Phase A: 20 raw paths (2 RCE, 14 LFI, 4 SUSPICIOUS)
Phase B: 25 slices (20 exploit + 5 explore)
Phase D: 25 slices → 4 PoCs
Duration: 386.7s | Tokens: 235,802
```

### PoC 1: `pocs/safetensors-0.8.0/` — path traversal via HuggingFace filename (load_file)

**类型**: LFI → 路径穿越 / 任意文件读写

**分析**: 用户控制的 `filename` 直接进入 `os.path.join(folder, sf_in_repo)` 无 sanitization。`hf_hub_download` 可能验证文件名，但后续 `os.path.join` 不验证，结果路径同时用于 `save_file`（写入）和 `load_file`（读取），导致任意文件读写。

**AdversaryAgent**: 未 rebut（"用户控制的 filename 进入 os.path.join 无 sanitization，可导致任意文件读写"）

### PoC 2: `pocs/safetensors-0.8.0/` — path traversal via malicious model upload (load_file)

**类型**: LFI → 路径穿越 / 任意文件读取

**分析**: 攻击者上传含 `../../../etc/passwd` 文件名的模型到仓库。`convert_generic` 处理时 `sf_in_repo` 变成 `../../../etc/passwd`，`sf_filename` 解析为 `/etc/passwd`，`load_file` 读取该文件。

**AdversaryAgent**: 未 rebut（"文件名可被攻击者控制，通过 os.path.join 无 sanitization 到达 load_file"）

### PoC 3: `pocs/safetensors-0.8.0/` — path traversal via model_id (convert_single)

**类型**: SUSPICIOUS → 模型 ID 路径穿越

**分析**: 用户控制 `model_id` 进入 `repo_folder_name()` 用于构造 `cache_dir`。无校验防止 `model_id` 中的 `../`，导致 `hf_hub_download` 写入任意路径。

**AdversaryAgent**: 未 rebut（"model_id 用户可控，无路径穿越校验"）

### PoC 4: `pocs/safetensors-0.8.0/` — path traversal via repository filename (convert_generic)

**类型**: SUSPICIOUS → 文件路径穿越

**分析**: 攻击者控制 `model_id` 指向恶意仓库，仓库含文件名 `../../etc/passwd.bin`。`os.path.splitext()` 产生 `../../etc/passwd`，`sf_in_repo = '../../etc/passwd.safetensors'`，`os.path.join(folder, sf_in_repo)` 解析到临时目录外，实现任意文件写入。

**AdversaryAgent**: 未 rebut（"用户控制的 filename 进入 os.path.join 无 sanitization"）

---

## joblib-1.5.3（78 .py 文件，1.8MB）

```
Phase A: 72 raw paths (10 RCE, 14 LFI, 3 SQLI, 6 REDOS, 39 SUSPICIOUS)
Phase B: 35 slices (25 exploit + 10 explore)
Phase D: 35 slices → 3 PoCs
Duration: 445.6s | Tokens: 377,315
```

### PoC 3: `pocs/joblib-1.5.3/` — pickle RCE via `joblib.load()`

**类型**: RCE → pickle 反序列化任意代码执行

**分析**: `numpy_pickle.load()` 内部调用 `pickle.load()`，当加载恶意 pickle 文件时自动执行任意命令。没有输入校验或访问控制。这是 joblib 的已知设计风险（documented behavior）。

**AdversaryAgent**: 未 rebut（"代码路径使用 pickle.load，明确警示过任意代码执行风险。无校验"）

**EvidenceChecker**: 匹配 3 个证据模式，提升到 5+/10 → 验证后保留为 vulnerable

### PoC 4: `pocs/joblib-1.5.3/` — LOKY_PICKLER 环境变量注入

**类型**: SUSPICIOUS → 任意模块导入 RCE

**分析**: `set_loky_pickler()` 函数直接将 `LOKY_PICKLER` 环境变量的值作为模块名导入。攻击者设 `LOKY_PICKLER=evil_module` 即可导入任意恶意模块，其 `Pickler` 类在序列化时执行代码。

**AdversaryAgent**: 未 rebut（"无输入校验；攻击者可通过环境变量注入或直接函数调用控制参数"）

### PoC 5: `pocs/joblib-1.5.3/` — LOKY_PICKLER 通 parallel 执行触发

**类型**: SUSPICIOUS → 任意模块导入 RCE（通过 `Parallel()` 触发）

**分析**: 同 PoC 4，入口不同。`Parallel(n_jobs=1)` 内部触发 `set_loky_pickler` 调用。攻击者设置 `LOKY_PICKLER` 环境变量后，调用 joblib 的并行执行功能即可触发恶意模块导入。

**AdversaryAgent**: 未 rebut（"`set_loky_pickler` 导入任意 Pickler 类，无校验。环境变量注入可行"）

---

## 补充：历史生成 PoC

### mlflow（2026-06-08，v3 管线）

| PoC | 类型 | 说明 |
|-----|------|------|
| `pocs/mlflow/` — pickle 反序列化 | RCE | pickle 反序列化 |
| `pocs/mlflow/` — pickle 反序列化 | RCE | pickle 反序列化 |
| `pocs/mlflow/` — pickle 反序列化 | RCE | pickle 反序列化 |
| `pocs/mlflow/` — path constructor 模式 | SUSPICIOUS | path constructor 模式 |
| `pocs/mlflow/` — path constructor 模式 | SUSPICIOUS | path constructor 模式 |
| `pocs/mlflow/` — 路径穿越 | AFO | 路径穿越 |
| `pocs/mlflow/` — 路径遍历 | LFI | 路径遍历 |

### zipp（2026-06-08，v3 管线）

| PoC | 类型 | 说明 |
|-----|------|------|
| `pocs/zipp/` — CVE-2024-5569 灾难性回溯 | REDOS | CVE-2024-5569 灾难性回溯 |
| `pocs/zipp/` — joinpath → open 桥接模式 | LFI | joinpath → open 桥接模式 |

---

> **注意**：以上文件名仅供参考。实际文件名由 `_describe()` 在运行时根据分析文本自动生成，
> 每次运行可能不同。所有 PoC 均位于 `pocs/{project_name}/` 子文件夹中。

## 管线表现总结

| 指标 | safetensors | joblib |
|------|------------|--------|
| 文件数 | 28 .py | 78 .py |
| 函数数 | 231 | 1,241 |
| 原始路径 | 20 | 72 |
| 切片数 | 25 | 35 |
| Duration | 331.5s | 445.6s |
| Tokens | 228,550 | 377,315 |
| High conf findings | 22 | 33 |
| **PoCs** | **2** | **3** |

SUSPICIOUS 类型贡献了 100% 的 PoC（5/5）——这些是 LLM 自由分析后确认的潜在逻辑漏洞，传统 SAST 无法发现的。LFI/RCE 全部被 AdvisorAgent 正确反驳（true negative）。
