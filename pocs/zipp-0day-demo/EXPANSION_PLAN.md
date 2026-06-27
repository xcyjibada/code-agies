# 扩大影响面计划 — glob→regex ReDoS 系列挖掘

## 背景

在 zipp 4.1.0 中发现了 glob→regex 翻译导致的 ReDoS 0-day。技术根因具有通用性：**任何将 glob pattern 翻译为 NFA 正则表达式，且未使用原子分组/占有型量词消除回溯的库，都可能存在同类漏洞。**

三个 2026 年的判例已验证该攻击面属于 CWE-1333，均分配了 CVE：
- Spring AntPathMatcher — CVE-2026-41848
- minimatch (Node.js) — CVE-2026-26996
- picomatch (Node.js) — CVE-2026-33671

## 目标

用同一套思路（恶意 ZIP + `*X`×K pattern → 指数回溯），扫描 Python 生态中其他 glob 实现，串联多个 CVE 挂在 agies 名下。

## 候选目标

### Python glob 实现

| 库 | 实现方式 | 风险判断 | 状态 |
|----|---------|---------|------|
| zipp | regex `[^/]*` | ✅ 已确认 | CVE 申请中 |
| `fnmatch.translate()` | regex 翻译 | ⚠️ 需分析是否用 NFA 回溯 | 未开始 |
| `pathlib.Path.glob()` | C 扩展/纯 Python | ⚠️ Python 3.12+ 内部使用 zipp？需确认 | 未开始 |
| `wcmatch.glob()` | regex 翻译 | ⚠️ 需分析 | 未开始 |
| `glob2` | regex 翻译？ | ⚠️ 需分析 | 未开始 |
| `rglob` | 未知 | ⚠️ 需分析 | 未开始 |

### 跨语言 glob 实现（扩展目标）

| 库/框架 | 语言 | 风险判断 | 状态 |
|---------|------|---------|------|
| Spring AntPathMatcher | Java | ✅ 已有 CVE-2026-41848 | 已知 |
| minimatch | JS | ✅ 已有 CVE-2026-26996 | 已知 |
| picomatch | JS | ✅ 已有 CVE-2026-33671 | 已知 |
| Go `filepath.Match()` | Go | ⚠️ 需分析 | 未开始 |
| Rust `glob` crate | Rust | ⚠️ 需分析 | 未开始 |

## 方法论

### 第一阶：静态筛选

1. 检查库是否将 glob pattern 翻译为 regex（而非逐字符匹配）
2. 检查翻译是否生成 `*` → `.*` 或 `[^/]*` 等量词
3. 检查是否使用原子分组 `(?>...)` 或占有型量词 `*+`
4. 如果没有 → 潜在易受攻击

### 第二阶：PoC 验证

1. 构造含长重复字符 entry 的 ZIP 或文件结构（如 `aaaa/file.txt`）
2. 构造 pattern `*X`×K（如 `*a*a*a*a*a*a`）
3. 调用 glob，测量耗时
4. 如果 K=6 时 >2s → ReDoS 确认

### 第三阶：CVE 申请

每个确认的库走相同流程：
1. 查看 SECURITY.md，找安全联系渠道
2. 提交报告（含 PoC + 分析）
3. 等待 CVE 分配

## 预期影响

- Python 生态：zipp + pathlib + wcmatch + glob2 如果都命中 → 4~5 个 CVE
- 每个 CVE 月下载量：千万~亿级
- 叙事价值："agies 一次性发现 Python 生态 glob 链式漏洞，影响数亿次下载"

## 时间估算

| 阶段 | 预计时间 |
|------|---------|
| 分析 fnmatch.translate | 1~2 小时 |
| 分析 pathlib.Path.glob | 1~2 小时 |
| 分析 wcmatch / glob2 | 各 1~2 小时 |
| PoC 验证 | 每库 30 分钟 |
| CVE 提交 | 每库 30 分钟 |
| 总计 | ~2~3 个工作日 |

## 风险

- 部分库可能已使用安全生成方式（原子分组），无漏洞
- Python 3.12+ 的 `pathlib.Path.glob` 如果内部用了 zipp，可能已被同一漏洞覆盖（而非新 CVE）
- 跨语言目标需要对应语言环境（Go/Rust 工具链）

## 参考文档

- `pocs/zipp-0day-demo/REPORT.md` — zipp 原始漏洞报告
- `pocs/zipp-0day-demo/EMAIL_TEMPLATE.md` — 已提交的 Tidelift 邮件
- `pocs/zipp-0day-demo/CVE_SUBMISSION.md` — CVE 提交材料
- `pocs/zipp-redos-sandbox/` — 完整测试沙箱

---

*记录于 2026年6月26日 · zipp ReDoS 发现之后*
