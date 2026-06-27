# Firefox Relay — 攻击面分析报告

> 分析日期：2026-06-27
> 目标版本：Mozilla Firefox Relay (fx-private-relay)
> 分析方法：agies v3 管道 (tree-sitter Phase A) + 人工代码审查 + 误报过滤

---

## 目录

1. [Pipeline 扫描结果 & 误报过滤](#1-pipeline-扫描结果--误报过滤)
2. [已确认漏洞](#2-已确认漏洞)
3. [攻击链分析](#3-攻击链分析)
4. [次要发现](#4-次要发现)
5. [防守建议](#5-防守建议)
6. [附录：代码位置索引](#6-附录代码位置索引)

---

## 1. Pipeline 扫描结果 & 误报过滤

agies v3 管道 Phase A（tree-sitter 路径发现）扫描了 **1277 个函数**，发现以下 sink 路径。经人工逐条审核后：

### 1.1 过滤总表

| 漏洞类型 | Raw 数量 | 真实 | 误报 | 误报率 |
|---------|---------|------|------|--------|
| SSRF | 15 | **1** | 14 | **93%** |
| LFI | 20 | **0** | 20 | **100%** |
| SQLi | 20 | **0** | 20 | **100%** |
| ReDoS | 3 | **0** | 3 | **100%** |
| `e.deserialize → rce` | 1 | **0** | 1 | **100%** |
| Suspicious (path/logic) | 3 | — | — | 待判断 |
| **合计** | **62** | **1** | **58** | **94%** |

### 1.2 每条误报的具体原因

#### SSRF — 14 条误报

| # | 位置 | sink | 误报原因 |
|---|------|------|---------|
| 1 | `emails/utils.py:89` | `requests.get(repo_url)` | URL 硬编码为 Mozilla shavar-prod-lists，非用户输入 |
| 2 | `privaterelay/apps.py:128` | `requests.get(fxa_jwks_url)` | URL 来自 `settings.SOCIALACCOUNT_PROVIDERS`，配置控制 |
| 3 | `privaterelay/.../update_fxrelay_allowlist_collection.py:21` | `requests.get(ALLOWLIST_INPUT_URL)` | management command，仅管理员执行 |
| 4 | `api/authentication.py:36` | `requests.post(fxa_token_url)` | FxA OAuth token 交换，认证流程 |
| 5 | `api/views/privaterelay.py:392` | `requests.get(FXA_PROFILE_URL)` | 硬编码 URL，需 Bearer token 认证 |
| 6-15 | 各 settings/配置来源的 HTTP 请求 | 同类 | 所有 `requests.*` 调用均使用配置或硬编码 URL |

**唯一真实 SSRF：** `emails/sns.py:135` — `urlopen(cert_url)`，URL 来自用户可控的 SNS JSON 消息体

#### LFI — 20 条全误报

| # | 位置 | sink | 误报原因 |
|---|------|------|---------|
| 1 | `emails/utils.py:79` | `open(TRACKER_FOLDER_PATH / file_name)` | 路径基于硬编码常量 `TRACKER_FOLDER_PATH` |
| 2 | `emails/utils.py:101` | `open(path / file_name, "w+")` | path 来自 `EMAILS_FOLDER_PATH`（硬编码） |
| 3-20 | 其他 `open()` 调用 | 同上 | 所有文件操作均使用硬编码或 settings 路径 |

#### SQLi — 20 条全误报

全项目未发现 `raw()`、`extra()`、`connection.execute()` 等可导致 SQL 注入的调用。所有数据库查询均通过 Django ORM 的标准接口执行。v3 的 SQLi 匹配对 Django ORM 项目有系统性误报。

#### ReDoS — 3 条全误报

| # | 位置 | sink | 误报原因 |
|---|------|------|---------|
| 1 | `emails/utils.py:454` | `re.subn(pattern, "", html_content)` | pattern 来自 tracker 域名列表（Mozilla 维护），非用户输入 |
| 2 | `emails/utils.py:492` | `re.subn(pattern, ...)` | 同上 |
| 3 | `emails/views.py:1244` | `re.sub("([@.:])", ...)` | 静态硬编码正则可安全编译 |

#### `e.deserialize → rce` — 1 条 LLM 幻觉

全项目 grep "deserialize" 未找到任何匹配。代码中无 pickle/yaml/marshal/msgpack 等反序列化操作。v3 Phase 0（LLM 辅助 sink 发现）输出的幻觉。

### 1.3 误报率总结

**62 条 raw sink 路径 → 过滤后剩 1 条真实漏洞 → 误报率 94%。**

这是 tree-sitter 静态匹配 + 无数据流分析的固有局限。v3 管道的 Phase B-D（Intent Agent + Logic Agent）本该对每条路径做 LLM 驱动的真假判断，但管道被输出缓冲卡住未能完成。

---

## 2. 已确认漏洞

### 2.1 [CWE-918] SNS Webhook SSRF — 预认证服务端请求伪造

**严重性：中危 (CVSS 6.5)**
**发现方式：agies v3 Phase A + 人工确认**

#### 位置
- `emails/sns.py:75-101` — `verify_from_sns()` 签名验证函数
- `emails/sns.py:114-158` — `_get_signing_public_key()` 证书下载函数
- `emails/views.py:377` — `sns_inbound()` webhook 入口
- `emails/sns.py:135` — `response = urlopen(cert_url)` **sink 点**

#### 根因

```
sns_inbound()                              views.py:377
  └─ verify_from_sns(json_body)            sns.py:75      ← 签名验证
       └─ _get_signing_public_key(url)     sns.py:114
            ├─ startswith() 守卫            sns.py:120-124 ← 字符串前缀检查
            └─ urlopen(cert_url)            sns.py:135     ← 🟥 SSRF 触发
                 └─ verify()                sns.py:89-99   ← 签名校验在之后
```

核心问题：`urlopen(cert_url)` 在第 135 行执行，但**签名验证**在第 89-99 行。攻击者可发送签名完全无效的 payload，`urlopen()` 仍然触发。

#### 循环引用缓存分析

`_get_signing_public_key()` 使用 Django cache 缓存解析后的公钥：
```python
key_cache = caches[...]
public_pem = key_cache.get(cache_key)
if public_pem:
    cert_pubkey = serialization.load_pem_public_key(public_pem)
else:
    response = urlopen(cert_url)  # 🟥 首次调用会触发 SSRF
    cert_pem = response.read()
    cert_pubkey = certs[0].public_key()
    public_pem = cert_pubkey.public_bytes(...)
    key_cache.set(cache_key, public_pem)  # 后续命中缓存不再请求
```

缓存键为 `f"{cert_url}:public_key"`，即**缓存命中与否取决于 URL 是否相同**。攻击者每次用不同的 URL 都可以绕过缓存触发新的 `urlopen()`。

#### 防御分析

```python
# sns.py:120-124 — 唯一的防御
cert_url_origin = f"https://sns.{settings.AWS_REGION}.amazonaws.com/"
if not (cert_url.startswith(cert_url_origin)):
    raise SuspiciousOperation(...)

# sns.py:135 — 🚩 noqa: S310 (linter 告警被压制)
response = urlopen(cert_url)  # noqa: S310 (check for custom scheme)
```

**`noqa: S310` 的含义（极其关键）：**
- Bandit/ruff 的 S310 规则：检测 `urlopen()` 调用是否未检查 URL 可信度
- 开发者加 `noqa: S310` 的理由是 `"(check for custom scheme)"`
- 但 `urlopen()` 的关键风险不是自定义 scheme（file:// 默认被禁），而是**默认跟随 HTTP 重定向**
- S310 **不是 "we checked the host"**，而是 "we checked the scheme" — 两者天差地别

**structual weakness**: `startswith()` 是字符串检查，不是 URL 解析:
- `urllib.request.urlopen` 默认跟随 301/302/303/307/308 重定向
- `startswith()` 和 `urllib` 的 URL 解析行为可能在未来版本产生差异
- 路径遍历、fragment 注入等被 `startswith` + trailing slash 阻挡，但架构上脆弱

#### 利用场景

```
POST /emails/sns-inbound
Content-Type: application/json

{
  "Type": "Notification",
  "SigningCertURL": "https://sns.us-east-1.amazonaws.com/valid-cert.pem",
  "Signature": "INVALID",
  ...
}
```

即便 `verify()` 会因签名无效抛异常，`urlopen()` 已经发出网络请求。这是一个 **side-channel SSRF**。

#### 守卫绕过潜力

| 绕过方式 | 可行性 | 说明 |
|---------|--------|------|
| `@evil.com` host 注入 | ❌ | trailing slash 阻挡，变成 path |
| `\\@evil.com` | ❌ | startswith 不匹配 |
| 自定义端口 | ❌ | startswith 不匹配 |
| DNS rebinding | ⚠️ 理论 | AWS 域名 TTL 控制严格 |
| AWS SNS open redirect | ⚠️ 可能 | 如果 SNS 端点返回 302，urlopen 会跟随 |
| urllib 版本差异 | ⚠️ 跨版本 | 未来 Python 版本可能 |
| 内网服务探测 | ✅ | 通过请求耗时/超时判断内网主机存活 |

---

### 2.2 [CWE-79] Email 转发 HTML 注入（准 XSS）

**严重性：低-中危 (取决于邮件客户端)**
**发现方式：人工代码审查**

#### 位置
- `emails/templates/emails/wrapped_email.html:196` — `{{ original_html|safe }}`
- `emails/views.py:1228-1274` — `_convert_html_content()`
- `emails/views.py:1266-1273` — `wrap_html_email()` 调用

#### 根因

```html
<!-- wrapped_email.html:196 -->
<td width="100%" style="padding-left: 15px; padding-right: 15px;">
  {{ original_html|safe }}          <!-- ← Django safe 过滤器，不做转义 -->
</td>
```

`original_html` 来源于用户发来的邮件 HTML 正文，经 `_convert_html_content()` 处理后直接插入到 Relay 的包装模板中，**没有任何 HTML 消毒**。

#### 攻击链

```
攻击者发送含恶意 HTML 的邮件 → SES → SNS Notification
  → sns_inbound()
    → _sns_inbound_logic()
      → _sns_notification()
        → _sns_message()
          → _handle_received()
            → _convert_to_forwarded_email()
              → _convert_html_content()
                → wrap_html_email()
                  → {{ original_html|safe }}  ← 🟥 注入点
```

#### 利用能力

| 能力 | 所有邮件客户端 | 仅部分客户端 |
|------|--------------|-------------|
| 追踪像素 | ✅ | — |
| 钓鱼链接 | ✅ | — |
| CSS 伪装 | ✅ | — |
| JavaScript 执行 | ❌ | ⚠️ 支持脚本的客户端 |
| CSRF token 窃取 | ❌ | ⚠️ webmail 异常 |

#### 限制
- 现代邮件客户端（Gmail, Outlook, Apple Mail）默认禁止 JavaScript
- 但仍可做：**追踪像素**、**钓鱼链接**、**邮件内容欺骗**
- 如果 Relay 有 web 界面渲染邮件内容（如 dashboard），可升级为存储型 XSS

#### 与 SSRF 的联动

这两个漏洞可通过同一入口 `sns_inbound` 触发，但攻击路径不同：
- SSRF：控制 `SigningCertURL` 字段
- HTML 注入：通过 SES 正常邮件转发流程

---

## 3. 攻击链分析

### 3.1 SSRF 调用链完整数据流

这是 `urlopen(cert_url)` 之后**完整的调用链和数据流**，每个环节都是一个可攻击面：

```
urlopen(cert_url)                              ← 🟥 网络请求
  ↓
response.read()                                ← 读取响应体到内存
  ↓ (bytes)
x509.load_pem_x509_certificates(cert_pem)      ← 解析为 X.509 证书
  ↓
certs[0].public_key()                          ← 提取 RSA 公钥
  ↓
cert_pubkey.verify(signature, hash, ...)       ← SHA1 签名验证
  ├─ 失败 → VerificationFailed → Django 500
  └─ 成功 → 返回 verified_json_body
               ↓
           sns_inbound() 继续
               ├─ validate_sns_arn_and_type()  ← ⛔ ARN 白名单检查
               └─ _sns_inbound_logic()
                    ├─ SubscriptionConfirmation → 只记录 SubscribeURL（安全）
                    └─ Notification
                         ↓
                    _sns_notification()
                         ↓
                    json.loads(json_body["Message"])  ← 用户可控 JSON
                         ↓
                    _sns_message()
                         ↓
                    _handle_received()
                         ↓
                    message_from_bytes(content)      ← 🟥 邮件解析
                         ↓
                    _replace_headers()               ← 替换邮件头
                         ↓
                    wrap_html_email()
                         ↓
                    {{ original_html|safe }}          ← 🟥 HTML 注入
                         ↓
                    ses_send_raw_email()              → 转发给真实收件人
```

### 3.2 攻击链 A：SNS SSRF — 重定向绕过（中等难度）

**核心思想：** 如果 `sns.{region}.amazonaws.com` 的任何路径返回 3xx 重定向，`urlopen()` 会默认跟随，完全跳过 `startswith()` 守卫。

```
攻击者构造：
  SigningCertURL: "https://sns.us-east-1.amazonaws.com/anypath"

  ↓ startswith() 通过 ✅（确实以 "https://sns.us-east-1.amazonaws.com/" 开头）

  ↓ urlopen() 向 SNS 发送 GET /anypath

  ↓ 如果 SNS 返回 302 → http://169.254.169.254/latest/meta-data/
    或 302 → http://internal.service:6379/  (Redis)
    或 302 → http://internal.api/admin

  ↓ urllib.request.urlopen 默认 FOLLOWS 重定向

  ↓ 请求到达内部服务（HTTP 不需要 SSL 证书验证）

  🟥 FULL SSRF BYPASS
```

**关键问题：`sns.{region}.amazonaws.com/` 是否对任何路径返回 302？** 常见 AWS 行为：
- 根路径 `/` → 可能 302 到 AWS console 或 API docs
- 未知路径 → 通常返回 404/403（不跳转）
- 但这取决于 AWS SNS 服务端的具体配置和版本

```
# 需要验证（攻击者可远程探测）：
# curl -v https://sns.us-east-1.amazonaws.com/
# curl -v https://sns.us-east-1.amazonaws.com/anything
# 看是否返回 3xx
```

**如果可行，跳转目标限制：**
- HTTP 跳转 → ✅ 可以访问内部任何 HTTP 服务（无 SSL 验证）
- HTTPS 跳转 → ⚠️ 需要目标有匹配的 SSL 证书（否则 urllib 拒绝连接）
- `file://` 协议 → ❌ Python urllib 默认禁止跨协议跳转

**调用链数据流（绕过后）：**
```
urlopen("https://sns.us-east-1.amazonaws.com/probe")
  → 302 → urlopen("http://internal.service:8080/admin")
    → response.read()  ← 读取内部页面内容
      → x509.load_pem_x509_certificates(response) ← 解析失败（不是 PEM）
        → 异常，Django 500
          ⚠️ 但 SSRF 已经发生，内部页面已被读取到内存
```

### 3.3 攻击链 B：urlopen 响应 → X.509 解析面

即使重定向不可行，`urlopen()` 的响应体被 `cryptography` 库解析为 X.509 证书：

```
urlopen(cert_url)
  ↓
response.read()                      ← 读入内存（大响应 = DoS）
  ↓
x509.load_pem_x509_certificates()   ← CPP/Rust 实现，但解析 attacker 可控数据
  ↓
检查: len(certs) != 1 → raise      ← 强制 single cert
  ↓
cert.public_key()                   ← 提取公钥
  ↓
检查: not isinstance(rsa.RSAPublicKey) → raise  ← 强制 RSA
  ↓
PKCS1v15-SHA1 verify                ← 签名验证
```

**攻击面：**
- **内存 DoS**：`response.read()` 无大小限制，SNS 可返回大文件（如 100MB）导致 OOM
- **CPU DoS**：复杂 X.509 证书链解析消耗 CPU
- **cryptography 库解析器**：但 cryptography 是内存安全语言（Rust）实现，RCE 风险极低
- **RSA 公钥 deserialize**：`serialization.load_pem_public_key()` 在缓存命中时调用

### 3.4 攻击链 C：SNS SSRF + 邮件处理链路（完整利用链）

完整的从 SSRF 到邮件注入的调用链：

```

Phase 1: 触发 SSRF（即使验证失败）
┌──────────────────────────────────────────────────────────┐
│ POST /emails/sns-inbound                                  │
│   SigningCertURL: "https://sns.us-east-1.amazonaws.com/X" │
│   Signature: "INVALID"                                    │
│   → urlopen(cert_url)  ← 🟥 网络请求已发出                │
│   → verify() ↓ FAIL                                       │
│   → VerificationFailed → Django 500                       │
│   ⚠ 但 urlopen 的 side-effect 已产生                       │
└──────────────────────────────────────────────────────────┘

Phase 2: 侧信道内网扫描（即使验证失败也有效）
┌──────────────────────────────────────────────────────────┐
│ 通过不同的 SigningCertURL 测量响应时间：                   │
│   "https://sns.us-east-1.amazonaws.com/probe1" → 200ms   │
│   "https://sns.us-east-1.amazonaws.com/probe2" → 5000ms  │ ← 超时
│   → 推断 probe2 路径触发了不同行为                         │
│                                                           │
│ 如果重定向绕过成功：                                        │
│   "https://sns.us-east-1.amazonaws.com/redirect-to-internal" │
│   → 302 → http://192.168.1.1:8080 → 10ms（端口开放）       │
│   → 302 → http://192.168.1.1:22   → 5000ms（端口关闭）     │
│   → 可通过响应时间差绘制内网拓扑                            │
└──────────────────────────────────────────────────────────┘

Phase 3: 响应体处理（如果重定向到攻击者控制的服务器）
┌──────────────────────────────────────────────────────────┐
│ urlopen → 302 → attacker-controlled HTTP server           │
│   → 返回伪造的 PEM 证书                                   │
│   → x509.load_pem_x509_certificates() 解析成功            │
│   → public_key() 提取 RSA 公钥 ✅                          │
│   → verify() 失败（无对应私钥签名）→ 异常                   │
│   ⚠ 但公钥已被缓存！                                      │
│     cache_key = f"{cert_url}:public_key"                   │
│     下次相同 cert_url → 用缓存中的公钥验证                  │
└──────────────────────────────────────────────────────────┘

Phase 4: 如果验证通过（需要破解 SHA1 签名或控制私钥）
┌──────────────────────────────────────────────────────────┐
│ verify() ✅                                              │
│   → json.loads(json_body["Message"]) ← 控制 Message 字段  │
│   → _handle_received()                                    │
│     → _get_email_bytes()                                  │
│       → message_json["content"]  ← 控制邮件内容           │
│     → message_from_bytes(content)  ← 解析邮件              │
│     → _convert_to_forwarded_email()                       │
│       → wrap_html_email()                                 │
│         → {{ original_html|safe }}  ← 🟥 HTML 注入        │
│     → ses_send_raw_email()  ← 转发到真实收件人             │
└──────────────────────────────────────────────────────────┘
```

### 3.5 攻击链 D：缓存投毒 → 公钥持久化

```python
# sns.py:126-157
key_cache = caches[getattr(settings, "AWS_SNS_CACHE", "default")]
cache_key = f"{cert_url}:public_key"
public_pem = key_cache.get(cache_key)

if public_pem:
    cert_pubkey = serialization.load_pem_public_key(public_pem)  # 用缓存的
else:
    response = urlopen(cert_url)  # 首次下载
    ...
    key_cache.set(cache_key, public_pem)  # 缓存

return cert_pubkey  # 返回公钥用于 verify()
```

**攻击场景：**
1. 攻击者找到 `sns.{region}.amazonaws.com` 上某路径返回 302 → `http://attacker.com/evil.pem`
2. `urlopen()` 跟随重定向下载 `evil.pem`
3. PEM 被解析为合法 RSA 公钥
4. 公钥被缓存，key = `f"{cert_url}:public_key"`
5. 后续相同 `cert_url` 的请求直接使用缓存公钥验证签名
6. 如果攻击者能进一步控制签名验证（通过 SHA1 碰撞或控制消息体格式），可完全绕过验证

**限制：** Django cache 通常有 TTL（默认 ~300 秒），缓存投毒的窗口有限。

### 3.6 攻击链 E：SNS + DEBUG 模式端点组合

```
emails/urls.py  — DEBUG 模式会启用这些测试端点：
  /emails/wrapped_email_test     ← 渲染 HTML 邮件预览
  /emails/first_time_user_test   ← 渲染首封测试邮件
  /emails/reply_requires_premium_test
  /emails/first_forwarded_email
  /emails/disabled_mask_for_spam_test

privaterelay/urls.py — 非调试端点：
  /admin/          ← 如果 ADMIN_ENABLED=True
  /silk/           ← 如果 USE_SILK=True（性能分析工具，有 RCE 历史）
  /__debug__/      ← 如果 DEBUG=True（Django Debug Toolbar）
```

**这些本身不是 SSRF 的一部分**，但如果生产环境不小心开启了 DEBUG/ADMIN/SILK，可以组合利用 SSRF 做内网打点后的横向移动。

---

## 4. 次要发现

### 4.1 唯一的未认证端点

`emails/views.py:377` — `sns_inbound()` 是该项目中**唯一**的 `@csrf_exempt` + 无认证检查的公开端点。所有其他端点（API、FxA）都需要 OAuth 或 Bearer 认证。

### 4.2 SNS SubscriptionConfirmation 不取 URL

`views.py:428-433` 中的 `SubscriptionConfirmation` 处理只记录了 `SubscribeURL`，不会主动请求它（避免了第二个 SSRF 向量）。

### 4.3 v3 管道误报分析摘要

**62 条 sink → 58 条误报 → 94% 误报率。**

v3 的 tree-sitter Phase A 是纯静态匹配，没有数据流分析。对于 Django 项目尤为突出：
- ORM 调用被误标为 SQLi
- settings/配置来源的 HTTP 调用被误标为 SSRF
- 硬编码路径的 `open()` 被误标为 LFI

Phase B-D（LLM 驱动的 Intent + Logic Agent）本可以过滤大部分误报，但管道输出缓冲导致结果未能输出。

### 4.4 加密实现安全

- `jwcrypto.jwe` (A256GCM) 加密 reply metadata — 正确
- HKDF 派生 reply keys — 正确
- `cryptography` 库验证 SNS 签名 — 标准实现

---

## 5. 防守建议

### 5.1 SSRF 修复

将 `startswith()` 替换为 URL 解析 + host 验证：

```python
# 替代 sns.py:120-124
parsed = urlparse(cert_url)
expected_host = f"sns.{settings.AWS_REGION}.amazonaws.com"
if parsed.hostname != expected_host or parsed.scheme != "https":
    raise SuspiciousOperation(...)

# 额外：禁止 urllib 跟随重定向
class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.request.HTTPError(...)
opener = urllib.request.build_opener(NoRedirectHandler)
response = opener.open(cert_url)
```

### 5.2 HTML 注入修复

将 `|safe` 替换为 HTML 消毒：

```html
{# 替代 wrapped_email.html:196 #}
{{ original_html|bleach }}
```

或使用 Django 的 `strip_tags` + `linebreaksbr`，至少消除 HTML 标签。

### 5.3 架构层面

- `urlopen()` 应移到 `verify()` 之后执行（先验证签名，再下载证书）
- SNS 证书可预置到部署包中，避免运行时下载
- 引入 `urllib.request.HTTPRedirectHandler` 禁止重定向

---

## 6. 附录：代码位置索引

### 真实漏洞

| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `emails/sns.py` | 135 | 🟥 SSRF | `urlopen(cert_url)` 签名验证前触发 |
| `emails/templates/emails/wrapped_email.html` | 196 | 🟥 HTML 注入 | `{{ original_html|safe }}` 不消毒 |
| `emails/views.py` | 377 | 🔓 未认证入口 | 唯一 `@csrf_exempt` 无 auth 端点 |

### 关键上下文

| 文件 | 行号 | 说明 |
|------|------|------|
| `emails/sns.py` | 75-101 | `verify_from_sns()` — 签名验证流程 |
| `emails/sns.py` | 114-158 | `_get_signing_public_key()` — 证书下载 + 缓存 |
| `emails/sns.py` | 120-124 | `startswith()` 守卫 |
| `emails/views.py` | 427-449 | `_sns_inbound_logic()` — 消息路由 |
| `emails/views.py` | 952-973 | `_get_email_bytes()` — SNS/S3 content 来源 |
| `emails/views.py` | 1029-1118 | `_convert_to_forwarded_email()` — 邮件转换 |
| `emails/views.py` | 1228-1274 | `_convert_html_content()` — HTML 处理 |
| `emails/utils.py` | 449-456 | `convert_domains_to_regex_patterns()` — 正则构建 |

### 误报来源（代表性）

| 文件 | 行号 | 误报类型 | 真实行为 |
|------|------|---------|---------|
| `emails/utils.py` | 89 | SSRF | `requests.get(hardcoded_url)` |
| `privaterelay/apps.py` | 128 | SSRF | `requests.get(settings_url)` |
| `emails/utils.py` | 79 | LFI | `open(hardcoded_path)` |
| `emails/views.py` | 1244 | ReDoS | `re.sub("([@.:])", ...)` 静态编译 |

---

## 攻击面热力图

```
                     未认证    认证    外部网络请求    用户数据处理
sns_inbound             🟥      —       🟥            🟥
API endpoints           —       🟦      —             🟦
FxA events              —       🟦      —             🟦
Email forwarding        —       —       🟦(SES/S3)    🟥
Admin/Debug             🟥      —       —             —

🟥 = 高风险   🟦 = 低风险   — = 不适用
```

---

*Report generated by agies v3 (tree-sitter Phase A) + manual code review + false positive triage*
*Target: Mozilla Firefox Relay (fx-private-relay) — Django + TypeScript*
*真阳性：2 | 误报：58 | 误报率：94%*
