# Firefox Relay 攻击面分析

> agies v3 pipeline 扫描 + 人工代码审计

## 文件清单

| 文件 | 说明 |
|------|------|
| [`ATTACK_SURFACE.md`](ATTACK_SURFACE.md) | 完整攻击面分析报告 |
| [`sns_ssrf_poc.py`](../fx-relay-sns-ssrf-poc.py) | SNS Webhook SSRF PoC（原始） |
| [`email_html_injection_poc.py`](email_html_injection_poc.py) | Email 转发 HTML 注入 PoC（新增） |

## 汇总

### 已确认

- **SNS SSRF** — `urlopen(cert_url)` 在签名验证前触发，唯一防御是 `startswith()` 字符串检查
- **HTML Injection** — `{{ original_html|safe }}` 将发件人 HTML 不经消毒注入转发邮件

### Pipeline Phase A 发现（未深入验证）

- 15 SSRF / 20 LFI / 20 SQLi / 3 ReDoS / 1 e.deserialize→rce

## 分析周期

- agies v3 Phase A：~2 分钟（1277 函数，tree-sitter）
- LLM Phase 0：~30 秒（1 次 LLM 调用发现额外 sink）
- 人工深挖 + 攻击链分析：~15 分钟
- **Total：~18 分钟从拉代码到出报告**

## 注意

所有 PoC 仅供安全研究和授权测试使用。未经授权的生产系统测试非法。
