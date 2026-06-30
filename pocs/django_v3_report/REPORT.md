# Django v3 Pipeline 审计报告

**目标**: /tmp/django (Django Web Framework)  
**Date**: 2026-06-30  
**Pipeline**: v3 (Phase A → B → C → D → D.3 → E)  
**Model**: deepseek-chat  
**Duration**: 184.3s  
**Token 消耗**: 472,206 (414,387 prompt + 57,819 completion)  

---

## Pipeline 概览

| Phase | 结果 |
|-------|------|
| Phase A: Path Discovery | 235 paths (tree-sitter) |
| Phase A.5: Source Classification | 208 paths after filtering |
| Phase B: Slice Sorting | 45 slices (30 exploit + 15 explore) |
| Phase B.7: Semantic Anchors | **424 matches** (18 种锚类型) |
| Phase B.7: Semantic Leaks | **79 leaks**, 196 sensitive vars |
| Phase C: README | ✅ |
| Phase D: Intent+Logic (45 slices) | 34 high confidence, 24 interesting |
| Phase D.3: Assumption Agent | **102 assumptions, 15 contradictions** |
| Phase D.5: Aggregation | 102 assumptions, 15 contradictions |
| Phase E | 76 cached intents, 367 knowledge entries |

---

## Phase D: Sink-Based Findings

34 high-confidence findings across all 45 analyzed paths:

| Path | Type | Sink | Status |
|------|------|------|--------|
| afo-000 | AFO | cleanup | high |
| sqli-002 | SQLI | last_executed_query | high |
| rce-003 | RCE | compile/eval | high (PoC generated) |
| sqli-005 | SQLI | executemany | high |
| redos-004 | ReDoS | startElement | high |
| ssrf-006 | SSRF | get_api_response | high |
| ssrf-009 | SSRF | _non_atomic_requests | high |
| afo-010 | AFO | _clone_test_db | high |
| lfi-012 | LFI | django_check_file | high |
| rce-020 | RCE | resolve_expression_parameter | high |
| lfi-015 | LFI | create_checksum_file | high (not rebutted) |

Notable denied findings (Adversary Agent):
- redos-004: Pattern match, LLM skeptical
- Several SSTI paths ruled safe by Logic Agent

---

## Phase D.3: Assumption Agent Results

### 假设分布（102 total）

从 424 个语义锚中提取，覆盖 18 种锚类型：

| 知识种类 | 假设数 | 说明 |
|---------|--------|------|
| TRUST_BOUNDARY | ~48 | 每次请求验证凭据 / Token 签名验证 |
| STATE_TRANSITION | ~28 | 环境变量解析 / Session 失效 / 过期检查 |
| PARSER | ~10 | 编解码一致性 / 反序列化 |
| OBJECT_IDENTITY | ~6 | 资源所有者检查 |
| INVARIANT | ~5 | 使用现代加密算法 |
| 其他 | ~5 | AUTHORITY, CACHE, OWNERSHIP |

### 矛盾（15 total, 从中选出 TOP 3）

**1. credential_validation × logout_invalidation [medium]**

```
存在凭据验证（LoginView）但 session 退出时不失效（SessionMiddleware），
认证 session 可被重复使用
```

- 假设 A: `credential_validation` — LoginView (views.py) 执行凭据验证
- 假设 B: `logout_invalidation` — SessionMiddleware (middleware.py) 退出不失效
- **相同文件类矛盾**（`credential_validation` 与 `logout_invalidation` 来自不同锚类型但共享 session 生命周期）

**2. credential_validation × logout_invalidation [medium]**

```
存在凭据验证（LoginView）但 session 退出时不失效（BaseSessionManager），
认证 session 可被重复使用
```

- 假设 B 版本: `BaseSessionManager` (base_session.py)

**3. credential_validation × logout_invalidation [medium]**

```
存在凭据验证（LoginView）但 session 退出时不失效（SessionStore），
认证 session 可被重复使用
```

- 假设 B 版本: `SessionStore` (signed_cookies.py)

> **分析**: 三条矛盾指向同一问题——Django 的 `authenticate()`/`login()` 路径存在凭据验证，但 `SessionMiddleware`/`BaseSessionManager`/`SessionStore` 的 logout 路径缺少完整的 session 失效。这是典型的 "状态转换越界" 型安全假设矛盾：认证状态被假设为"退出后失效"，但 session 管理层不保证这一点。

---

## Phase 3: LLM 攻击链合成

```json
{
  "attack_chains": [
    {
      "chain_id": "CHAIN-001",
      "title": "Session固定与重用攻击链",
      "prerequisites": [
        "攻击者能够获取或设置用户的会话ID",
        "系统使用基于会话的认证",
        "会话在退出时未完全失效"
      ],
      "steps": [
        "1. 攻击者获取合法用户会话ID",
        "2. 用户退出登录，但SessionStore/BaseSessionManager未清除会话",
        "3. 攻击者复用原会话ID访问受保护资源",
        "4. 系统未验证会话是否对应已认证用户"
      ],
      "impact": "未授权访问受保护资源",
      "confidence": 7
    }
  ]
}
```

---

## 语义泄露分析

79 个泄露事件，196 个敏感变量在 47 个文件中：

| 泄露通道 | 计数 |
|---------|------|
| return（凭据返回值） | ~28 |
| logger.debug/info | ~18 |
| format_string | ~12 |
| http_response | ~10 |
| print | ~6 |
| other | ~5 |

**典型泄露**: API token / token / password / api_key 作为函数返回值传递（credential_return），调用方可能记录到日志或转发。

---

## 架构结论

### Assumption Agent 有效性评估

| 指标 | 值 | 评价 |
|------|-----|------|
| 假设提取（Phase 1） | 102 | ✅ 大规模提取稳定 |
| 矛盾检测（Phase 2） | 15 | ✅ 去重有效，不爆炸 |
| 攻击链合成（Phase 3） | 1 chain | ⚠️ 仅 LLM 部分，可考虑增加多个锚类型 |
| 发现真实漏洞 | 0 | ⚠️ session 固定/重用偏设计缺陷，非代码级可利用 |
| `env_resolution` FP | 0 | ✅ 模式修复后无 `$salt` FP |

### 盲区（Django 特殊性）

1. **Django 自身是框架不是应用** — 424 个语义锚大量命中 docs/scripts 等非核心文件
2. **Django SecurityMiddleware 是设计级防御** — Assumption 能找到 "login 有验证但 logout 不失效" 的矛盾，但这在 Django 中是有意设计（由应用层控制 logout 行为）
3. **库级漏洞 vs App 级** — Django 自带的认证中间件正确实现，矛盾出现在更高的业务逻辑抽象层
4. **`env_resolution` 在 Django 中 0 匹配** — Django 不使用 `$ENV` 模式解析凭据，这证明修复有效

### 改进建议

1. **按项目目录过滤语义锚** — 当前 424 锚包含大量 docs/scripts/examples，应优先分析 django/django/ 目录
2. **增加 CONFIG_DRIVEN 锚类型** — Django 有大量 settings-based 配置，配置注入是新的矛盾面
3. **增加 CSRF/Middleware 特定规则** — Django 的 CSRF 中间件、SecurityMiddleware、`@login_required` 装饰器等有独特的安全保证语义
