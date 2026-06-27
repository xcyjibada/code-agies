### Open Redirect / 架构缺陷 in django-oauth-toolkit (/oauth/authorize)

**Package:** django-oauth-toolkit (PyPI, https://github.com/jazzband/django-oauth-toolkit)
**Version:** <= 3.3.0
**CWE:** 601

---

The `/oauth/authorize` endpoint has a redirect vulnerability in `handle_no_permission()` (`oauth2_provider/views/base.py:257`). The root cause is an architecture-level layer violation, not simply a missing input check.

#### 架构层面

Django 的类视图在 `AuthorizationView` 上的 MRO 是：

```
dispatch()                           # 请求分发
  → LoginRequiredMixin.dispatch()    # 认证检查
    → (未认证) handle_no_permission()  ← 认证层的错误处理
    → (已认证) get()                   ← OAuth 业务逻辑层
      → validate_authorization_request()  ← oauthlib 协议层
```

`handle_no_permission()` 是认证系统（`LoginRequiredMixin`）的错误处理函数，职责是"用户没登录，告诉它去登录"。但它直接消费了 OAuth 协议层的参数——`redirect_uri`、`prompt`、`state`——完全没有经过 oauthlib 验证。

OAuth 的参数在 OAuth 协议处理前，不应该被任何上层代码使用。这个漏洞不是少写了一行校验，是**业务逻辑绕过了协议层**。

#### 漏洞细节

当未认证用户请求 `/authorize?prompt=none&redirect_uri=https://evil.com` 时：

1. `dispatch()` 初始化 `self.oauth2_data = {}`
2. `LoginRequiredMixin.dispatch()` 发现未认证
3. → 直接调 `handle_no_permission()`（`get()` 从未执行，oauthlib 验证不存在）
4. ← 从 `request.GET` 读取 `redirect_uri`，无校验
5. ← 调 `self.redirect(redirect_to, application=None)`
6. ← `application=None` → 跳过所有应用级 whitelist，只检查 scheme（`["http", "https"]`）
7. ← 302 到 `https://evil.com?error=login_required`

不需要 `client_id`、`response_type`、`state`，有 `prompt=none` + `redirect_uri` 就够。

#### 攻击场景

**场景 1 — 浏览器钓鱼**

基本用法。用户看到 OAuth 提供商域名，信任，然后 302 到攻击者站点。这个场景的杀伤力取决于提供商域名和攻击者页面的贴合度。

**场景 2 — OAuth 客户端库自动处理**

`prompt=none` 的错误响应格式是标准的 OIDC 协议：
```
https://evil.com?error=login_required&state=xxx
```

OAuth 客户端库（如 `oauthlib`、`requests-oauthlib`、`AppAuth`）会在收到 302 后解析这个 Location 头，提取 `error` 和 `state`，触发错误处理回调。这意味着：

- 攻击者不需要受害者在 evil.com 上做什么——**客户端库自己解析了重定向并触发了 OAuth 错误流程**
- 如果攻击者的 URL 指向一个也包含了合法 OAuth 客户端的混合页面，客户端库的状态机可能被诱导到「授权失败」状态，而这个失败的真实原因（参数未验证）和客户端理解的原因不一致
- 这本质上是 OAuth 状态机与底层 HTTP 状态之间的分歧

**场景 3 — Referer 信息泄漏**

authorize URL 中的全部参数通过 Referer 头发往 evil.com：
```
Referer: https://provider.com/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=https://legit-app.com/callback&scope=openid+profile+email&state=CSRF_TOKEN&prompt=none
```

泄漏的信息：
- `client_id` — 用户使用了哪些应用
- `redirect_uri` — 应用的 callback 地址
- `scope` — 请求了哪些权限（能推断应用类型）
- `state` — CSRF token（单点泄露不能直接利用，但结合客户端漏洞可能有用）

**场景 4 — SSRF 绕过**

需要特定架构。如果下游服务信任了 OAuth 提供商域名做 URL 白名单，且跟随 302：
```
下游服务: "https://provider.com" 在白名单里 ✅
  → 请求 /oauth/authorize?prompt=none&redirect_uri=http://169.254.169.254/
    → 302 → 下游服务跟随 → 打到云元数据端点
```

#### 深度防御情况

oauthlib 的 `create_authorization_response()` 在 POST 阶段会重新验证 redirect_uri 是否匹配注册应用的 URI 白名单。这意味着**授权码拦截不可行**。这个漏洞的影响局限在：

- 重定向控制（所有 http/https 目标）
- OAuth 客户端库状态干扰
- Referer 信息泄漏

不能升级到 token 窃取或授权码劫持。

#### 复现

```bash
# 一行验证
curl -v "https://target.com/oauth/authorize?prompt=none&redirect_uri=https://evil.com"

# 回应 302 Location: https://evil.com?error=login_required → 漏洞存在
# 回应 302 /login/?next=... → 未使用该 override 或已修复
```

```python
import requests
s = requests.Session()
r = s.get("https://target.com/oauth/authorize",
          params={"prompt": "none", "redirect_uri": "https://evil.com"},
          allow_redirects=False)
assert r.status_code == 302
assert "evil.com" in r.headers.get("Location", "")
```

#### CVSS 3.1

5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)

#### 修复建议

`handle_no_permission()` 不应该直接消费 OAuth 参数。架构上的正确修法是：

```python
def handle_no_permission(self):
    prompt = self.request.GET.get("prompt")
    redirect_uri = self.request.GET.get("redirect_uri")
    if prompt == "none" and redirect_uri:
        # redirect_uri 来自未经 oauthlib 验证的用户输入
        # 限制 netloc 必须与当前请求一致
        parsed = urlparse(redirect_uri)
        if parsed.netloc and parsed.netloc != self.request.get_host():
            return super().handle_no_permission()
        ...
```

或者移除整个 override，回退到 AccessMixin 默认的登录页跳转（虽然这会破坏 prompt=none 的 OIDC 语义，但安全）。
