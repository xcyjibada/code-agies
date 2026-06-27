# django-oauth-toolkit Open Redirect (CWE-601)

> 发现日期：2026-06-25
> 目标版本：django-oauth-toolkit 3.3.0（PyPI 最新）
> 影响组件：`oauth2_provider/views/base.py:BaseAuthorizationView`

## 漏洞概要

`BaseAuthorizationView.handle_no_permission()` 在未认证用户发起 OIDC `prompt=none` 请求时，直接从 URL 参数取 `redirect_uri` 做 302 跳转，**不做 host 校验**。攻击者可构造恶意链接，将合法 OAuth 端点的重定向劫持到钓鱼站点。

**CVSS 评估：中等 (5.4) — 网络攻击向量，低复杂度，无需认证，影响完整性。** 无法提升至授权码窃取或 token 劫持（见下文攻击链分析）。

## 漏洞位置

**文件：** `oauth2_provider/views/base.py:257-282`

```python
def handle_no_permission(self):
    prompt = self.request.GET.get("prompt")
    redirect_uri = self.request.GET.get("redirect_uri")
    if prompt == "none" and redirect_uri:
        response_parameters = {"error": "login_required"}
        state = self.request.GET.get("state")
        if state:
            response_parameters["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        redirect_to = redirect_uri + separator + urlencode(response_parameters)
        return self.redirect(redirect_to, application=None)  # application=None → 只校验 scheme
```

**跳转函数** (`base.py:62-69`):
```python
def redirect(self, redirect_to, application):
    if application is None:
        allowed_schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
    else:
        allowed_schemes = application.get_allowed_schemes()
    return OAuth2ResponseRedirect(redirect_to, allowed_schemes)
```

**OAuth2ResponseRedirect** (`http.py:17-32`) 只校验 scheme，不校验 host：
```python
def validate_redirect(self, redirect_to):
    parsed = urlparse(str(redirect_to))
    if not parsed.scheme:
        raise DisallowedRedirect("OAuth2 redirects require a URI scheme.")
    if parsed.scheme not in self.allowed_schemes:
        raise DisallowedRedirect(...)
```

默认 `ALLOWED_REDIRECT_URI_SCHEMES = ["http", "https"]` → 任何 http/https 域名均可。

## 利用条件

1. 目标部署了 django-oauth-toolkit 且启用 OAuth2 授权端点
2. 受害者**未认证**（已认证用户走正常流程，不走 `handle_no_permission`）
3. 受害者点击攻击者构造的 URL

## 利用效果

```
攻击者构造 URL:
  https://legitimate.com/oauth/authorize?prompt=none&redirect_uri=https://evil.com

受害者点击（未认证）→ 302 跳转到:
  https://evil.com?error=login_required
```

## MRO 调用链

```
AuthorizationView (FormView)
  → BaseAuthorizationView.dispatch()           # base.py:45 — 初始化 oauth2_data
    → LoginRequiredMixin.dispatch()            # Django — 检查用户是否已认证
      → (未认证) → handle_no_permission()
        → BaseAuthorizationView.handle_no_permission()  # base.py:257 — ⚠️ 覆盖 AccessMixin 默认实现
```

关键点：`BaseAuthorizationView.dispatch()` 调 `super().dispatch()` 进入 `LoginRequiredMixin.dispatch()`，后者在用户未认证时调 `handle_no_permission()`。由于 `BaseAuthorizationView` 覆盖了该方法，而非使用 `AccessMixin` 默认的登录跳转，导致 `redirect_uri` 直接暴露。

## 攻击链分析 — 能否升级？

### ❌ 授权码拦截（不可利用）

理论上可以通过 `form_valid()` 的隐藏表单字段 `redirect_uri=https://evil.com` 覆盖 oauthlib 内部的 redirect_uri，但：

1. `form_valid()` (`base.py:117-147`) 将 `redirect_uri` 传入 `credentials` 字典
2. oauthlib `create_authorization_response()` 执行 `setattr(request, k, v)` 覆盖 request 属性
3. **但** oauthlib 内部立即调 `validate_authorization_request()` 重新校验 redirect_uri 是否匹配已注册 Application 的回调 URI
4. 不匹配 → 抛 `FatalClientError` → 不发送重定向

**深度防御阻断，授权码不能被劫持。**

### ❌ Token 劫持 / SSRF 升级（不可利用）

- 302 跳转是服务端返回 HTTP 响应，不是服务端主动请求，不构成 SSRF
- Token 端点有 `@csrf_exempt` 但 CSRF 不是本攻击链的入口
- 已认证用户不走此代码路径

### ✅ 纯钓鱼（可利用）

攻击者利用 oauth 端点的可信域名做跳板，用户看到合法域名后放松警惕被重定向到钓鱼页面。结合 OAuth 授权页面（熟悉的应用授权 UI）可增强钓鱼可信度。

## 修复建议

`handle_no_permission()` 应对 `redirect_uri` 做 host 验证：

```python
def handle_no_permission(self):
    prompt = self.request.GET.get("prompt")
    redirect_uri = self.request.GET.get("redirect_uri")
    if prompt == "none" and redirect_uri:
        # 校验 redirect_uri 是否合法（至少不能重定向到外部域名）
        parsed = urlparse(redirect_uri)
        if parsed.netloc and parsed.netloc != self.request.get_host():
            return super().handle_no_permission()
        ...
```

或移除 `handle_no_permission()` 覆盖，回退到 `AccessMixin` 默认行为（重定向到登录页）。

## 参考

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OAuth2 Threat Model (RFC 6819) §4.2.4](https://datatracker.ietf.org/doc/html/rfc6819#section-4.2.4)
- [OIDC Core §3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError)
