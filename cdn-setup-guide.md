# Cloudflare CDN 套代理教程

## 原理

Cloudflare CDN（免费套餐）可以代理 TCP 443 端口的 TLS 流量。
因此将 **VLESS + WebSocket + TLS** 放在 CF 后面，CF 做 TLS 终止和 IP 隐藏，可以大幅提高稳定性。

```
客户端 → Cloudflare CDN → VPS (Xray) → 目标
        ↑ IP 是 CF 的    ↑ 真正的 IP 被隐藏
```

两个 VPS：一台套 CF（主力，稳定），另一台保持 hy2（备用，低延迟）。

---

## 第一步：域名和 Cloudflare 配置

### 1. 准备域名
需要一个域名（几块钱一年，Namesilo/Namecheap/阿里云都行），NS 改成 Cloudflare 的：
```
bob.ns.cloudflare.com
donna.ns.cloudflare.com
```

### 2. DNS 记录
Cloudflare 后台添加一条 **A 记录**（子域名随意，比如 `jp.你的域名.com`）：

| 类型 | 名称 | 内容 | 代理状态 |
|------|------|------|----------|
| A    | jp   | VPS IP | ✅ 代理 (橙色云朵) |

**关键：必须是橙色云朵（Proxied），流量才会走 CDN。**

### 3. SSL/TLS 设置
Cloudflare 后台 → SSL/TLS → 选择 **Full (strict)**
- 需要给你的域名申请一个证书放 VPS 上（可以 CF 自动签的源证书或者 acme.sh 申请）

生成源证书（最简单的方式）：
```
Cloudflare 后台 → SSL/TLS → Origin Server → Create Certificate
```
选择 RSA（兼容性更好），有效期选最长的，下载 `cert.pem` 和 `key.pem`。

---

## 第二步：服务器端部署 Xray（选一台 VPS 即可）

### 1. 安装 Xray

```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

### 2. 上传证书

在 VPS 上创建目录并上传刚才下载的两个文件：

```bash
mkdir -p /etc/ssl/certs/
# 把 cert.pem 和 key.pem 放到这个目录
# cert.pem 改名 jp.yourdomain.com.pem
# key.pem 改名 jp.yourdomain.com.key
```

**需要**配置前上传证书，可以用 scp：

```bash
# 本地执行
scp cert.pem xcy@<VPS_IP>:/etc/ssl/certs/jp.yourdomain.com.pem
scp key.pem xcy@<VPS_IP>:/etc/ssl/certs/jp.yourdomain.com.key
```

### 3. 配置 Xray

编辑 `/usr/local/etc/xray/config.json`：

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "UUID要自己生成",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/jp.yourdomain.com.pem",
              "keyFile": "/etc/ssl/certs/jp.yourdomain.com.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/websocket路径"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

生成 UUID：

```bash
cat /proc/sys/kernel/random/uuid
# 出来一串类似：3b8e9b72-0a3c-4f1d-8c5e-2f7a9d1e4c6b
```

路径（path）随便写一串，比如 `/vl1234`，不要用 `/ws` 这种太明显的。

### 4. 配置防火墙

```bash
# 放行 443 端口
ufw allow 443/tcp
# 或者 iptables
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### 5. 启动 Xray

```bash
systemctl start xray
systemctl enable xray
systemctl status xray
# 看日志
journalctl -u xray -n 20 --no-pager
```

---

## 第三步：Cloudflare 防火墙（可选但推荐）

CF 后台 → Security → WAF，加一条规则只允许你所在国家的 IP：

```
Field: Country  Operator: equals  Value: CN
Action: Block
```

这样非中国的流量直接被 CF 拦截，不会打到你的 VPS。

（注意：这是在 CDN 层拦截，客户端本身不需要是中国的，因为你的流量会先到 CF 再到 VPS）

---

## 第四步：客户端

### 方案 A：用 sing-box（推荐）

服务器上编辑 `/etc/sing-box/config.json`：

```json
{
  "outbounds": [
    {
      "type": "vless",
      "server": "jp.你的域名.com",
      "server_port": 443,
      "uuid": "你的UUID",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "jp.你的域名.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "transport": {
        "type": "ws",
        "path": "/websocket路径"
      }
    },
    {
      "type": "hysteria2",
      "server": "156.231.116.44",
      "server_port": 你的hy2端口,
      "password": "你的hy2密码",
      "tls": {
        "enabled": false
      }
    }
  ],
  "route": {
    "rules": [
      {
        "outbound": 0  // 默认走 VLESS (CF)
      }
    ]
  }
}
```

### 方案 B：V2RayNG / Nekoray（桌面端）

配置模板：

```
地址：jp.你的域名.com
端口：443
用户ID：你的UUID
加密：none
传输协议：WebSocket
伪装域名：jp.你的域名.com
路径：/websocket路径
传输安全：TLS
ALPN：h2,http/1.1
```

### 方案 C：Clash Meta 内核

```yaml
proxies:
  - name: "JP-VLESS-CF"
    type: vless
    server: jp.你的域名.com
    port: 443
    uuid: 你的UUID
    flow: xtls-rprx-vision
    tls: true
    servername: jp.你的域名.com
    network: ws
    ws-opts:
      path: "/websocket路径"
    utls: true
    client-fingerprint: chrome
```

---

## 第五步：验证是否生效

### 检查 CDN 是否生效

```bash
# 看 IP 是不是 Cloudflare 的
dig jp.你的域名.com +short
# 应该返回 Cloudflare 的 IP（104.x.x.x / 172.x.x.x 开头），而不是你的 VPS IP
```

### 检查代理是否通

```bash
curl -x http://127.0.0.1:你的代理端口 -v https://www.google.com
```

---

## 故障排查

### 502 / 521 错误
Cloudflare 连不上你的 VPS：
- 检查 VPS 上 `ufw` / `iptables` 是否放行了 443
- 检查 Xray 进程是否在运行
- 检查证书路径是否正确

### 能连但很慢
- 尝试修改 WS path，不要用简单路径
- 检查 VPS 到 CF 的延迟（CF 边缘节点尽量选亚洲的）

### 证书错误
- `Full (strict)` 模式下，CF 会验证 VPS 的证书
- 确保 VPS 上的 `cert.pem` 和 `key.pem` 匹配、未过期
- 需要包含完整证书链

---

## 整体架构

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│ 本地客户端 │────▶│ Cloudflare    │────▶│ 日本 VPS     │
│ (VLESS+WS │     │ CDN (443/TCP) │     │ Xray (443)   │
│  +TLS)    │     │ IP 被隐藏     │     │ 主力路线     │
└──────────┘     └──────────────┘     └─────────────┘

┌──────────┐                           ┌─────────────┐
│ 本地客户端 │───────────────────────────▶│ 美国 VPS     │
│ (hy2 UDP) │                           │ Hysteria 2   │
│ 备用线路   │                           │ 低延迟备用    │
└──────────┘                           └─────────────┘
```

一条断自动走另一条。
