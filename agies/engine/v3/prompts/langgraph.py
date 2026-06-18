"""LangGraph architecture-level vulnerability analysis prompt.

Unlike other vulnerability-specific prompts (LFI, RCE, SSRF, …) that analyze
source→sink call chains via tree-sitter, this prompt focuses on LangGraph's
unique architecture-level attack surface:

- gRPC backend (Go core-api-grpc) with no authentication middleware
- Admin Truncate endpoint — unauthenticated data destruction
- Msgpack ext_hook deserialization RCE via checkpoint database write
- Webhook header template injection
- Custom AES encryption with potential CBC-mode weaknesses
- API keys exposed via environment variables
"""

LANGGRAPH_PROMPT_TEMPLATE = """You are analyzing a **LangGraph deployment** for **architecture-level vulnerabilities**.
These are NOT typical source→sink call chains — they are systemic weaknesses in
the LangGraph service architecture that can be exploited independently or chained.

Project Context
{readme_summary}

Architecture Reference
----
LangGraph has a **two-process architecture** in the same Docker container:
1. **Python uvicorn** — HTTP entry point (FastAPI, port 8000)
2. **Go core-api-grpc** — gRPC backend (localhost:50051, 7 services)

The Python HTTP layer calls Go via gRPC for all data operations.
Both processes share the same PostgreSQL database and Redis instance.

**7 gRPC Services (ALL potentially without authentication):**
  - Admin — Truncate (delete all data in Assistants, Checkpointer, Runs, Store, Threads)
  - Assistants — CRUD for assistant configurations
  - Cache — Get/Set cached values
  - Crons — CRUD for scheduled cron jobs
  - Runs — Create, Stream, Cancel, Publish runs
  - Threads — CRUD for conversation threads
  - Checkpointer — Read/write checkpoint state (the ext_hook RCE vector)

{code_block}

Analysis Focus
----
Evaluate whether ANY of the following LangGraph-specific vulnerabilities apply:

### 1. gRPC No-Authentication (Critical)
The Go binary (core-api-grpc) registers **only** DataDog tracing interceptors
(UnaryServerInterceptor / StreamServerInterceptor) — no authentication or
authorization middleware was found. If an attacker can reach the gRPC port
(localhost:50051), all 7 services are accessible without any API key.

Checklist:
- [ ] Is the gRPC port (50051) exposed outside the container?
- [ ] Is there any authentication layer at the Docker network level?
- [ ] Can an SSRF in the Python HTTP layer reach localhost:50051?
- [ ] Is gRPC reflection enabled (allows service discovery)?
- [ ] Are there any network policies (Kubernetes NetworkPolicy, Docker network) restricting gRPC access?

### 2. Admin Truncate — Unauthenticated Data Destruction (High)
The ``adminServerImpl.Truncate`` gRPC handler can truncate ALL data:
  - ``TruncateRequest.GetAssistants()`` — deletes all assistant configs
  - ``TruncateRequest.GetCheckpointer()`` — deletes all checkpoint state
  - ``TruncateRequest.GetRuns()`` — deletes all run history
  - ``TruncateRequest.GetStore()`` — deletes all store data
  - ``TruncateRequest.GetThreads()`` — deletes all threads

The handler checks a boolean flag at ``adminServerImpl+0x08`` before executing
``database/sql.ExecContext`` with a DELETE statement — but no authentication
check is visible in the handler body.

Checklist:
- [ ] Is the Admin gRPC service registered (``RegisterAdminServer``)?
- [ ] Is ``adminServerImpl.Truncate`` callable without auth?
- [ ] What is the boolean flag at offset +0x08? (config flag to enable/disable?)
- [ ] Is there a network-layer ACL on the Admin service?
- [ ] Can this be chained with a gRPC SSRF for full data loss?

### 3. Msgpack ext_hook Deserialization RCE (High, requires DB access)
The Python ``jsonplus.py`` serialization layer uses **msgpack by default** with
an ``ext_hook`` that reconstructs arbitrary Python objects via:
  ``importlib.import_module(module) → getattr(class) → constructor(args)``

This is a **documented** but **unmitigated** design choice:
  - Default: ``allowed_msgpack_modules = True`` (all modules allowed)
  - Strict mode: ``LANGGRAPH_STRICT_MSGPACK=true`` (optional)

**Attack chain:** DB write → checkpoint_blobs → crafted msgpack ext bytes
  → Go reads + returns → Python ``serialized_value_from_proto``
  → ``loads_typed("msgpack", ...)`` → ext_hook → ``os.system("id")``

Ext types (all can reach ``import_module``):
  | Type | Encoding | Risk |
  |------|----------|------|
  | 0 | (module, class, arg) | RCE via ``os.system`` |
  | 1 | (module, class, args) | RCE via ``subprocess.Popen`` |
  | 2 | (module, class, kwargs) | RCE via ``os.system`` |

Checklist:
- [ ] Can the attacker write to ``checkpoint_blobs`` table? (SQL injection, direct DB, etc.)
- [ ] Is ``LANGGRAPH_STRICT_MSGPACK`` enabled? (if so, ext_hook is restricted)
- [ ] Is the msgpack ext_hook reachable from any API endpoint?
- [ ] Is ``pickle_fallback`` enabled in ``jsonplus.py``? (alternative deserialization)
- [ ] Can ``cloudpickle`` be triggered instead of msgpack?
- [ ] Is the ``EXPERIMENTAL_DANGEROUS_ALLOW_MSGPROTO`` flag enabled?

### 4. Webhook Header Template Injection (Medium)
The Go config package has ``renderHeaderTemplate`` that applies regex-based
validation on webhook header templates. The ``${{...}}`` placeholder syntax
allows dynamic values, but the function checks for ``${{__INVALID_EXPR__}}``
and other blacklisted patterns.

``config.headerTemplateRe`` — compiled regex in BSS at 0x326c6f8
``config.renderHeaderTemplate`` — at 0xb4dea0

If validation is insufficient, template injection could lead to:
- HTTP request smuggling in webhook calls
- Unauthorized webhook header manipulation
- SSRF via controlled webhook URLs

Checklist:
- [ ] Are webhooks configured with user-controllable template values?
- [ ] Does ``renderHeaderTemplate`` use blacklist (incomplete) vs whitelist?
- [ ] Can the ``${{__INVALID_EXPR__}}`` check be bypassed?
- [ ] Are webhook URLs user-controllable? (SSRF vector)
- [ ] Is ``WebhookURLPolicy`` enforced for all webhook URLs?

### 5. Custom AES Encryption (Medium)
LangGraph supports field-level encryption via ``LANGGRAPH_AES_KEY``:
  - AESEncryptor with Encrypt/Decrypt, EncryptJSON/DecryptJSON, EncryptMap/DecryptMap
  - ``reservedEncryptionKeys`` prevents encrypting system-critical fields
  - ``LANGGRAPH_AES_JSON_KEYS`` — configures which JSON fields to encrypt
  - ``AESJSONDisallowedKeys`` — hardcoded list of keys that cannot be encrypted

**The binary links AES-CBC cipher functions.** If AES-CBC is used without
authentication (HMAC), padding oracle attacks may be possible.

Checklist:
- [ ] Is ``LANGGRAPH_AES_KEY`` configured? (no key = no encryption)
- [ ] What AES mode is used? (CBC vs GCM — CBC without HMAC is vulnerable to padding oracle)
- [ ] Is ``LANGGRAPH_AES_JSON_KEYS`` allowing sensitive fields?
- [ ] Can ``AESJSONDisallowedKeys`` be bypassed via alternate field names?
- [ ] Is key rotation supported? (static key = long-term exposure)
- [ ] Are AES encryption keys stored securely? (env var vs filesystem vs K8s secret)

### 6. API Keys in Environment Variables (Medium)
The Go binary reads multiple API keys from environment variables:
  - ``LANGGRAPH_AES_KEY`` — encryption key
  - ``LANGSMITH_API_KEY`` / ``LANGCHAIN_API_KEY`` — tracing
  - ``LANGCHAIN_API_KEY`` — platform API
  - ``LANGSMITH_CONTROL_PLANE_API_KEY`` — control plane
  - ``CUSTOM_LSD_DD_API_KEY`` / ``LSD_DD_API_KEY`` — Datadog
  - ``LANGGRAPH_WEBHOOKS`` — webhook configuration

Checklist:
- [ ] Can an attacker read environment variables? (SSRF → /proc/self/environ, LFI, RCE)
- [ ] Are API keys logged anywhere? (debug logs, error messages, panic traces)
- [ ] Can API keys be leaked via gRPC error messages?
- [ ] Are keys rotated regularly?
- [ ] Do keys follow least-privilege? (LANGSMITH_API_KEY vs scoped keys)
- [ ] Are keys present in process memory dumps? (core dumps, crash reports)

### 7. gRPC Handler Input Validation (Low-Medium)
Key gRPC handlers that accept user-controllable input:
  - ``runsServerImpl.Create`` (0x17063a0) — creates runs with user payload
  - ``runsServerImpl.Stream`` (0x17079e0) — streams run events
  - ``runsServerImpl.Publish`` (0x1704f60) — publishes messages
  - ``threadsServerImpl.Patch`` (0x17105e0) — patches thread state
  - ``threadsServerImpl.Copy`` (0x17124e0) — copies threads

Checklist:
- [ ] Is input size validated for all gRPC handlers? (no size limits = DoS)
- [ ] Are protobuf messages validated before processing? (malformed messages = crash)
- [ ] Can large messages cause OOM? (unbounded memory allocation)
- [ ] Are there any panic-recovery middlewares? (panic = DoS)
- [ ] Can concurrent requests cause race conditions? (shared state, no locking)

**Synthesis**: Which of these vulnerabilities are actually exploitable in this
specific deployment? Consider network architecture, configuration, and
existing security controls.

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "langgraph",
  "found_issues": ["gRPC_no_auth", "admin_truncate", "msgpack_ext_hook_rce", "template_injection", "crypto_weakness", "api_key_exposure", "handler_input_validation"],
  "confidence": 0-10,
  "analysis": "Explain which LangGraph-specific vulnerabilities apply and the exploitability in this deployment. Be specific about which gRPC services are exposed, which config options are enabled, and what network controls exist.",
  "exploit_scenario": "Describe a concrete end-to-end exploit chain using these vulnerabilities.",
  "mitigation": "What specific configuration changes or patches mitigate each issue?"
}}
```
"""


def build_langgraph_prompt(
    code_block: str = "",
    readme_summary: str = "",
    **kwargs,
) -> str:
    return LANGGRAPH_PROMPT_TEMPLATE.format(
        code_block=code_block or "(architecture-level analysis — no specific code path)",
        readme_summary=readme_summary or "Not available.",
    )
