agies — auditing /tmp/langgraph_codegen-2.2.1

  Languages: Python
  Files: 38


Phase A: Path Discovery
  Backend: tree-sitter
  Functions: 54
    Remote Code Execution: 2 sink(s)
    Local File Inclusion: 2 sink(s)
    ReDoS (Regular Expression DoS): 1 sink(s)

Phase B: Slice Sorting (5 raw paths)
  Body-detected orphans: 2 (no call chain)
  Exploit: 5 + Explore: 0
  Project type: lib

Phase C: README Understanding
  (skipped — library mode)

Phase D: Library Analysis (5 slices)
  [1/5] lfi-000 (get_graph)
  [2/5] rce-001 (verify_generated_files)
  [3/5] redos-002 (main)
  [4/5] rce-003 (gen_graph)
  [5/5] lfi-004 (gen_main)
    ⚠ 9/10 — 1 contradiction(s)
    path bridge: 2 builder + 1 consumer
    Adversary: lfi-000...
    x rebutted
      reason: The sink function `get_graph` calls `get_example_path(graph_name)`
which likely constructs a path using `os.path.join` or similar. However, the 
data flow annotations indicate that the entry point has no identifiable 
parameters and the static engine could not trace variable propagation. The 
function `get_graph` takes `graph_name` as a parameter, but there is no evidence
that this parameter is attacker-controlled. The simulated wrapper suggests 
untrusted input reaches the library, but the actual library code does not show 
any external API that accepts user input. Without a clear path from untrusted 
input to `graph_name`, the vulnerability is not exploitable.
    Evidence: lfi-000...
    ? 10/10 — interesting
    Evidence: redos-002...
    ? pattern matched (5 match(es))
    ? pattern matched (1 match(es))
    ⚠ 9/10 — 1 contradiction(s)
    path bridge: 2 builder + 4 consumer
    Adversary: lfi-004...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: rce-003...
    not rebutted
      weak point: The finding relies on the assumption that get_example_path 
does not sanitize path traversal and that the generated code is executed by the 
caller. Both are plausible given the code structure and lack of validation.
    PoC Agent: rce-003...
    ⚠ 9/10 — 1 contradiction(s)
    Adversary: rce-001...
    x rebutted
      reason: The sink function `gen_main` does not accept any user-controlled 
input. It takes `basename` and `state_class` as parameters, which are derived 
from the input file name and parsed state, not from untrusted user input. The 
`basename` is obtained via `input_path.stem` after resolving the input file 
path, which is validated to exist and is not attacker-controlled. The 
`state_class` is parsed from the file content, which is also not directly 
user-controlled. There is no path traversal vulnerability because the sink does 
not use any untrusted data to construct file paths. The finding incorrectly 
assumes that `gen_main` is reachable with attacker-controlled input, but the 
data flow shows that all inputs to `gen_main` are derived from the validated 
input file, not from untrusted user input.
    Evidence: lfi-004...
    not rebutted
      weak point: The attacker controls `basename` via `input_file`, and 
`verify_generated_files` executes a file named `{basename}_graph.py` without 
validation. If the attacker can write a malicious file to the output directory 
(e.g., via path traversal or by controlling the input file content), they can 
achieve RCE. The `--verify` flag is attacker-controlled, making the sink 
reachable.
    PoC Agent: rce-001...
    ? pattern matched (5 match(es))
    PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_codegen-2.2.1/rce_python_subproces
s_verify_generated_files_2.py
    Evidence: rce-001...
    evidence found (7 match(es))
      PoC: 1. Create a malicious Python file named `exploit_graph.py` with 
content: `import os; os.system('id > /tmp/pwned')`
2. Create a dummy `.lgraph` file na...
    PoC: 
/home/xcy/workSpace/code-agies/pocs/langgraph_codegen-2.2.1/rce_python_code_stri
ngs_graph_gen_graph.py
    Evidence: rce-003...
    evidence found (7 match(es))
      PoC: Create a file at /tmp/evil.graph containing: {"START": {"state": 
"MessageGraph", "edges": []}, "exec('import os; os.system(\"id\")')": {"state": 
"Mess...

Phase E: Results
  Blackboard: 2 cached intents, 19 knowledge entries, 5 phase results
  High confidence (3):
    rce-001: subprocess.run — logic_gap
      1. Create a file named `test.lgraph` with content that causes `basename` 
to be `test`. 2. Place a malicious Python file named `test_graph.py` in the same
directory (or use path traversal in `input_file` to point to a directory where 
attacker controls files). 3. Run `lgcodegen test.lgraph --verify`. The 
`verify_generated_files` function will execute `test_graph.py`, achieving RCE.
    redos-002: ? — ?
      
    rce-003: exec/eval/compile — logic_gap
      Create a file at /tmp/evil.graph containing: 'START': {'state': 
'MessageGraph', 'edges': []}, 'exec("import os; os.system("id")")': {'state': 
'MessageGraph', 'edges': []}. Then call get_graph('../../tmp/evil') to trigger 
code execution.

Pipeline Complete
  Target: /tmp/langgraph_codegen-2.2.1
  Model: deepseek-chat
  Duration: 87.5s
  Paths discovered: 5
  Slices analyzed: 5
  Findings: 3 high, 2 interesting
  Tokens: 80,320 total (62,717 prompt + 17,603 completion)

  Recommended verification targets:
    RCE rce-001: The entry point `main()` accepts `args.input_file` from the 
attacker (line 55). The `basename` is de
    REDOS redos-002: Code-level pattern evidence (1 matches): ?:graph_spec = 
re.sub(
    RCE rce-003: The entry point is `get_graph(graph_name)`, which takes 
user-controlled `graph_name`. It calls `get_

v3 CodeQL pipeline complete.
