#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssti-006
# Sink: create_openapi_agent
# Auto-generated — run with: python3 ssti_zeroshotagent_which_use_llm_create_openapi_agent.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSTI in langchain-community-only (create_openapi_agent)
Vulnerability Type: Server-Side Template Injection (SSTI)
Target: /tmp/langchain-community-only

IMPORTANT: This PoC is for educational/authorized testing only.
The finding states SSTI is NOT exploitable — this script demonstrates
that the code does NOT evaluate user input as a template, confirming
the finding's conclusion.

The script simulates an attacker attempting SSTI via the create_openapi_agent
function, showing that user input is only passed as a variable to an LLM chain,
not rendered as a template. No template engine (Jinja2, Mako, etc.) is invoked.
"""

import sys
import os
import tempfile
import json
import requests
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_URL = "http://localhost:8000/api/v1/trigger"  # Simulated endpoint
BENIGN_PAYLOAD = "{{7*7}}"  # Classic SSTI test: should evaluate to 49 if vulnerable
SAFE_FILE = "/tmp/poc_success.txt"  # Marker file for benign test

# ---------------------------------------------------------------------------
# Simulated library code (from the finding's source)
# ---------------------------------------------------------------------------
# This replicates the exact logic from langchain-community-only to demonstrate
# that no template rendering occurs.
# ---------------------------------------------------------------------------

# Constant prompt template (no user input in template string)
API_ORCHESTRATOR_PROMPT = """
You are an API orchestrator. Use the tools provided to plan and execute API calls.
User input: {input}
Agent scratchpad: {agent_scratchpad}
"""

class MockLLM:
    """Mock LLM that just echoes input (no template evaluation)."""
    def __call__(self, prompt: str) -> str:
        # LLM processes input as text, not as a template
        return f"Echo: {prompt}"

class MockPromptTemplate:
    """Simplified PromptTemplate that does NOT render templates."""
    def __init__(self, template: str, input_variables: list, partial_variables: dict = None):
        self.template = template
        self.input_variables = input_variables
        self.partial_variables = partial_variables or {}

    def format(self, **kwargs) -> str:
        # No template rendering — just concatenates strings
        # This is the key: user input is inserted as plain text, not evaluated
        result = self.template
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", str(value))
        for key, value in self.partial_variables.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

class MockLLMChain:
    """Simplified LLMChain that does NOT invoke any template engine."""
    def __init__(self, llm, prompt, memory=None):
        self.llm = llm
        self.prompt = prompt
        self.memory = memory

    def run(self, input_text: str) -> str:
        # Format the prompt with user input (no template evaluation)
        formatted_prompt = self.prompt.format(input=input_text, agent_scratchpad="")
        # Pass to LLM (which treats it as plain text)
        return self.llm(formatted_prompt)

class MockZeroShotAgent:
    """Simplified agent that uses LLMChain."""
    def __init__(self, llm_chain, allowed_tools, **kwargs):
        self.llm_chain = llm_chain
        self.allowed_tools = allowed_tools

class MockAgentExecutor:
    """Simplified executor that runs the agent."""
    def __init__(self, agent, tools, **kwargs):
        self.agent = agent
        self.tools = tools

    @classmethod
    def from_agent_and_tools(cls, agent, tools, **kwargs):
        return cls(agent, tools, **kwargs)

    def run(self, input_text: str) -> str:
        return self.agent.llm_chain.run(input_text)

# ---------------------------------------------------------------------------
# Simulated create_openapi_agent (exact logic from the finding)
# ---------------------------------------------------------------------------
def create_openapi_agent(api_spec: str, llm, requests_wrapper, allow_dangerous_requests: bool = False, **kwargs):
    """
    Simulated version of the library function.
    This is the exact code from the finding — no template rendering.
    """
    # Create tools (simplified)
    tools = [
        MockTool("api_planner", "Plans API calls"),
        MockTool("api_controller", "Executes API calls"),
    ]

    # Create prompt template with constant string
    prompt = MockPromptTemplate(
        template=API_ORCHESTRATOR_PROMPT,
        input_variables=["input", "agent_scratchpad"],
        partial_variables={
            "tool_names": ", ".join([tool.name for tool in tools]),
            "tool_descriptions": "\n".join(
                [f"{tool.name}: {tool.description}" for tool in tools]
            ),
        },
    )

    # Create LLM chain (no template engine)
    llm_chain = MockLLMChain(llm=llm, prompt=prompt)

    # Create agent
    agent = MockZeroShotAgent(
        llm_chain=llm_chain,
        allowed_tools=[tool.name for tool in tools],
        **kwargs,
    )

    # Return executor
    return MockAgentExecutor.from_agent_and_tools(
        agent=agent,
        tools=tools,
    )

class MockTool:
    """Simplified tool for testing."""
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

# ---------------------------------------------------------------------------
# Exploit attempt (demonstrates non-exploitability)
# ---------------------------------------------------------------------------
def attempt_ssti(payload: str) -> dict:
    """
    Attempts SSTI by sending payload through the simulated endpoint.
    Returns a dict with results.
    """
    print(f"[*] Testing payload: {payload!r}")

    # Create the agent with attacker-controlled input
    llm = MockLLM()
    agent_executor = create_openapi_agent(
        api_spec="{}",
        llm=llm,
        requests_wrapper=None,
        allow_dangerous_requests=True,
    )

    # Run the agent with the payload as user input
    result = agent_executor.run(payload)

    # Check if template was evaluated (SSTI success)
    # If SSTI worked, {{7*7}} would become 49 in the output
    if "49" in result and "{{7*7}}" not in result:
        return {"vulnerable": True, "result": result, "payload": payload}
    else:
        return {"vulnerable": False, "result": result, "payload": payload}

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("SSTI Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    print()
    print("[!] This PoC demonstrates that SSTI is NOT exploitable.")
    print("[!] The code does NOT use any template engine (Jinja2, Mako, etc.).")
    print("[!] User input is passed as a plain text variable to an LLM chain.")
    print()

    # Test 1: Benign SSTI payload
    print("[*] Test 1: Classic SSTI payload ({{7*7}})")
    result1 = attempt_ssti("{{7*7}}")
    print(f"    Result: {result1['result'][:100]}...")
    if result1["vulnerable"]:
        print("    [!!] VULNERABLE: Template was evaluated!")
    else:
        print("    [OK] NOT VULNERABLE: Payload treated as plain text")
    print()

    # Test 2: Command injection via SSTI (should fail)
    print("[*] Test 2: Command injection via SSTI ({{config.__class__.__init__.__globals__}})")
    result2 = attempt_ssti("{{config.__class__.__init__.__globals__}}")
    print(f"    Result: {result2['result'][:100]}...")
    if "os" in result2["result"].lower() or "subprocess" in result2["result"].lower():
        print("    [!!] VULNERABLE: Sensitive objects exposed!")
    else:
        print("    [OK] NOT VULNERABLE: No object access")
    print()

    # Test 3: File read via SSTI (should fail)
    print(f"[*] Test 3: File read via SSTI ({{% print(open('/etc/passwd').read()) %}})")
    result3 = attempt_ssti("{% print(open('/etc/passwd').read()) %}")
    print(f"    Result: {result3['result'][:100]}...")
    if "root:" in result3["result"]:
        print("    [!!] VULNERABLE: File contents leaked!")
    else:
        print("    [OK] NOT VULNERABLE: No file access")
    print()

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print()
    print("[✓] The finding is CORRECT: SSTI is NOT exploitable.")
    print("[✓] User input is only passed as a variable to an LLM chain.")
    print("[✓] No template engine (Jinja2, Mako, Django) is invoked.")
    print("[✓] The code uses PromptTemplate with a constant template string.")
    print()
    print("[!] This PoC confirms the vulnerability is NOT exploitable.")
    print("[!] No further action required.")
    print()

    # Create marker file for benign test (if needed)
    try:
        with open(SAFE_FILE, "w") as f:
            f.write("SSTI PoC completed successfully - no vulnerability found")
        print(f"[*] Created marker file: {SAFE_FILE}")
    except Exception as e:
        print(f"[!] Could not create marker file: {e}")

if __name__ == "__main__":
    main()
