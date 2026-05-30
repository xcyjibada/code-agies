#!/usr/bin/env python3
"""Test MappingAgent against a real project with a real LLM.

Usage:
  # Use default model (deepseek-chat)
  python tests/test_mapping_real.py /path/to/project

  # Use a specific model
  python tests/test_mapping_real.py /path/to/project --model claude-sonnet-4-6

  # Use Ollama (no API key needed if running locally)
  python tests/test_mapping_real.py /path/to/project --model ollama/llama3
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main() -> None:
    parser = argparse.ArgumentParser(description="Test MappingAgent against a real project")
    parser.add_argument("project_path", help="Path to the project to analyze")
    parser.add_argument("--model", default="deepseek-chat", help="LLM model name")
    parser.add_argument("--max-chars", type=int, default=12000, help="Max chars in output")
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    if not os.path.exists(project_path):
        print(f"Error: {project_path} does not exist")
        sys.exit(1)

    print(f"Project: {project_path}")
    print(f"Model:   {args.model}")
    print()

    # --- Create LLM ---
    try:
        from agies.llm import get_model
        llm = get_model(args.model)
    except Exception as e:
        print(f"Error creating LLM: {e}")
        print()
        print("Available models:")
        print("  deepseek-chat  (requires DEEPSEEK_API_KEY)")
        print("  claude-*       (requires ANTHROPIC_API_KEY)")
        print("  gpt-*          (requires OPENAI_API_KEY)")
        print("  ollama/*       (requires Ollama running locally)")
        sys.exit(1)

    if not llm.api_key:
        print(f"Warning: {llm.env_key_name} is not set. The API call may fail.")
        print()

    # --- Create MappingAgent ---
    from agies.engine.v2.agents.mapping import MappingAgent

    agent = MappingAgent()

    print("Running MappingAgent...")
    print()

    try:
        response = agent.run({"project_path": project_path}, llm)
    except Exception as e:
        print(f"Error during agent execution: {e}")
        sys.exit(1)

    # --- Print results ---
    print("=" * 60)
    print("MAPPING RESULT")
    print("=" * 60)

    if response.content:
        content_preview = response.content[:args.max_chars]
        if len(response.content) > args.max_chars:
            content_preview += "..."
        print(f"\nLLM Response:\n{content_preview}")
        print()

    print(f"\nStructured Output:")
    print(json.dumps(response.output, indent=2, ensure_ascii=False, default=str))

    print(f"\nTool Calls: {len(response.tool_calls)}")
    for tc in response.tool_calls:
        print(f"  - {tc.name}({tc.arguments})")

    print(f"Total Tokens (est): {response.total_tokens}")
    print()

    # --- Validate output against schema ---
    if response.output:
        from agies.engine.v2.agents.mapping import MappingOutput

        print("=" * 60)
        print("SCHEMA VALIDATION")
        print("=" * 60)
        try:
            validated = MappingOutput(**response.output)
            print(f"  ✓ Valid ({len(validated.modules)} modules, "
                  f"{len(validated.key_files)} key files, "
                  f"{len(validated.trust_assumptions)} trust assumptions)")
        except Exception as e:
            print(f"  ✗ Validation failed: {e}")

        if response.output.get("trust_assumptions"):
            print()
            print("Trust Assumptions:")
            for ta in response.output["trust_assumptions"]:
                print(f"  - {ta.get('assumption', '?')}")
                if ta.get("risk_category"):
                    print(f"    risk: {ta['risk_category']}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
