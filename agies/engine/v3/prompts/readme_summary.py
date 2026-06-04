"""README summary prompt — 1-shot LLM call to inject project context."""

README_PROMPT = """Read this README and summarize the project's security-relevant context.

Focus on what matters for security analysis:

1. **What kind of project is this?** (web app, CLI tool, library, AI model server, …)
2. **What are the entry points?** (HTTP endpoints, CLI commands, message queue consumers, …)
3. **Authentication model** (API keys, JWT, OAuth, sessions, no auth, …)
4. **Data handling** (does the project accept user uploads, process URLs, render user content, query databases, …)
5. **Third-party dangerous APIs** (does it use exec/eval, subprocess, pickle, yaml.load, …)
6. **Security mechanisms** (any mentioned: CSP, auth middleware, input validation, WAF, …)

README content:
```
{readme_text}
```

Output a concise JSON summary (2-3 sentences per field, max 500 tokens):
```json
{{
  "project_type": "...",
  "entry_points": "...",
  "authentication": "...",
  "data_handling": "...",
  "dangerous_apis": "...",
  "security_mechanisms": "...",
  "risk_assessment": "Low / Medium / High — one sentence why"
}}
```
"""


def build_readme_prompt(readme_text: str) -> str:
    """Build the README summary prompt."""
    return README_PROMPT.format(readme_text=readme_text)
