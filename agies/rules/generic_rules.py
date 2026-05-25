"""Generic audit rules (language-agnostic)."""

from . import AuditRule, RuleSet


class HardcodedSecrets(AuditRule):
    name = "Hardcoded Secrets"
    description = "Detect hardcoded API keys, passwords, tokens, and secrets."
    language = None

    def get_prompt_instructions(self) -> str:
        return """
Look for:
- Hardcoded API keys, tokens, or passwords
- AWS/GCP/Azure credential patterns
- JWT tokens, private keys (BEGIN RSA/EC/OPENSSH PRIVATE KEY)
- Database connection strings with embedded credentials
- OAuth client secrets, Slack tokens, GitHub tokens

Report each finding with the file path, line number, and the type of secret found.
""".strip()


class DangerousFilePermissions(AuditRule):
    name = "Dangerous File Permissions"
    description = "Check for dangerous file permission settings."
    language = None

    def get_prompt_instructions(self) -> str:
        return """
Look for:
- Files or configs with 777, 666 permissions
- Umask set to 000
- World-writable files in production configuration
- chmod with overly permissive settings

Report each finding with file path and line number.
""".strip()


def generic_ruleset() -> RuleSet:
    rs = RuleSet("Generic Security")
    rs.add(HardcodedSecrets())
    rs.add(DangerousFilePermissions())
    return rs
