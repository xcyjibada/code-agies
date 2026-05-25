"""JavaScript/TypeScript-specific audit rules."""

from . import AuditRule, RuleSet


class XSS(AuditRule):
    name = "Cross-Site Scripting (XSS)"
    description = "Detect XSS vulnerabilities in JavaScript/TypeScript code."
    language = "JavaScript"

    def get_prompt_instructions(self) -> str:
        return """
Search for XSS patterns:
- innerHTML, outerHTML, insertAdjacentHTML with user input
- dangerouslySetInnerHTML in React
- document.write() with unsanitized input
- URL params or hash used directly in DOM manipulation
- v-html in Vue.js
- eval() of user-controlled strings

Report each finding with file path, line number, and the data flow source.
""".strip()


class PrototypePollution(AuditRule):
    name = "Prototype Pollution"
    description = "Detect prototype pollution vulnerabilities."
    language = "JavaScript"

    def get_prompt_instructions(self) -> str:
        return """
Search for prototype pollution patterns:
- Object.assign() with user-controlled input
- Recursive merge functions (merge, deepMerge, extend)
- [key] assignment without hasOwnProperty check
- Express body-parser with type: 'application/json' used in unsafe merges
- Lodash merge with unsanitized input

Report each finding with file path and line number.
""".strip()


class InsecureDependency(AuditRule):
    name = "Insecure Dependency Usage"
    description = "Detect use of known dangerous npm patterns."
    language = "JavaScript"

    def get_prompt_instructions(self) -> str:
        return """
Search for insecure dependency patterns:
- require('child_process').exec with user input
- execSync, spawn with shell=true and user-controlled args
- eval() or new Function() with dynamic code
- Regular expression DoS patterns (ReDoS)
- Using crypto.createHash without proper algorithm

Report each finding with file path and line number.
""".strip()


def js_ruleset() -> RuleSet:
    rs = RuleSet("JavaScript/TypeScript Security")
    rs.add(XSS())
    rs.add(PrototypePollution())
    rs.add(InsecureDependency())
    return rs
