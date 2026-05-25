"""Python-specific audit rules."""

from . import AuditRule, RuleSet


class PythonInjection(AuditRule):
    name = "Code Injection"
    description = "Detect dangerous function calls that can lead to code injection."
    language = "Python"

    def get_prompt_instructions(self) -> str:
        return """
Search for dangerous function calls:
- eval(), exec(), compile() with untrusted input
- __import__() with dynamic module names
- pickle.loads() / pickle.load() from untrusted sources
- os.system(), subprocess.Popen with shell=True and string concatenation
- yaml.load() without SafeLoader

For each finding, trace back to see if the input is user-controlled.
Report with file path, line number, and whether the input is user-controllable.
""".strip()


class PythonSQLInjection(AuditRule):
    name = "SQL Injection"
    description = "Detect SQL injection vulnerabilities in Python code."
    language = "Python"

    def get_prompt_instructions(self) -> str:
        return """
Search for SQL injection patterns:
- f-strings or string concatenation in SQL queries
- .execute(f"...") or .execute("... " + var + " ...")
- raw SQL with .format() using user input
- Django RawSQL, extra(), or connection.cursor() with string formatting
- SQLAlchemy text() with concatenated parameters

Report each finding with file path and line number.
""".strip()


class PythonPathTraversal(AuditRule):
    name = "Path Traversal"
    description = "Detect path traversal vulnerabilities."
    language = "Python"

    def get_prompt_instructions(self) -> str:
        return """
Search for path traversal patterns:
- open(), os.path.join() using user-supplied filenames
- send_file() with user-controlled paths
- os.remove(), os.unlink(), shutil.rmtree() with user input
- zipfile.extractall() without path sanitization

Report each finding with file path, line number, and the source of user input.
""".strip()


def python_ruleset() -> RuleSet:
    rs = RuleSet("Python Security")
    rs.add(PythonInjection())
    rs.add(PythonSQLInjection())
    rs.add(PythonPathTraversal())
    return rs
