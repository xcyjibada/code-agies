"""Tool definitions for the audit agent."""

from .file_ops import read_file, list_directory
from .search import grep_search
from .command import run_command
from .report import write_report, reset_findings, get_findings, set_analyzer_result, get_taint_flows
from .index_tools import (
    lookup_function, find_callers, find_callees, set_index,
    get_call_chain_logic, record_knowledge, set_state,
)

__all__ = [
    "read_file", "list_directory", "grep_search", "run_command",
    "write_report", "reset_findings", "get_findings", "set_analyzer_result", "get_taint_flows",
    "lookup_function", "find_callers", "find_callees", "set_index",
    "get_call_chain_logic", "record_knowledge", "set_state",
]


def get_tool_definitions():
    """Return list of all tool definitions (function + JSON schema)."""
    return [
        {
            "name": "read_file",
            "fn": read_file,
            "schema": {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file or a range of lines from a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Absolute path to the file"},
                            "start_line": {"type": "integer", "description": "Starting line number (1-based)"},
                            "end_line": {"type": "integer", "description": "Ending line number (inclusive)"},
                        },
                        "required": ["path"],
                    },
                },
            },
        },
        {
            "name": "list_directory",
            "fn": list_directory,
            "schema": {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List files and directories in a path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Directory path to list"},
                        },
                        "required": ["path"],
                    },
                },
            },
        },
        {
            "name": "grep_search",
            "fn": grep_search,
            "schema": {
                "type": "function",
                "function": {
                    "name": "grep_search",
                    "description": "Search for a pattern in files using ripgrep",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Search pattern (regex)"},
                            "path": {"type": "string", "description": "Directory or file to search in"},
                            "glob": {"type": "string", "description": "File glob filter (e.g. *.py)"},
                        },
                        "required": ["pattern", "path"],
                    },
                },
            },
        },
        {
            "name": "run_command",
            "fn": run_command,
            "schema": {
                "type": "function",
                "function": {
                    "name": "run_command",
                    "description": "Run a shell command (read-only recommended)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Shell command to execute"},
                            "timeout": {"type": "integer", "description": "Timeout in seconds"},
                        },
                        "required": ["command"],
                    },
                },
            },
        },
        {
            "name": "write_report",
            "fn": write_report,
            "schema": {
                "type": "function",
                "function": {
                    "name": "write_report",
                    "description": "Write a finding or report section to the audit report",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "description": "Finding title"},
                            "severity": {"type": "string", "description": "Severity: critical/high/medium/low/info"},
                            "detail": {"type": "string", "description": "Detailed description of the finding"},
                            "file_path": {"type": "string", "description": "Related file path"},
                            "line_number": {"type": "integer", "description": "Related line number"},
                            "suggestion": {"type": "string", "description": "Fix suggestion"},
                            "confidence": {"type": "string", "description": "L1(pattern match) / L2(data flow confirmed) / L3(full chain confirmed)"},
                        },
                        "required": ["title", "detail", "confidence"],
                    },
                },
            },
        },
        {
            "name": "get_taint_flows",
            "fn": get_taint_flows,
            "schema": {
                "type": "function",
                "function": {
                    "name": "get_taint_flows",
                    "description": "Query structured taint flow data from static analysis. Filter by severity, file, or sink type.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "description": "Filter by severity: critical/high/medium/low/info"},
                            "file_glob": {"type": "string", "description": "Filter by file path substring"},
                            "sink_name": {"type": "string", "description": "Filter by sink function name"},
                            "limit": {"type": "integer", "description": "Max results to return (default 20)"},
                        },
                    },
                },
            },
        },
        {
            "name": "lookup_function",
            "fn": lookup_function,
            "schema": {
                "type": "function",
                "function": {
                    "name": "lookup_function",
                    "description": "Find functions by name in the FunctionIndex. Optionally filter by file path substring.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Function name to search for"},
                            "file_glob": {"type": "string", "description": "Optional file path substring filter"},
                        },
                        "required": ["name"],
                    },
                },
            },
        },
        {
            "name": "find_callers",
            "fn": find_callers,
            "schema": {
                "type": "function",
                "function": {
                    "name": "find_callers",
                    "description": "Find functions that directly call a given function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Function name to find callers of"},
                        },
                        "required": ["name"],
                    },
                },
            },
        },
        {
            "name": "find_callees",
            "fn": find_callees,
            "schema": {
                "type": "function",
                "function": {
                    "name": "find_callees",
                    "description": "Find functions called by a given function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Function name to find callees of"},
                        },
                        "required": ["name"],
                    },
                },
            },
        },
        {
            "name": "record_knowledge",
            "fn": record_knowledge,
            "schema": {
                "type": "function",
                "function": {
                    "name": "record_knowledge",
                    "description": "Record a discovered fact for cross-agent knowledge sharing. Call this after discovering something meaningful (call chain, auth bypass, etc.) so future agents working on the same functions benefit.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Function name or file path the knowledge relates to (e.g. 'verify_user' or 'app/dao.py')"},
                            "value": {"type": "string", "description": "Free-text summary of what was discovered, 1-3 sentences"},
                        },
                        "required": ["key", "value"],
                    },
                },
            },
        },
        {
            "name": "get_call_chain_logic",
            "fn": get_call_chain_logic,
            "schema": {
                "type": "function",
                "function": {
                    "name": "get_call_chain_logic",
                    "description": "Return a compact logic dossier for the call chain from entry_function to sink_function. Uses the FunctionIndex call graph + tree-sitter logic extraction to produce a one-page summary. After reviewing the dossier, use record_knowledge to persist any meaningful chain discoveries.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "sink_function": {"type": "string", "description": "Function name at the end of the call chain (the vulnerable sink)"},
                            "entry_function": {"type": "string", "description": "Optional entry-point function. If empty, finds all paths to sink_function."},
                            "max_depth": {"type": "integer", "description": "Maximum call-chain depth (default 12)"},
                        },
                        "required": ["sink_function"],
                    },
                },
            },
        },
    ]

