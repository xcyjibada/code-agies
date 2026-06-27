/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { PresetTemplate, VulnType } from "./types";

export const PRESET_TEMPLATES: PresetTemplate[] = [
  {
    id: "zipp-cve-2024-5569",
    name: "zipp Path Traversal (CVE-2024-5569)",
    description: "Path Traversal vulnerability in standard python path-construction where custom zipfile processing allows bypass via custom relative operators and '/' operator overrides.",
    vulnType: VulnType.LFI,
    readme: `# Standard Zip Utility Library
A modern, self-contained Python wrapper for processing compressed zip files with optimized lookup indices.

## Usage
Provide input archived files and request file extraction or direct stream read paths via standard entrypoints.`,
    files: [
      {
        filePath: "zipp/core.py",
        code: `class CompletePath:
    def __init__(self, root, at=""):
        self.root = root
        self.at = at

    def __truediv__(self, next_node):
        # Python override for '/' division operator
        # Shortcut mapping directly to our main path join utility
        return self.joinpath(next_node)

    def joinpath(self, *parts):
        # Joins relative path segments inside the zip archive file structure
        # Critical bypass target: does path clean bypass with nested relative components?
        joined = os.path.join(self.at, *parts)
        if parts and parts[0].startswith("/"):
            # If absolute component is passed under '/', we force relative
            joined = parts[0].lstrip("/")
        return CompletePath(self.root, at=joined)

    def open(self, mode="r"):
        # Returns a stream. Relies on the consumer to handle actual container reads.
        cleaned_path = self.at.replace("../", "") # single pass naive sanitize
        full_physical_target = self.root.resolve_real_path(cleaned_path)
        return open(full_physical_target, mode)`
      },
      {
        filePath: "zipp/consumer.py",
        code: `class ZipArchiveReader:
    def __init__(self, archive_file):
        self.path_root = CompletePath(root=archive_file, at="")

    def read_text(self, target_filepath, encoding="utf-8"):
        # The ultimate user-facing lookup helper
        # Vulnerability happens back here: calling Open directly using overridden '/' operators
        target_node = self.path_root / target_filepath
        with target_node.open("r") as f:
            return f.read()`
      }
    ]
  },
  {
    id: "naive-lfi-sanitize",
    name: "Single-Pass SafeLFI Path Naive Sanitizer",
    description: "Naively strips '..' from paths. Shows how agies v3 flags bypass potential during sorting and uses LLM Logic Agent to identify contradictions in sanitization promises.",
    vulnType: VulnType.LFI,
    readme: `# Simple Static File Delivery Endpoint
Delivers static resources securely inside the designated repository files.
Ensures no active path traverses outside of public folder.`,
    files: [
      {
        filePath: "utils/path_cleaner.ts",
        code: `export function sanitizePath(inputPath: string): string {
  // Naive bypass: removes target '..' sequence only once.
  // Inputting '....//' yields '..' after single pass, allowing LFI.
  const cleaned = inputPath.replace("../", "");
  return cleaned;
}`
      },
      {
        filePath: "controllers/asset_controller.ts",
        code: `import { sanitizePath } from "../utils/path_cleaner";
import * as fs from "fs";
import * as path from "path";

export function handleAssetRequest(req: any, res: any) {
  const reqFilename = req.query.filename || "default.png";
  
  // Node 1: retrieve clean file path
  const sanitized = sanitizePath(reqFilename);
  
  // Node 2: Combine with public dir and feed to fs.readFile
  const physicalPath = path.join("/opt/app/public", sanitized);
  
  fs.readFile(physicalPath, "utf-8", (err, data) => {
    if (err) return res.status(404).json({ error: "File not found" });
    res.send(data);
  });
}`
      }
    ]
  },
  {
    id: "eval-rce",
    name: "Python Unsanitized eval() RCE",
    description: "Exposes a remote evaluation calculator. Highlights standard Remote Code Execution (RCE) via direct call of python eval() and subprocess bindings.",
    vulnType: VulnType.RCE,
    readme: `# Math Evaluation Server
A micro-webservice to parse and isolate complex arithmetic expressions for mathematical modeling.`,
    files: [
      {
        filePath: "app/calculator.py",
        code: `def evaluate_expression(user_formula, scope_dict=None):
    # Evaluates arbitrary formulas safely?
    # No input checks are done, opening up complete RCE
    local_scope = scope_dict or {}
    return eval(user_formula, {"__builtins__": None}, local_scope)`
      },
      {
        filePath: "app/routes.py",
        code: `from app.calculator import evaluate_expression
from flask import request, jsonify

@app.route("/api/compute")
def api_compute():
    expression = request.args.get("expr", "1+1")
    
    # Calls expression resolver on user parameters directly
    computed_value = evaluate_expression(expression)
    return jsonify({"result": computed_value})`
      }
    ]
  },
  {
    id: "sqli-bypass",
    name: "SQL Injection with custom single-replace sanitizer",
    description: "Custom query router sanitizing only specific keywords and utilizing unsafe direct string interpolation rather than parameterized queries.",
    vulnType: VulnType.SQLI,
    readme: `# Inventory Lookup Portal
Supports remote SKU inquiries using flexible filters in SQL databases.`,
    files: [
      {
        filePath: "db/sanitizer.py",
        code: `def filter_sql_inject(query_param: str) -> str:
    # Intended to remove malicious SQL command verbs
    # naive string replace lets attackers craft payloads with lower/uppercase variations
    cleaned = query_param.replace("UNION", "").replace("SELECT", "")
    return cleaned`
      },
      {
        filePath: "db/connector.py",
        code: `import sqlite3
from db.sanitizer import filter_sql_inject

def query_sku_stock(sku_id: str):
    # Node 1: Clean SKU parameter
    safe_sku = filter_sql_inject(sku_id)
    
    # Node 2: Broken string interpolation
    query = f"SELECT * FROM inventory WHERE sku = '{safe_sku}' AND active = 1"
    
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(query) # Sink Execution
    return cursor.fetchall()`
      }
    ]
  }
];
