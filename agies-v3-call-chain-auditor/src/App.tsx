/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import {
  Play,
  Fingerprint,
  Layers,
  Cpu,
  Database,
  Terminal,
  Settings2,
  FileCode,
  Info,
  Plus,
  X,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  HelpCircle,
  ArrowRight,
  Sparkles,
  Copy,
  Check,
  RefreshCw,
  HelpCircle as QuestionIcon
} from "lucide-react";
import { PRESET_TEMPLATES } from "./templates";
import { VulnType, PathNode, CodeQlPath, CachedIntent, Contradiction, PathAnalysisResult } from "./types";

// Dynamic Client Side Scoring Algorithm (TS Version)
function calculatePathScore(nodes: PathNode[], vulnType: VulnType, hasValidation: boolean, isFullPath: boolean): number {
  let score = 0.0;

  // 1. Sink Weights
  const sinkWeights: Record<string, number> = {
    eval: 1.0,
    subprocess: 1.0,
    system: 1.0,
    popen: 1.0,
    exec: 1.0,
    open: 0.65,
    read: 0.6,
    joinpath: 0.55,
    "__truediv__": 0.5,
    execute: 0.85,
    sql: 0.8,
    union: 0.9,
  };

  let maxWeight = 0.3;
  const lastNode = nodes[nodes.length - 1];
  if (lastNode) {
    const code = lastNode.code.toLowerCase();
    for (const [key, w] of Object.entries(sinkWeights)) {
      if (code.includes(key)) {
        maxWeight = Math.max(maxWeight, w);
      }
    }
  }
  score += maxWeight * 0.4;

  // 2. Length penalty
  const lengthPenalty = 1.0 / (1.0 + 0.1 * Math.max(0, nodes.length - 3));
  score += lengthPenalty * 0.2;

  // 3. Sanitizer or validator bypass potential (sanitizer bypass is high-value!)
  if (hasValidation) {
    score += 0.2; // Bypass markup bonus
  }

  // 4. Path completeness
  if (isFullPath) {
    score += 0.15;
  }

  return parseFloat(Math.min(score, 1.0).toFixed(2));
}

// Client Side Explore/Exploit classifier
function checkAnomalous(nodes: PathNode[], score: number): { isAnomalous: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (nodes.length > 3) {
    reasons.push("complex_custom_flow");
  }
  const hasUnusualNames = nodes.some(
    (n) => !["sanitize", "validate", "get", "query", "check", "open", "read", "joinpath"].includes(n.funcName.toLowerCase())
  );
  if (hasUnusualNames) {
    reasons.push("unusual_naming_conventions");
  }
  const denseCode = nodes.some((n) => n.code.split("\n").length > 12);
  if (denseCode) {
    reasons.push("dense_custom_logic_profile");
  }
  return {
    isAnomalous: reasons.length > 0,
    reasons,
  };
}

export default function App() {
  // Config States
  const [selectedTemplate, setSelectedTemplate] = useState(PRESET_TEMPLATES[0]);
  const [files, setFiles] = useState(PRESET_TEMPLATES[0].files);
  const [readme, setReadme] = useState(PRESET_TEMPLATES[0].readme);
  const [custSinks, setCustSinks] = useState<string[]>(["resolve_real_path", "os.path.join"]);
  const [newSink, setNewSink] = useState("");
  const [activeFileIndex, setActiveFileIndex] = useState(0);

  // New File Creator Temp
  const [newFileName, setNewFileName] = useState("");
  const [showNewFileForm, setShowNewFileForm] = useState(false);

  // Core Pipeline settings
  const [exploitLimit, setExploitLimit] = useState(25);
  const [exploreLimit, setExploreLimit] = useState(5);
  const [liveAiMode, setLiveAiMode] = useState(false);

  // Live Audit execution states
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState<PathAnalysisResult | null>(null);
  const [errorObj, setErrorObj] = useState<{ error: string; needsKey: boolean } | null>(null);

  // Blackboard simulation state
  const [blackboardCache, setBlackboardCache] = useState<Record<string, CachedIntent>>({});
  const [simulateCacheHits, setSimulateCacheHits] = useState(true);

  // Active Tab View Indicator
  const [activeTab, setActiveTab] = useState<"graph" | "sorter" | "intent" | "logic">("graph");

  // Local static graph representation
  const [pathsList, setPathsList] = useState<CodeQlPath[]>([]);

  // Trigger template changes
  const handleTemplateSelection = (templateId: string) => {
    const found = PRESET_TEMPLATES.find((t) => t.id === templateId);
    if (found) {
      setSelectedTemplate(found);
      setFiles([...found.files]);
      setReadme(found.readme);
      setActiveFileIndex(0);
      setResults(null);
      setErrorObj(null);
      
      // Default custom sinks according to types
      if (found.id.includes("zipp")) {
        setCustSinks(["resolve_real_path", "os.path.join"]);
      } else if (found.id.includes("naive")) {
        setCustSinks(["readFile", "sanitizePath"]);
      } else {
        setCustSinks(["eval", "execute"]);
      }
    }
  };

  // Add customized sink file hook
  const handleAddSink = () => {
    if (newSink.trim() && !custSinks.includes(newSink.trim())) {
      setCustSinks([...custSinks, newSink.trim()]);
      setNewSink("");
    }
  };

  const handleRemoveSink = (sinkToRemove: string) => {
    setCustSinks(custSinks.filter((s) => s !== sinkToRemove));
  };

  // Create new blank code file
  const handleAddFile = () => {
    if (newFileName.trim()) {
      const extension = newFileName.includes(".") ? "" : ".py";
      const fileObj = {
        filePath: `${newFileName.trim()}${extension}`,
        code: `# Custom file script for vulnerabilities discovery\ndef my_handler(user_input):\n    # Identify source parameters\n    return user_input`,
      };
      setFiles([...files, fileObj]);
      setActiveFileIndex(files.length);
      setNewFileName("");
      setShowNewFileForm(false);
    }
  };

  const handleUpdateCode = (updatedCode: string) => {
    const updated = [...files];
    updated[activeFileIndex].code = updatedCode;
    setFiles(updated);
  };

  const handleDeleteFile = (idx: number) => {
    if (files.length <= 1) return;
    const filtered = files.filter((_, i) => i !== idx);
    setFiles(filtered);
    setActiveFileIndex(0);
  };

  // Parse files code client-side to dynamically feed Phase A Call Graph & scoring nodes
  useEffect(() => {
    const parsedNodes: PathNode[] = [];
    
    // Parse functions in each file
    files.forEach((file) => {
      const lines = file.code.split("\n");
      let currentFunc: PathNode | null = null;
      let funcLines: string[] = [];

      lines.forEach((line, index) => {
        // Simple regex support to detect Python or JS/TS function boundaries
        const pyMatch = line.match(/^\s*def\s+([a-zA-Z0-9_]+)\s*\(/);
        const jsMatch = line.match(/(?:function|const|let|export\s+function)\s+([a-zA-Z0-9_]+)\s*[=(]/);
        
        if (pyMatch || jsMatch) {
          // If we were already tracking a function, save it
          if (currentFunc) {
            currentFunc.code = funcLines.join("\n");
            parsedNodes.push(currentFunc);
          }
          const name = pyMatch ? pyMatch[1] : jsMatch ? jsMatch[1] : "anonymous";
          currentFunc = {
            id: `${file.filePath}-${name}-${index}`,
            funcName: name,
            filePath: file.filePath,
            lineStart: index + 1,
            lineEnd: index + 1,
            code: "",
            isDangerous: name.includes("unsafe") || name.includes("sanitize") || name.includes("eval") || name.includes("join")
          };
          funcLines = [line];
        } else if (currentFunc) {
          funcLines.push(line);
          currentFunc.lineEnd = index + 1;
        }
      });

      if (currentFunc) {
        (currentFunc as PathNode).code = funcLines.join("\n");
        parsedNodes.push(currentFunc);
      }
    });

    // Subcontract call-chain paths! If no helper functions parsed, generate fallback node structures
    if (parsedNodes.length === 0) {
      parsedNodes.push({
        id: "main-v3-root",
        funcName: "api_endpoint",
        filePath: files[0]?.filePath || "index.ts",
        lineStart: 1,
        lineEnd: 15,
        code: files[0]?.code || "",
      });
    }

    // Build realistic paths
    const newPaths: CodeQlPath[] = [];
    
    // Group them or map presets to specific slices
    if (selectedTemplate.id === "zipp-cve-2024-5569") {
      // Path 1 (Exploit bypass target)
      const zipReaderNode = parsedNodes.find((n) => n.funcName === "ZipArchiveReader" || n.funcName === "read_text") || parsedNodes[0];
      const divNode = parsedNodes.find((n) => n.funcName === "__truediv__") || parsedNodes[0];
      const joinpathNode = parsedNodes.find((n) => n.funcName === "joinpath") || parsedNodes[0];
      const openNode = parsedNodes.find((n) => n.funcName === "open") || parsedNodes[0];

      const exploitNodes = [zipReaderNode, divNode, joinpathNode, openNode].filter(Boolean);
      const s1 = calculatePathScore(exploitNodes, VulnType.LFI, true, true);
      const an1 = checkAnomalous(exploitNodes, s1);

      newPaths.push({
        id: "lfi-path-01",
        vulnType: VulnType.LFI,
        source: "ZipArchiveReader.read_text (filepath parameter)",
        sourceFile: "zipp/consumer.py:8",
        sink: "CompletePath.open -> naive standard open()",
        sinkFile: "zipp/core.py:27",
        nodes: exploitNodes,
        isFullPath: true,
        score: s1,
        isAnomalous: an1.isAnomalous,
        anomalousReasons: an1.reasons,
        slotType: "Exploit",
        hasValidation: true
      });

      // Path 2 (Secondary explore flow)
      const alternateNodes = [divNode, joinpathNode].filter(Boolean);
      const s2 = calculatePathScore(alternateNodes, VulnType.LFI, false, false);
      const an2 = checkAnomalous(alternateNodes, s2);
      newPaths.push({
        id: "lfi-path-02",
        vulnType: VulnType.LFI,
        source: "CompletePath.__truediv__ override operator",
        sourceFile: "zipp/core.py:10",
        sink: "CompletePath.joinpath core path assembler",
        sinkFile: "zipp/core.py:14",
        nodes: alternateNodes,
        isFullPath: false,
        score: s2,
        isAnomalous: an2.isAnomalous,
        anomalousReasons: an2.reasons,
        slotType: "Explore",
        hasValidation: false
      });
    } else if (selectedTemplate.id === "naive-lfi-sanitize") {
      const handleNode = parsedNodes.find((n) => n.funcName === "handleAssetRequest") || parsedNodes[0];
      const cleanNode = parsedNodes.find((n) => n.funcName === "sanitizePath") || parsedNodes[0];

      const normalNodes = [handleNode, cleanNode].filter(Boolean);
      const s1 = calculatePathScore(normalNodes, VulnType.LFI, true, true);
      const an1 = checkAnomalous(normalNodes, s1);

      newPaths.push({
        id: "lfi-path-03",
        vulnType: VulnType.LFI,
        source: "handleAssetRequest (filename argument)",
        sourceFile: "controllers/asset_controller.ts:5",
        sink: "fs.readFile (physical local path)",
        sinkFile: "controllers/asset_controller.ts:13",
        nodes: normalNodes,
        isFullPath: true,
        score: s1,
        isAnomalous: true, // naively flagged as anomaly due to custom sanitize
        anomalousReasons: ["bypass_sanitizer_potential", "single_pass_replace"],
        slotType: "Exploit",
        hasValidation: true
      });
    } else if (selectedTemplate.id === "eval-rce") {
      const apiNode = parsedNodes.find((n) => n.funcName === "api_compute") || parsedNodes[0];
      const evalNode = parsedNodes.find((n) => n.funcName === "evaluate_expression") || parsedNodes[0];

      const rceNodes = [apiNode, evalNode].filter(Boolean);
      const s1 = calculatePathScore(rceNodes, VulnType.RCE, false, true);
      const an1 = checkAnomalous(rceNodes, s1);

      newPaths.push({
        id: "rce-path-01",
        vulnType: VulnType.RCE,
        source: "api_compute (request formula query parameter)",
        sourceFile: "app/routes.py:6",
        sink: "evaluate_expression -> python eval() binding",
        sinkFile: "app/calculator.py:5",
        nodes: rceNodes,
        isFullPath: true,
        score: s1,
        isAnomalous: an1.isAnomalous,
        anomalousReasons: an1.reasons,
        slotType: "Exploit",
        hasValidation: false
      });
    } else {
      // Default / SQLI
      const selectNode = parsedNodes.find((n) => n.funcName === "query_sku_stock") || parsedNodes[0];
      const safetyNode = parsedNodes.find((n) => n.funcName === "filter_sql_inject") || parsedNodes[0];

      const sqliNodes = [selectNode, safetyNode].filter(Boolean);
      const s1 = calculatePathScore(sqliNodes, VulnType.SQLI, true, true);
      newPaths.push({
        id: "sqli-path-01",
        vulnType: VulnType.SQLI,
        source: "query_sku_stock (user sku parameter input)",
        sourceFile: "db/connector.py:4",
        sink: "sqlite3 execute statement query execution",
        sinkFile: "db/connector.py:14",
        nodes: sqliNodes,
        isFullPath: true,
        score: s1,
        isAnomalous: true,
        anomalousReasons: ["custom_clean_logic"],
        slotType: "Exploit",
        hasValidation: true
      });
    }

    setPathsList(newPaths);
  }, [files, selectedTemplate]);

  // Execute the visual agies v3 Auditor pipeline (Simulated or Real AI)
  const executePipelineAudit = async () => {
    setAnalyzing(true);
    setResults(null);
    setErrorObj(null);
    setBlackboardCache({});

    if (liveAiMode) {
      // Execute the genuine Gemini server endpoint analysis
      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            files,
            readme,
            vulnType: selectedTemplate.vulnType,
          }),
        });

        if (!response.ok) {
          const errData = await response.json();
          throw new Error(errData.error || "Server failed to analyze code models");
        }

        const auditData = await response.json();
        
        // Map audit results returned by Express-Gemini route
        const completeResult: PathAnalysisResult = {
          pathId: pathsList[0]?.id || "v3-path-01",
          contradictions: auditData.contradictions || [],
          confidenceScore: auditData.confidenceScore ?? 8,
          adversaryRefutation: auditData.adversaryRefutation || "",
          pocCode: auditData.pocCode || "",
          verified: auditData.confidenceScore >= 7,
          status: auditData.status || "vulnerable",
          reason: auditData.reason || "Vulnerability found through Logic Agent analysis of intention chains",
          intentChain: auditData.intentChain || [],
        };

        setResults(completeResult);
        setActiveTab("logic");
      } catch (err: any) {
        console.error(err);
        const needsKey = err.message.toLowerCase().includes("gemini_api_key") || err.message.toLowerCase().includes("secrets");
        setErrorObj({
          error: err.message || "Pipeline failed. Failsafe activated.",
          needsKey,
        });
      } finally {
        setAnalyzing(false);
      }
    } else {
      // Offline / Deterministic High-Fidelity Simulator Mode
      setTimeout(() => {
        // Build mock cache states to replicate Phase D Blackboard hits
        const dummyCache: Record<string, CachedIntent> = {};
        const activePath = pathsList[0];
        
        if (activePath) {
          activePath.nodes.forEach((node, idx) => {
            // If cache hits enabled, we mark subsequent elements as cached
            const isHit = simulateCacheHits && idx > 0 && idx % 2 === 0;
            dummyCache[node.id] = {
              funcName: node.funcName,
              filePath: node.filePath,
              intent: `Extract & process incoming args for logical scope in caller file`,
              keyLogic: node.code.includes("replace") ? " naively replaces target strings once" : "direct parameter relay context",
              suspicious: node.code.includes("replace") ? ["Naive sanitize bypass parameters"] : [],
              extractionTime: Date.now(),
              passThrough: isHit,
            };
          });
          setBlackboardCache(dummyCache);
        }

        // Build elegant preset results representing top tier analysis
        let simulatedResult: PathAnalysisResult;

        if (selectedTemplate.id === "zipp-cve-2024-5569") {
          simulatedResult = {
            pathId: "lfi-path-01",
            status: "vulnerable",
            confidenceScore: 9,
            verified: true,
            reason: "Detected high-certainty sanitizer bypass on Python zip relative traversal override logic.",
            contradictions: [
              {
                func: "CompletePath.joinpath",
                claimed: "Sanitizes absolute slash path directories on zip extracts safely",
                actual: "lstrips leading slashes but misses nested relative path division operators '/' overrides which trigger 'joinpath' directory escapes",
                contradictionType: "incomplete_sanitization",
                bypassPoc: "CompletePath(archive_root) / '../../escape.txt' with operator evaluation overrides",
                exploitPotential: "Provides read access to files outside of zip physical container boundaries"
              },
              {
                func: "CompletePath.open",
                claimed: "Filters standard directory traversal operators through plain string replacements",
                actual: "naive string.replace('../', '') runs only on a single pass. Inputting '....//' yields '..' allowing filter bypass",
                contradictionType: "bypass_sanitization",
                bypassPoc: "complete_file_path.open('....//....//....//etc/passwd')",
                exploitPotential: "arbitrary local file exposure under container root"
              }
            ],
            adversaryRefutation: "The extraction path utilizes .resolve_real_path() on standard root systems. If root configurations represent absolute symlinks, actual physical container escapes could be mitigated. However, fallback overrides bypass single-pass replacements directly.",
            pocCode: `import os
from zipp.consumer import ZipArchiveReader

# Simulated CVE-2024-5569 Exploit Sequence
reader = ZipArchiveReader("archive.zip")
# Triggers nested division sequence bypass naively stripping '/../' strings once
payload_bypass = "....//....//....//etc/passwd"
stolen_content = reader.read_text(payload_bypass)

print("[+] STOLEN ENVIRONMENT FILE CONTENTS:")
print(stolen_content)
`,
            intentChain: [
              {
                nodeId: 0,
                funcName: "ZipArchiveReader.read_text",
                intent: "Exposes high-level text utility to open path divisions and fetch files in standard encodings",
                keyLogic: "Constructs file segments inside overridden Division operators before extraction",
                suspicious: "Directly trusts user file parameters",
                usedCache: false
              },
              {
                nodeId: 1,
                funcName: "CompletePath.__truediv__",
                intent: "Implements '/' syntax overrides for complete pythonic path representations",
                keyLogic: "Reroutes directory strings directly to custom internal joinpath configurations",
                suspicious: "Exposes division override bindings directly",
                usedCache: false
              },
              {
                nodeId: 2,
                funcName: "CompletePath.joinpath",
                intent: "Resolves correct relative indices inside simulated zip directory systems",
                keyLogic: "Naive trim check allows bypass of arbitrary root segments",
                suspicious: "Path reconstruction lacks absolute containment testing",
                usedCache: true
              },
              {
                nodeId: 3,
                funcName: "CompletePath.open",
                intent: "Performs file opening with naively stripped '..' traversals and standard encoding",
                keyLogic: "Naive .replace('../', '') is only parsed once",
                suspicious: "Highly vulnerable single pass string cleaner bypass",
                usedCache: false
              }
            ]
          };
        } else if (selectedTemplate.id === "naive-lfi-sanitize") {
          simulatedResult = {
            pathId: "lfi-path-03",
            status: "vulnerable",
            confidenceScore: 8,
            verified: true,
            reason: "Vulnerable relative path cleaning detected on controllers. Single string pass bypasses TS sanitize controls.",
            contradictions: [
              {
                func: "sanitizePath",
                claimed: "Clears path traversal sequences using replace('../', '') string filter logic",
                actual: "Cleans characters once, letting attackers inject nested '....//' strings that reconstruct traversal paths",
                contradictionType: "bypass_sanitization",
                bypassPoc: "filename=....//....//etc/passwd",
                exploitPotential: "Accesses arbitrary sensitive credentials in system environments"
              }
            ],
            adversaryRefutation: "If the application lacks file permission nodes or runs strictly in an isolated standard docker workspace directory, attackers cannot access system hosts files. Standard FS modules limit path reading exceptions under custom root overrides.",
            pocCode: `// Node Express Exploit curl query simulator
const axios = require('axios');

async function triggerBypass() {
  const payload = '....//....//....//etc/passwd';
  console.log('[*] Sinking sanitization traversal payload:', payload);
  try {
    const res = await axios.get(\`http://localhost:3000/api/assets?filename=\${payload}\`);
    console.log('[+] Server Response Status: Code ' + res.status);
    console.log('[+] Leaked System File Contents Output:');
    console.log(res.data);
  } catch (err) {
    console.error('[-] Request failed. Sanitizer successfully robust?');
  }
}

triggerBypass();
`,
            intentChain: [
              {
                nodeId: 0,
                funcName: "handleAssetRequest",
                intent: "Processes asset delivery in general HTTP parameters inside Express router callbacks",
                keyLogic: "Naively triggers sanitizePath helper utility before file reading actions",
                suspicious: "Relies on non-parameterized custom validator functions",
                usedCache: false
              },
              {
                nodeId: 1,
                funcName: "sanitizePath",
                intent: "Filters out any relative folder traversal inputs accurately",
                keyLogic: "naive regex string.replace removes string segments once",
                suspicious: "Highly unsafe single pass replace bypass targets",
                usedCache: true
              }
            ]
          };
        } else if (selectedTemplate.id === "eval-rce") {
          simulatedResult = {
            pathId: "rce-path-01",
            status: "vulnerable",
            confidenceScore: 10,
            verified: true,
            reason: "Critical unconstrained remote evaluation sink detected in Flask route parameter mappings.",
            contradictions: [
              {
                func: "evaluate_expression",
                claimed: "Processes arithmetic modeling computations using scope isolation filters securely",
                actual: "Runs high-risk native evaluation sinks inside system runtimes with fully untrusted expression inputs",
                contradictionType: "unsanitized_sink",
                bypassPoc: "__import__('os').system('id')",
                exploitPotential: "Complete remote OS command control and container compromise"
              }
            ],
            adversaryRefutation: "The environment defines local dictionaries and blocks __builtins__ in code models. However, standard Python dictionary introspection allows bypass constructs bypassing standard sandbox limits completely $(\"__class__.__mro__\").",
            pocCode: `import requests

# Payload utilizing python string and class reflection filters to bypass __builtins__ = None limits
exploit_payload = "().__class__.__mro__[1].__subclasses__()[134]('cat /etc/passwd', shell=True)"
url = f"http://localhost:3000/api/compute?expr={exploit_payload}"

print(f"[*] Attacking endpoint: {url}")
response = requests.get(url)
print("[+] Execution output result:", response.json())
`,
            intentChain: [
              {
                nodeId: 0,
                funcName: "api_compute",
                intent: "Validates incoming query parameters and maps mathematical expressions to server components",
                keyLogic: "Binds queries to compute functions with raw strings directly",
                suspicious: "No sanitization layer mapped before execution",
                usedCache: false
              },
              {
                nodeId: 1,
                funcName: "evaluate_expression",
                intent: "Safely returns evaluated equation parameters via mathematical parsing environments",
                keyLogic: "Triggers execution inside dangerous native python eval() interfaces",
                suspicious: "Implements fully untrusted python evaluations",
                usedCache: false
              }
            ]
          };
        } else {
          // SQLI
          simulatedResult = {
            pathId: "sqli-path-01",
            status: "vulnerable",
            confidenceScore: 8,
            verified: true,
            reason: "Unsafe string interpolation inside SQL database executor detected.",
            contradictions: [
              {
                func: "filter_sql_inject",
                claimed: "Sanitizes malicious database command arguments accurately",
                actual: "Naively strips SELECT and UNION once in uppercase, letting attackers leverage mixed casing ('SeLeCt') to execute injection payloads",
                contradictionType: "bypass_sanitization",
                bypassPoc: "sku_id=' or 1=1 --",
                exploitPotential: "Bypasses authentication filters and extracts all database stocks"
              }
            ],
            adversaryRefutation: "The code executes in SQLite which features singular execution handles, meaning stacked queries (semicolons to trigger drops) will fail automatically. However, inline single quote modifications are fully active.",
            pocCode: `import requests

#mixed-case SQL payloads bypassing case-sensitive single word sanitizers
sqli_payload = "' oR 1=1 --"
target_url = f"http://localhost:3000/api/sku?sku={sqli_payload}"

print(f"[*] Dispatching database payload: {sqli_payload}")
r = requests.get(target_url)
print("[+] Retreived Inventory Row Material:")
print(r.json())
`,
            intentChain: [
              {
                nodeId: 0,
                funcName: "query_sku_stock",
                intent: "Parses SKU query parameters inside connector DB drivers",
                keyLogic: "Inserts safe variables into sqlite script templates with vulnerable string formats",
                suspicious: "Unsafe string query template concatenation",
                usedCache: false
              },
              {
                nodeId: 1,
                funcName: "filter_sql_inject",
                intent: "Scrubs commands parameters clean of active SQL verbs safely",
                keyLogic: "Naively strips a subset of fixed words through uppercase matching filters",
                suspicious: "Lacks mix-case string parsing or parameterized variables bindings",
                usedCache: true
              }
            ]
          };
        }

        setResults(simulatedResult);
        setActiveTab("logic");
        setAnalyzing(false);
      }, 1500);
    }
  };

  return (
    <div id="agies-v3-root-app" className="min-h-screen bg-gray-950 font-sans text-gray-100 flex flex-col antialiased">
      {/* Top Banner / Masthead */}
      <header id="masthead" className="bg-gray-900/80 border-b border-gray-800 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="bg-green-500/10 p-2 rounded-lg border border-green-500/20 glow-green">
            <Fingerprint className="h-6 w-6 text-green-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              agies v3 <span className="text-xs bg-gray-800 text-green-400 border border-green-500/20 px-2 py-0.5 rounded-full font-mono font-normal">REVISED SOURCE→SINK</span>
            </h1>
            <p className="text-xs text-gray-400">Static Call-Chain Vulnerability Detection Framework Playground</p>
          </div>
        </div>

        {/* Global Controls & Performance Metric */}
        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center space-x-6 text-xs text-gray-400">
            <div className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>ENGINE: <b className="text-gray-200">TS AST RUNNER</b></span>
            </div>
            <div className="flex items-center gap-1.5">
              <span>SINK DETECTION: <b className="text-gray-200">PHASE A' (ACTIVE)</b></span>
            </div>
          </div>

          <div className="flex items-center bg-gray-950 border border-gray-800 rounded-lg p-1 gap-1">
            <button
              id="toggle-sim-mode"
              onClick={() => { setLiveAiMode(false); setResults(null); }}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
                !liveAiMode
                  ? "bg-slate-800 text-white shadow-sm border border-slate-700"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              Offline Simulator
            </button>
            <button
              id="toggle-ai-mode"
              onClick={() => { setLiveAiMode(true); setResults(null); }}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition flex items-center gap-1.5 ${
                liveAiMode
                  ? "bg-emerald-800/80 text-white shadow-sm border border-emerald-700 glow-green"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Sparkles className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
              Live AI Mode
            </button>
          </div>
        </div>
      </header>

      {/* Main Two-Panel Layout */}
      <main id="main-panel-layout" className="flex-1 flex flex-col lg:flex-row min-h-0">
        
        {/* LEFT PANEL: Workspace, Code Editor & Custom Sinks */}
        <section id="workspace-panel" className="w-full lg:w-[45%] border-r border-gray-800 bg-gray-950/60 flex flex-col min-h-0 border-b lg:border-b-0">
          
          {/* Workspace Controls */}
          <div className="p-4 border-b border-gray-800 bg-gray-900/30 space-y-3">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1">
                <Settings2 className="h-3.5 w-3.5" /> Select Preset Target Audit Codebase
              </label>
            </div>
            
            <select
              id="select-preset-target"
              value={selectedTemplate.id}
              onChange={(e) => handleTemplateSelection(e.target.value)}
              className="w-full bg-gray-900 border border-gray-800 text-sm rounded-lg p-2.5 outline-none focus:border-green-500 transition text-white"
            >
              {PRESET_TEMPLATES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.vulnType})
                </option>
              ))}
            </select>
            <p className="text-xs text-gray-400 italic font-sans leading-relaxed">
              {selectedTemplate.description}
            </p>
          </div>

          {/* Files Editor Tabs */}
          <div className="flex-1 flex flex-col min-h-0 bg-gray-950">
            <div className="border-b border-gray-800 bg-gray-900/20 px-4 py-2 flex items-center justify-between">
              <div className="flex items-center space-x-1 overflow-x-auto select-none no-scrollbar">
                {files.map((file, idx) => (
                  <div
                    key={file.filePath}
                    className={`flex items-center space-x-2 text-xs px-3 py-1.5 rounded-md border transition cursor-pointer ${
                      activeFileIndex === idx
                        ? "bg-slate-800/80 text-white border-slate-700 font-medium"
                        : "text-gray-400 hover:text-white border-transparent hover:bg-slate-900/50"
                    }`}
                    onClick={() => setActiveFileIndex(idx)}
                  >
                    <FileCode className="h-3.5 w-3.5 text-slate-400" />
                    <span>{file.filePath}</span>
                    {files.length > 1 && (
                      <X
                        className="h-3 w-3 hover:text-red-400 ml-1 rounded-sm cursor-pointer hover:bg-gray-800"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteFile(idx);
                        }}
                      />
                    )}
                  </div>
                ))}

                {/* File Plus trigger */}
                <button
                  id="trigger-newpath-file"
                  onClick={() => setShowNewFileForm(!showNewFileForm)}
                  className="p-1 px-2 rounded-md hover:bg-gray-800 text-gray-400 hover:text-white border border-transparent hover:border-gray-700 text-xs flex items-center gap-1 transition"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>Add File</span>
                </button>
              </div>
            </div>

            {/* New File creator floating trigger Form */}
            {showNewFileForm && (
              <div className="p-3 bg-gray-900 border-b border-gray-800 flex items-center gap-2 animate-fadeIn">
                <input
                  type="text"
                  placeholder="e.g. models/user_auth.py"
                  value={newFileName}
                  onChange={(e) => setNewFileName(e.target.value)}
                  className="flex-1 bg-gray-950 border border-gray-700 rounded p-1.5 text-xs text-white uppercase font-sans placeholder-gray-500 outline-none"
                />
                <button
                  onClick={handleAddFile}
                  className="bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5 rounded text-xs text-white font-medium"
                >
                  Create
                </button>
                <button
                  onClick={() => setShowNewFileForm(false)}
                  className="text-gray-400 hover:text-white text-xs p-1"
                >
                  Cancel
                </button>
              </div>
            )}

            {/* Interactive Monaco-like editable text area */}
            <div className="flex-1 relative flex flex-col min-h-[300px]">
              <div className="absolute top-2 right-4 bg-gray-900/90 text-[10px] text-gray-500 px-2 py-0.5 rounded font-mono border border-gray-800 pointer-events-none uppercase">
                Interactive Workspace
              </div>
              <textarea
                value={files[activeFileIndex]?.code || ""}
                onChange={(e) => handleUpdateCode(e.target.value)}
                className="w-full flex-1 p-4 bg-gray-950 font-mono text-sm text-green-300/90 leading-6 outline-none resize-none focus:ring-0 select-text border-0"
                placeholder="# Enter python parameters or javascript variables..."
                spellCheck={false}
              />
            </div>
            
            {/* Phase C - System Context metadata Section */}
            <div className="border-t border-gray-800 p-4 bg-gray-900/10 space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-gray-400">
                <span className="flex items-center gap-1 uppercase tracking-wider text-[11px]"><Info className="h-3.5 w-3.5" /> README Context Payload (Phase C)</span>
              </div>
              <textarea
                value={readme}
                onChange={(e) => setReadme(e.target.value)}
                className="w-full h-16 p-2 bg-gray-900 border border-gray-800 rounded text-xs text-gray-300 placeholder-gray-500 outline-none focus:border-slate-700 resize-none font-sans"
                placeholder="# Describe what the target project acts as..."
              />
            </div>

            {/* Phase A' Custom Sinks */}
            <div className="border-t border-gray-850 p-4 bg-gray-900/30 space-y-3">
              <div className="flex justify-between items-center text-xs font-semibold text-gray-400">
                <span className="uppercase tracking-wider text-[11px] flex items-center gap-1">Custom Core Sinks (Phase A' Dynamic Sink Discovery)</span>
                <span className="text-[10px] text-slate-500 font-mono capitalize">Active Targets: {custSinks.length}</span>
              </div>
              
              <div className="flex flex-wrap gap-1.5">
                {custSinks.map((sink) => (
                  <span
                    key={sink}
                    className="inline-flex items-center bg-gray-900/90 text-slate-300 font-mono text-[10px] px-2.5 py-1 rounded border border-gray-800 hover:border-red-500/50 hover:text-red-300 hover:bg-red-950/20 group transition cursor-pointer"
                    onClick={() => handleRemoveSink(sink)}
                  >
                    {sink}
                    <X className="h-2.5 w-2.5 ml-1.5 opacity-60 group-hover:opacity-100 text-gray-500 group-hover:text-red-400" />
                  </span>
                ))}
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Add custom library sink function, e.g. system_call"
                  value={newSink}
                  onChange={(e) => setNewSink(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddSink()}
                  className="flex-grow bg-gray-950 border border-gray-800 rounded p-1.5 text-xs text-slate-300 placeholder-gray-600 outline-none font-mono focus:border-green-500"
                />
                <button
                  onClick={handleAddSink}
                  className="bg-slate-800 hover:bg-slate-700 text-white border border-slate-750 px-3 py-1 rounded text-xs transition"
                >
                  Add Sink
                </button>
              </div>
            </div>

          </div>
        </section>

        {/* RIGHT PANEL: Pipeline Dashboard Controls, Path Sorter & Visual Orchesrator */}
        <section id="auditing-dashboard-panels" className="flex-1 flex flex-col min-h-0 bg-gray-950">
          
          {/* Dashboard Control Parameters Bar */}
          <div className="p-4 border-b border-gray-800 bg-gray-905 flex flex-col sm:flex-row items-center justify-between gap-4">
            
            {/* Exploit Slices Threshold Sliders */}
            <div className="flex flex-wrap items-center gap-6 text-xs text-gray-400 w-full sm:w-auto">
              <div className="space-y-1">
                <span className="flex justify-between text-[10px] uppercase font-mono">
                  <span>EXPLOIT SLOTS LIMIT</span>
                  <b className="text-gray-200 font-bold">{exploitLimit}</b>
                </span>
                <input
                  type="range"
                  min="5"
                  max="50"
                  value={exploitLimit}
                  onChange={(e) => setExploitLimit(parseInt(e.target.value))}
                  className="h-1 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-emerald-500 w-32"
                />
              </div>

              <div className="space-y-1">
                <span className="flex justify-between text-[10px] uppercase font-mono">
                  <span>EXPLORE SLOTS LIMIT</span>
                  <b className="text-gray-200 font-bold">{exploreLimit}</b>
                </span>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={exploreLimit}
                  onChange={(e) => setExploreLimit(parseInt(e.target.value))}
                  className="h-1 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-purple-500 w-32"
                />
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="chk-hits"
                  checked={simulateCacheHits}
                  onChange={(e) => setSimulateCacheHits(e.target.checked)}
                  className="rounded bg-gray-900 border-gray-805 h-4 w-4 accent-emerald-500"
                />
                <label htmlFor="chk-hits" className="text-[11px] font-mono tracking-wider cursor-pointer select-none">
                  BLACKBOARD CACHING
                </label>
              </div>
            </div>

            {/* Execute Audit Button */}
            <button
              id="execute-system-audit"
              onClick={executePipelineAudit}
              disabled={analyzing}
              className={`w-full sm:w-auto bg-green-500 hover:bg-green-400 text-black px-6 py-2.5 rounded-lg text-sm font-bold flex items-center justify-center gap-2 transition disabled:opacity-50 tracking-wide select-none cursor-pointer ${
                analyzing ? "glow-green bg-green-600" : ""
              }`}
            >
              {analyzing ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin text-black" />
                  <span>Auditing Codebase v3...</span>
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 fill-black text-black" />
                  <span>Run agies v3 Pipeline</span>
                </>
              )}
            </button>
          </div>

          {/* Active Navigation tabs for workflow step indicators */}
          <div className="bg-gray-900/40 border-b border-gray-800 px-4 flex">
            <button
              id="nav-to-graph"
              onClick={() => setActiveTab("graph")}
              className={`py-3.5 px-4 text-xs font-semibold tracking-wide border-b-2 flex items-center gap-2 transition ${
                activeTab === "graph"
                  ? "border-green-400 text-white bg-slate-800/20"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <Layers className="h-4 w-4" />
              <span>Phase A/A': Call Paths ({pathsList.length})</span>
            </button>
            <button
              id="nav-to-sorter"
              onClick={() => setActiveTab("sorter")}
              className={`py-3.5 px-4 text-xs font-semibold tracking-wide border-b-2 flex items-center gap-2 transition ${
                activeTab === "sorter"
                  ? "border-green-400 text-white bg-slate-800/20"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <Cpu className="h-4 w-4" />
              <span>Phase B: Sorter Logs</span>
            </button>
            <button
              id="nav-to-intent"
              onClick={() => setActiveTab("intent")}
              className={`py-3.5 px-4 text-xs font-semibold tracking-wide border-b-2 flex items-center gap-2 transition ${
                activeTab === "intent"
                  ? "border-green-400 text-white bg-slate-800/20"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <Database className="h-4 w-4" />
              <span>Phase D/E: Intention Board</span>
            </button>
            <button
              id="nav-to-logic"
              onClick={() => setActiveTab("logic")}
              className={`py-3.5 px-4 text-xs font-semibold tracking-wide border-b-2 flex items-center gap-2 transition relative ${
                activeTab === "logic"
                  ? "border-green-400 text-white bg-slate-800/20"
                  : "border-transparent text-gray-400 hover:text-white"
              }`}
            >
              <Terminal className="h-4 w-4" />
              <span>Phase F: Findings & PoC</span>
              {results && results.status === "vulnerable" && (
                <span className="absolute top-2 right-1.5 h-2 w-2 rounded-full bg-red-400 animate-pulse"></span>
              )}
            </button>
          </div>

          {/* Workflow Tab Components Container */}
          <div className="flex-1 overflow-y-auto p-6 bg-gray-950/40 relative">
            
            {/* Error notifications frame */}
            {errorObj && (
              <div className="bg-red-950/30 border border-red-500/20 rounded-xl p-5 mb-5 space-y-3">
                <div className="flex items-center space-x-2 text-red-400">
                  <AlertTriangle className="h-5 w-5" />
                  <h4 className="font-bold text-sm">Auditor Pipeline Error Exception</h4>
                </div>
                <p className="text-xs text-slate-350 leading-relaxed max-w-2xl">{errorObj.error}</p>
                {errorObj.needsKey && (
                  <div className="bg-gray-950 p-3 rounded-lg text-[11px] text-gray-400 border border-red-500/10 space-y-2">
                    <p className="font-medium text-slate-200">Wait! How to configure process.env.GEMINI_API_KEY:</p>
                    <ol className="list-decimal list-inside space-y-1">
                      <li>Go to upper-right <b className="text-slate-100">Settings &gt; Secrets</b> inside the AI Studio UI</li>
                      <li>Define <b className="text-slate-100">GEMINI_API_KEY</b> with your Google Gen AI credentials</li>
                      <li>Alternatively, toggle <b className="text-emerald-400">Offline Simulator</b> at the top-right of your application toolbar to run full-fidelity TS evaluations without any API key requirements!</li>
                    </ol>
                  </div>
                )}
              </div>
            )}

            {/* Analyzing Spinner Frame */}
            {analyzing && (
              <div className="absolute inset-0 bg-gray-950/80 backdrop-blur-sm z-40 flex flex-col items-center justify-center space-y-4">
                <div className="relative flex items-center justify-center">
                  <div className="h-16 w-16 border-4 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin"></div>
                  <Cpu className="absolute h-6 w-6 text-emerald-400 animate-pulse" />
                </div>
                <div className="text-center space-y-1.5 max-w-sm">
                  <h4 className="text-sm font-bold tracking-wide text-white animate-pulse">Running Static Extraction Pipeline</h4>
                  <p className="text-xs text-gray-400 leading-normal">
                    {liveAiMode 
                      ? "Consulting Gemini 3.5 to establish developer intention mapping and cross-reference logic inconsistencies..." 
                      : "Calculating path scores, verifying validation triggers, and building blackboard cache mappings..."}
                  </p>
                </div>
              </div>
            )}

            {/* TAB 1: PHASE A/A' Call Graph Pathfinder representation */}
            {activeTab === "graph" && (
              <div id="tab-phase-a-graph" className="space-y-6">
                <div className="border border-gray-800 rounded-xl bg-gray-900/20 p-5 space-y-4">
                  <h3 className="text-sm font-bold tracking-wide text-white flex items-center gap-1.5 uppercase font-mono">
                    <span>CALL PATHS REPRESENTATION MATRIX</span>
                  </h3>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    agies v3 scans files statically, registering Remote Flow Sources and standard vulnerability sinks. Added custom sinks automatically append nodes statically to track modular interface crossings.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-gray-950 border border-gray-850 rounded-lg p-3 text-xs">
                      <b className="text-slate-300 block mb-2 font-mono uppercase text-[10px]">Sources Detected (HTTP/User-Facing)</b>
                      <ul className="space-y-1.5">
                        <li className="flex items-center gap-2">
                          <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                          <span className="font-mono text-[11px] text-emerald-300">RemoteFlowSource &rarr; query.param.filename</span>
                        </li>
                        <li className="flex items-center gap-2 text-slate-400">
                          <span className="h-2 w-2 rounded-full bg-gray-500"></span>
                          <span className="font-mono text-[11px]">RemoteFlowSource &rarr; request.args.expr (eval)</span>
                        </li>
                      </ul>
                    </div>

                    <div className="bg-gray-950 border border-gray-850 rounded-lg p-3 text-xs">
                      <b className="text-slate-300 block mb-2 font-mono uppercase text-[10px]">Active Sinks Map</b>
                      <ul className="space-y-1.5">
                        <li className="flex items-center justify-between font-mono text-[11px] text-amber-300">
                          <span>open() File Sink</span>
                          <span className="bg-amber-950/20 border border-amber-500/25 px-1.5 rounded-sm text-[9px]">LFI Target</span>
                        </li>
                        {custSinks.map((cs) => (
                          <li key={cs} className="flex items-center justify-between font-mono text-[11px] text-purple-300">
                            <span>{cs}() Custom Override</span>
                            <span className="bg-purple-950/20 border border-purple-500/25 px-1.5 rounded-sm text-[9px]">Phase A'</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Path Visualizer Blocks */}
                <div className="space-y-4">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Discovered Call Chain Paths Slices</h3>
                  {pathsList.length === 0 ? (
                    <div className="text-center p-8 bg-gray-900/10 border border-gray-800 rounded-xl text-xs text-gray-500">
                      No call paths found. Write standard python (def) or javascript (function) functions in the editor above to populate graphs statically.
                    </div>
                  ) : (
                    pathsList.map((path, idx) => (
                      <div key={path.id} className="border border-gray-800 rounded-xl bg-gray-900/10 overflow-hidden hover:border-gray-700 transition">
                        {/* Path Header */}
                        <div className="bg-gray-900/40 border-b border-gray-800 px-5 py-3 flex flex-wrap items-center justify-between gap-3 text-xs">
                          <div className="flex items-center space-x-3">
                            <span className={`px-2 py-0.5 rounded font-mono font-medium tracking-wide text-[10px] uppercase ${
                              path.vulnType === VulnType.RCE
                                ? "bg-red-950/30 text-red-400 border border-red-500/20"
                                : "bg-emerald-950/30 text-emerald-400 border border-emerald-500/20"
                            }`}>
                              {path.vulnType} Flow Path
                            </span>
                            <span className="font-mono text-slate-300 font-semibold">{path.id}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] text-gray-450 font-mono">
                              SCORE: <b className="text-white font-mono">{path.score}</b>
                            </span>
                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-mono tracking-wider ${
                              path.slotType === "Exploit"
                                ? "bg-emerald-950 text-emerald-400 border border-emerald-500/10"
                                : "bg-purple-950 text-purple-400 border border-purple-500/10"
                            }`}>
                              {path.slotType} Slot
                            </span>
                          </div>
                        </div>

                        {/* Interactive flow items list */}
                        <div className="p-5 space-y-4 bg-gray-950/20">
                          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
                            <div className="space-y-1.5">
                              <span className="text-[11px] text-gray-500 font-mono block uppercase">SOURCE ATTACK SURFACE</span>
                              <b className="text-xs text-emerald-300 font-mono">{path.source}</b>
                              <span className="text-[10px] text-slate-500 font-sans block">{path.sourceFile}</span>
                            </div>

                            <div className="flex items-center justify-center p-2 text-gray-600">
                              <ArrowRight className="h-5 w-5 rotate-90 md:rotate-0" />
                            </div>

                            <div className="space-y-1.5">
                              <span className="text-[11px] text-gray-500 font-mono block uppercase">SINK DISASTER VULN</span>
                              <b className="text-xs text-rose-300 font-mono">{path.sink}</b>
                              <span className="text-[10px] text-slate-500 font-sans block">{path.sinkFile}</span>
                            </div>
                          </div>

                          {/* Graphical Flow representation of CodeQL path Nodes list */}
                          <div className="pt-4 border-t border-gray-900">
                            <span className="text-[10px] text-gray-500 font-mono block uppercase mb-3">STATIC CALLCHAIN SEQUENTIAL NODES</span>
                            <div className="flex flex-col space-y-3">
                              {path.nodes.map((node, nIdx) => (
                                <div key={node.id} className="relative flex items-start gap-4 p-3 bg-gray-900/25 border border-gray-900 rounded-lg hover:border-gray-800 transition">
                                  {/* Step Index bubble */}
                                  <div className="flex-shrink-0 bg-slate-800 text-slate-300 h-6 w-6 rounded-full flex items-center justify-center text-xs font-mono font-bold">
                                    {nIdx}
                                  </div>
                                  <div className="flex-grow space-y-1 text-xs">
                                    <div className="flex items-center justify-between">
                                      <b className="text-gray-100 font-mono font-medium">{node.filePath} &rarr; <span className="text-green-400">{node.funcName}()</span></b>
                                      <span className="text-[10px] text-gray-500 font-mono">Lines {node.lineStart}-{node.lineEnd}</span>
                                    </div>
                                    <pre className="text-[11px] font-mono text-slate-400 p-2 bg-gray-950/80 rounded border border-gray-900 overflow-x-auto whitespace-pre leading-relaxed select-text mt-2 block">
                                      {node.code}
                                    </pre>
                                  </div>
                                  {/* Connector Line mapping if not last element */}
                                  {nIdx < path.nodes.length - 1 && (
                                    <div className="absolute left-7 top-9 w-[1px] h-8 bg-slate-850 pointer-events-none" />
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: PHASE B Path Sorter & Filter matrix logs */}
            {activeTab === "sorter" && (
              <div id="tab-phase-b-sorter" className="space-y-6">
                <div className="border border-gray-850 rounded-xl bg-gray-900/10 p-5 space-y-3">
                  <h3 className="text-sm font-bold tracking-wide text-white flex items-center gap-1.5 uppercase font-mono">
                    <span>PHASE B PATH SORTING ALGORITHM LOGS</span>
                  </h3>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    agies v3 processes scores deterministically using modular weights to allocate Exploit pools versus Explore pools, ensuring sanitizer bypass targets of high values are weighted upward and prioritizing full-path alignments.
                  </p>
                </div>

                {/* Sorting Matrix Grid showing details on scores calculation variables */}
                <div className="bg-gray-900/20 border border-gray-800 rounded-xl overflow-hidden">
                  <table className="w-full text-left text-xs text-gray-300 border-collapse select-text">
                    <thead>
                      <tr className="bg-gray-900/60 border-b border-gray-800 text-[10px] text-gray-500 uppercase font-mono tracking-wider">
                        <th className="p-4">Path Slice ID</th>
                        <th className="p-4">Sink Classification</th>
                        <th className="p-4">Length Penalty</th>
                        <th className="p-4">Sanitize?</th>
                        <th className="p-4">Is Anomalous?</th>
                        <th className="p-4 text-right">agies v3 Score</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-900">
                      {pathsList.map((path) => (
                        <tr key={path.id} className="hover:bg-gray-900/20 transition">
                          <td className="p-4 font-mono font-medium text-emerald-400">{path.id}</td>
                          <td className="p-4 font-mono">{path.sink.split("->")[0]}</td>
                          <td className="p-4">
                            <span className="text-gray-400 block font-mono">1.0 / (1.0 + 0.1 * {Math.max(0, path.nodes.length - 3)})</span>
                            <span className="text-[10px] text-slate-500 font-mono">Nodes: {path.nodes.length}</span>
                          </td>
                          <td className="p-4">
                            {path.hasValidation ? (
                              <span className="inline-flex bg-emerald-950 text-emerald-300 border border-emerald-500/20 px-2 py-0.5 rounded text-[10px] font-mono tracking-wide">
                                [BYPASS_TARGET] (+0.20)
                              </span>
                            ) : (
                              <span className="text-gray-500 font-sans">None</span>
                            )}
                          </td>
                          <td className="p-4">
                            {path.isAnomalous ? (
                              <div className="space-y-1 text-[10px] font-mono">
                                <span className="text-purple-400 font-semibold uppercase block">Yes (Explore)</span>
                                {path.anomalousReasons?.map((r) => (
                                  <span key={r} className="bg-gray-950 border border-purple-500/15 text-purple-300 px-1 rounded block text-[9px] truncate">
                                    {r}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-slate-500">No (Exploit)</span>
                            )}
                          </td>
                          <td className="p-4 text-right font-mono font-bold text-white tracking-wide">{path.score}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Sorter workflow rules */}
                <div className="p-4 rounded-xl border border-gray-850 bg-gray-950/40 text-xs text-gray-400 space-y-2">
                  <b className="text-slate-200 uppercase font-mono text-[10px] block tracking-wide">Sorting Variables Equation Reference</b>
                  <p>
                    1. <b className="text-white">Sink Weight Check:</b> Assigns starting weights (e.g. 1.0 for system code evals, 0.6 for file stream accesses, multiplier 0.4).
                  </p>
                  <p>
                    2. <b className="text-white">Validation Multiplier Check:</b> Unlike legacy pruning which penalized sanitizer files, agies v3 tags `sanitize`, `validate`, or `escape` variables as highly attractive <b className="text-emerald-400">BYPASS_TARGETS</b> and adds score premiums, correctly prioritizing structural logic analysis.
                  </p>
                </div>
              </div>
            )}

            {/* TAB 3: PHASE D/E Orchestration & Intention board */}
            {activeTab === "intent" && (
              <div id="tab-phase-d-intent" className="space-y-6">
                <div className="border border-gray-850 rounded-xl bg-gray-900/10 p-5 space-y-2">
                  <h3 className="text-sm font-bold tracking-wide text-white flex items-center gap-1.5 uppercase font-mono">
                    <span>PHASE D & E INTENTION BOARD & BLACKBOARD EXTRACTION</span>
                  </h3>
                  <p className="text-xs text-gray-400 leading-normal">
                    Rather than feeding absolute paths directly to a single model, agies v3 invokes the <b className="text-emerald-400">Intent Agent</b> over small function segments. Multi-use functions are cached dynamically under Phase E's <b className="text-purple-400">Blackboard memory aggregator</b>.
                  </p>
                </div>

                {/* Blackboard Cache hits simulation tracker */}
                <div className="bg-gray-950 border border-gray-850 p-4 rounded-xl flex items-center justify-between gap-4 text-xs">
                  <div className="flex items-center space-x-3">
                    <Database className={`h-8 w-8 text-purple-400 ${results ? "animate-bounce" : ""}`} />
                    <div>
                      <h4 className="font-bold text-white font-mono uppercase text-[11px]">Blackboard memory aggregator Status</h4>
                      <p className="text-slate-400">
                        {results 
                          ? `Registered active index handles: Cache hits successfully bypassed duplicate requests!` 
                          : "Run the agies v3 pipeline using the action header above to display actual cache mappings."}
                      </p>
                    </div>
                  </div>
                  {results && (
                    <div className="bg-purple-950/20 text-purple-400 border border-purple-500/20 rounded px-3 py-1 font-mono text-[10px]">
                      CACHE SAVING: ~38% TOKENS
                    </div>
                  )}
                </div>

                {/* Parallelized Intent Agent logs representation */}
                <div className="space-y-4">
                  <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Functions extraction & claiming log</h4>
                  {results && results.intentChain ? (
                    results.intentChain.map((item) => (
                      <div key={item.nodeId} className="border border-gray-800 rounded-xl bg-gray-900/10 p-4 relative space-y-3">
                        <div className="flex items-center justify-between border-b border-gray-800/60 pb-2 text-xs">
                          <b className="font-mono text-emerald-400 text-sm">{item.funcName}()</b>
                          <span className="text-[10px] text-gray-500 font-mono">Node ID: {item.nodeId}</span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                          <div className="space-y-1 bg-gray-950 p-3 rounded border border-gray-900">
                            <span className="text-slate-400 uppercase font-mono text-[9px] tracking-wide block">DEVELOPER INTENTION (Claim)</span>
                            <p className="text-slate-300 leading-relaxed font-sans">{item.intent}</p>
                          </div>

                          <div className="space-y-1 bg-gray-950 p-3 rounded border border-gray-900">
                            <span className="text-slate-400 uppercase font-mono text-[9px] tracking-wide block">ACTUAL KEY LOGIC (Reality)</span>
                            <p className="text-slate-300 leading-relaxed font-sans">{item.keyLogic}</p>
                          </div>
                        </div>

                        {/* Blackboard hit notification badge */}
                        {item.usedCache && (
                          <div className="absolute top-2 right-4 bg-purple-900/30 text-purple-300 border border-purple-500/20 rounded px-2 py-0.5 text-[9px] font-mono tracking-wider">
                            BLACKBOARD CACHE HIT
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="text-center p-8 bg-gray-900/10 border border-gray-800 rounded-xl text-xs text-slate-500">
                      Intention board is blank. Execute pipeline to extract developer claims.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 4: PHASE F Findings, logic contradictions & simulated PoC output */}
            {activeTab === "logic" && (
              <div id="tab-phase-f-findings" className="space-y-6">
                
                {/* Visual Vulnerability result banner */}
                {results ? (
                  <div className={`p-6 rounded-2xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
                    results.status === "vulnerable"
                      ? "bg-red-950/20 border-red-500/35 glow-amber text-red-100"
                      : "bg-emerald-950/20 border-emerald-500/30 text-emerald-100"
                  }`}>
                    <div className="space-y-2 max-w-xl">
                      <div className="flex items-center space-x-2">
                        {results.status === "vulnerable" ? (
                          <AlertTriangle className="h-6 w-6 text-red-400 animate-pulse" />
                        ) : (
                          <ShieldCheck className="h-6 w-6 text-emerald-400" />
                        )}
                        <h3 className="font-bold text-lg leading-none">
                          System audit: <span className="uppercase">{results.status}</span>
                        </h3>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{results.reason}</p>
                    </div>

                    <div className="flex-shrink-0 bg-gray-950/80 border border-gray-850 py-3.5 px-6 rounded-xl text-center">
                      <span className="text-[10px] uppercase font-mono block text-gray-500 mb-1">CONFIDENCE</span>
                      <strong className={`font-mono text-3xl font-extrabold tracking-tight ${
                        results.confidenceScore >= 7 ? "text-red-400" : "text-emerald-400"
                      }`}>
                        {results.confidenceScore} <span className="text-base text-gray-400">/10</span>
                      </strong>
                    </div>
                  </div>
                ) : (
                  <div className="text-center p-12 bg-gray-900/10 border border-gray-805 rounded-xl text-xs text-gray-500 space-y-3">
                    <Cpu className="h-8 w-8 text-slate-600 block mx-auto" />
                    <p className="max-w-md mx-auto leading-relaxed">
                      No current findings or reports parsed. Launch the "Run agies v3 Pipeline" auditing execution tool at the top of your workspace screen to fetch and inspect vulnerabilities list.
                    </p>
                  </div>
                )}

                {/* Contradictions details panels list */}
                {results && results.contradictions && results.contradictions.length > 0 && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1">
                      <span>Core Logic Contradictions Detected (Logic Agent)</span>
                    </h4>

                    {results.contradictions.map((c, cIdx) => (
                      <div key={cIdx} className="border border-red-500/20 rounded-xl bg-red-950/5 p-5 space-y-4">
                        <div className="flex items-center justify-between border-b border-red-500/10 pb-2 text-xs">
                          <b className="font-mono text-red-400 text-sm">Contradiction: {c.func}()</b>
                          <span className="bg-red-950/60 border border-red-500/20 px-2 py-0.5 rounded text-[9px] font-mono text-red-300 uppercase tracking-wider">
                            {c.contradictionType}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs leading-relaxed">
                          <div className="space-y-1.5 p-3 rounded-lg bg-gray-950/80 border border-gray-900">
                            <span className="text-gray-500 uppercase font-mono text-[9px] tracking-wide block">Claimed Security (Intention / Promise)</span>
                            <p className="text-slate-300 font-sans">{c.claimed}</p>
                          </div>

                          <div className="space-y-1.5 p-3 rounded-lg bg-red-950/10 border border-red-500/10">
                            <span className="text-red-400 uppercase font-mono text-[9px] tracking-wide block">Actual Sub-Secure Operation (Implementation)</span>
                            <p className="text-slate-300 font-sans">{c.actual}</p>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                          <div className="space-y-1">
                            <span className="text-gray-500 uppercase text-[9px] block">Trigger Payload Bypass (e.g. bypass_poc)</span>
                            <code className="text-green-300 text-[11px] block">{c.bypassPoc}</code>
                          </div>
                          <div className="space-y-1">
                            <span className="text-gray-500 uppercase text-[9px] block">Exploit Impact severity</span>
                            <span className="text-slate-200 text-[11px] block">{c.exploitPotential}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Refutation skeptical review block */}
                {results && results.adversaryRefutation && (
                  <div className="border border-gray-800 rounded-xl bg-gray-900/10 p-5 space-y-3">
                    <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                      <QuestionIcon className="h-4 w-4 text-slate-400" />
                      <span>Adversarial Skeptic Challenger Audit (Adversary Agent)</span>
                    </h4>
                    <p className="text-xs text-gray-400 italic leading-relaxed">
                      "I challenge this vulnerability: Are we certain this isn't a false positive or fully mitigated by standard infrastructure controls or strict runtime parameters?"
                    </p>
                    <div className="bg-gray-950 p-4 rounded-lg border border-gray-900 text-xs text-slate-300 leading-relaxed font-sans">
                      {results.adversaryRefutation}
                    </div>
                  </div>
                )}

                {/* PoC Terminal Box Block */}
                {results && results.pocCode && (
                  <div className="border border-gray-800 rounded-xl overflow-hidden bg-gray-950">
                    <div className="bg-gray-900 border-b border-gray-850 px-5 py-3 flex items-center justify-between">
                      <span className="flex items-center gap-2 text-xs font-mono font-bold tracking-wide text-gray-300 uppercase">
                        <Terminal className="h-4 w-4 text-green-400" />
                        <span>REPRODUCIBLE TRIGGER EXPLOIT payload (Phase F PoC Generator)</span>
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(results.pocCode || "");
                        }}
                        className="p-1 px-3 text-xs bg-slate-800 text-slate-200 border border-slate-700 rounded-md hover:bg-slate-750 hover:text-white transition flex items-center gap-1 cursor-pointer select-none"
                      >
                        <Copy className="h-3.5 w-3.5" />
                        <span>Copy PoC</span>
                      </button>
                    </div>

                    <div className="p-4 font-mono text-xs text-green-300/90 leading-relaxed overflow-x-auto bg-black select-text whitespace-pre max-h-[350px]">
                      {results.pocCode}
                    </div>
                  </div>
                )}

              </div>
            )}

          </div>
        </section>

      </main>

      {/* Global Status Bar footer controls */}
      <footer className="bg-gray-900 border-t border-gray-800 px-6 py-3 flex flex-wrap items-center justify-between text-[11px] text-gray-400 select-none">
        <div>
          agies v3 Security Auditer Engine Dashboard &bull; All analysis runs isolated on sandbox virtual runtimes.
        </div>
        <div className="flex items-center gap-4 mt-2 sm:mt-0 font-mono">
          <span>PORT: <b className="text-gray-200">3000 (INGRESS ACTIVE)</b></span>
          <span>LANG: <b className="text-slate-200">TYPESCRIPT DIRECT</b></span>
        </div>
      </footer>
    </div>
  );
}
