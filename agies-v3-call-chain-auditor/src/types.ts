/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum VulnType {
  RCE = "RCE",
  LFI = "LFI",
  SSRF = "SSRF",
  SQLI = "SQLI",
  XSS = "XSS",
  AFO = "AFO",
  IDOR = "IDOR",
  REDOS = "REDOS",
}

export interface PathNode {
  id: string;
  funcName: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  code: string;
  isDangerous?: boolean;
}

export interface CodeQlPath {
  id: string;
  vulnType: VulnType;
  source: string;
  sourceFile: string;
  sink: string;
  sinkFile: string;
  nodes: PathNode[];
  isFullPath: boolean;
  score?: number;
  isAnomalous?: boolean;
  anomalousReasons?: string[];
  slotType?: "Exploit" | "Explore";
  hasValidation?: boolean;
}

export interface CachedIntent {
  funcName: string;
  filePath: string;
  intent: string;
  keyLogic: string;
  suspicious: string[];
  extractionTime: number;
  passThrough: boolean;
}

export interface Contradiction {
  func: string;
  claimed: string;
  actual: string;
  contradictionType: string;
  bypassPoc: string;
  exploitPotential: string;
}

export interface PathAnalysisResult {
  pathId: string;
  contradictions: Contradiction[];
  confidenceScore: number;
  adversaryRefutation?: string;
  pocCode?: string;
  verified: boolean;
  status: "secure" | "vulnerable" | "suspicious";
  reason: string;
  intentChain?: {
    nodeId: number;
    funcName: string;
    intent: string;
    keyLogic: string;
    suspicious: string;
    usedCache: boolean;
  }[];
}

export interface PresetTemplate {
  id: string;
  name: string;
  description: string;
  vulnType: VulnType;
  files: {
    filePath: string;
    code: string;
  }[];
  readme: string;
  customSinks?: string[];
}
