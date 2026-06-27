/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI, Type } from "@google/genai";
import { createServer as createViteServer } from "vite";

// Load environment variables (.env)
dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Lazy-initialized Gemini client client key checking prevents server crashing on startup
let genAiClient: GoogleGenAI | null = null;
function getGeminiAI(): GoogleGenAI {
  if (!genAiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      throw new Error("GEMINI_API_KEY is not defined. Please add GEMINI_API_KEY in the Secrets panel inside the AI Studio UI.");
    }
    genAiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        }
      }
    });
  }
  return genAiClient;
}

// REST route - Live AI agies v3 Auditor proxy
app.post("/api/analyze", async (req, res) => {
  try {
    const { files, readme, vulnType } = req.body;
    if (!files || !Array.isArray(files)) {
      return res.status(400).json({ error: "No files array provided for static analysis" });
    }

    const ai = getGeminiAI();

    // 1. Compile entire code context
    const codeContext = files
      .map((f: any) => `### FILE: ${f.filePath} ###\n${f.code}`)
      .join("\n\n");

    const systemInstruction = `You are the lead agies v3 Static Analysis AI Agent. 
Your objective is to spot deep logical vulnerabilities, particularly sanitizer bypasses and path-traverals.
Adhere strictly to the requested JSON response format. Refer to VulnHuntr style analysis guidelines.`;

    // Prompt for executing high-fidelity "Intent & Contradiction Analysis"
    const analysisPrompt = `
Analyze the code codebase for vulnerability type: ${vulnType}.
Project context / README:
${readme || "N/A"}

=== SOURCE CODE ===
${codeContext}

==== TASK =====
1. Break down the code into its core functions (at least the main entrypoint and sink functions).
2. For each function, document the "developer intent" (claimed logic), actual inputs/outputs, the "key logic" (actual implementation), and any suspicious behaviors.
3. Determine if there is a "logic contradiction" between what the function claims to do (e.g. "completely sanitize path") and what its implementation actually does (e.g. "replace only once").
4. Formulate an adversarial refutation (skeptical counterargument) to determine if this is a genuine high-certainty vulnerability or a false positive.
5. Create a Python or Node.js proof-of-concept (PoC) exploit script demonstrating how a malicious parameter triggers the vulnerability.
6. Rate your overall findings confidence from 0 to 10 (7+ is vulnerable validation confirmation!).

Provide safety-conscious analysis showing logical structure contradiction. Ensure to output standard JSON mapping exact schema below:
{
  "confidenceScore": number (0-10),
  "status": "secure" | "vulnerable" | "suspicious",
  "reason": "String summary of vulnerability findings",
  "contradictions": [
    {
      "func": "functionName",
      "claimed": "what the function claims or is intended to clean/secure",
      "actual": "the actual sub-secure operations it conducts",
      "contradictionType": "bypass_sanitization" | "unsanitized_sink" | "other",
      "bypassPoc": "exploit payload example",
      "exploitPotential": "impact outcome description"
    }
  ],
  "intentChain": [
    {
      "nodeId": number,
      "funcName": "functionName",
      "intent": "developer intention",
      "keyLogic": "actual implementation strategy",
      "suspicious": "suspected vulnerability gaps",
      "usedCache": false
    }
  ],
  "adversaryRefutation": "skeptical counterargument trying to refute this finding to guarantee low false positives",
  "pocCode": "A complete python or javascript code block outlining the payload execution flow"
}
`;

    const modelName = "gemini-3.5-flash";
    const response = await ai.models.generateContent({
      model: modelName,
      contents: analysisPrompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            confidenceScore: { type: Type.INTEGER, description: "A confidence rating from 0 to 10." },
            status: { type: Type.STRING, description: "Classification: secure, vulnerable, or suspicious." },
            reason: { type: Type.STRING, description: "A high-level summary paragraph of the risk vector." },
            contradictions: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  func: { type: Type.STRING },
                  claimed: { type: Type.STRING },
                  actual: { type: Type.STRING },
                  contradictionType: { type: Type.STRING },
                  bypassPoc: { type: Type.STRING },
                  exploitPotential: { type: Type.STRING }
                },
                required: ["func", "claimed", "actual", "contradictionType", "bypassPoc", "exploitPotential"]
              }
            },
            intentChain: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  nodeId: { type: Type.INTEGER },
                  funcName: { type: Type.STRING },
                  intent: { type: Type.STRING },
                  keyLogic: { type: Type.STRING },
                  suspicious: { type: Type.STRING },
                  usedCache: { type: Type.BOOLEAN }
                },
                required: ["nodeId", "funcName", "intent", "keyLogic", "suspicious", "usedCache"]
              }
            },
            adversaryRefutation: { type: Type.STRING, description: "Refutation counterargument to minimize false positives." },
            pocCode: { type: Type.STRING, description: "Complete runnable python or node script simulating trigger payload." }
          },
          required: ["confidenceScore", "status", "reason", "contradictions", "intentChain", "adversaryRefutation", "pocCode"]
        }
      }
    });

    const resultText = response.text || "{}";
    const parsedData = JSON.parse(resultText.trim());
    return res.json(parsedData);

  } catch (error: any) {
    console.error("Gemini Auditor Error:", error);
    return res.status(500).json({
      error: error.message || "An unexpected error occurred during AI analysis. Is GEMINI_API_KEY configured correctly inSecrets?",
      needsKeyConfig: !process.env.GEMINI_API_KEY
    });
  }
});

// Configure Vite or Static Asset delivery
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    // Developers setup - mount Vite dynamic dev server
    console.log("Mounting Vite Development Middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Production setup - serve static build materials
    const distPath = path.join(process.cwd(), "dist");
    console.log(`Serving Static Assets from production dist folder: ${distPath}`);
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`agies v3 fullstack server listening on http://localhost:${PORT}`);
  });
}

startServer();
