import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { runSemgrepScan } from "./tools/semgrep.js";
import { runTrivyScan } from "./tools/trivy.js";
import { runEvidenceScan } from "./tools/evidence.js";
import { runInfraScan } from "./tools/infra.js";
import { runDastScan } from "./tools/dast.js";
import { runGitleaksScan } from "./tools/gitleaks.js";

const server = new Server(
    {
        name: "ai-auditor-scanner",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
        },
    }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "run_sast_scan",
                description: "Run a Static Application Security Testing (SAST) scan using Semgrep.",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetPath: {
                            type: "string",
                            description: "Absolute path to the repository or directory to scan.",
                        },
                    },
                    required: ["targetPath"],
                },
            },
            {
                name: "run_dep_scan",
                description: "Run a dependency vulnerability scan using Trivy.",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetPath: {
                            type: "string",
                            description: "Absolute path to the repository or directory to scan.",
                        },
                    },
                    required: ["targetPath"],
                },
            },
            {
                name: "run_evidence_scan",
                description: "Run non-technical evidence scan (Scopes, Docs, Privacy).",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetPath: {
                            type: "string",
                            description: "Absolute path to the repository or directory to scan.",
                        },
                    },
                    required: ["targetPath"],
                },
            },
            {
                name: "run_infra_scan",
                description: "Run Infrastructure scan (Docker, CI/CD, Secrets).",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetPath: {
                            type: "string",
                            description: "Absolute path to the repository or directory to scan.",
                        },
                    },
                    required: ["targetPath"],
                },
            },
            {
                name: "run_dast_scan",
                description: "Run a Dynamic Application Security Testing (DAST) scan on a running URL.",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetUrl: {
                            type: "string",
                            description: "URL of the running application to scan (e.g., http://localhost:3000).",
                        },
                        authToken: {
                            type: "string",
                            description: "Optional Bearer token for authenticated scanning.",
                        },
                    },
                    required: ["targetUrl"],
                },
            },
            {
                name: "run_secret_scan",
                description: "Run secret scanning using Gitleaks (scans git history).",
                inputSchema: {
                    type: "object",
                    properties: {
                        targetPath: {
                            type: "string",
                            description: "Absolute path to the repository or directory to scan.",
                        },
                    },
                    required: ["targetPath"],
                },
            },
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        if (name === "run_sast_scan") {
            const { targetPath } = z
                .object({ targetPath: z.string() })
                .parse(args);

            const scanResult = await runSemgrepScan(targetPath);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        if (name === "run_dep_scan") {
            const { targetPath } = z
                .object({ targetPath: z.string() })
                .parse(args);

            const scanResult = await runTrivyScan(targetPath);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        if (name === "run_evidence_scan") {
            const { targetPath } = z
                .object({ targetPath: z.string() })
                .parse(args);

            const scanResult = await runEvidenceScan(targetPath);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        if (name === "run_infra_scan") {
            const { targetPath } = z
                .object({ targetPath: z.string() })
                .parse(args);

            const scanResult = await runInfraScan(targetPath);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        if (name === "run_dast_scan") {
            const { targetUrl, authToken } = z
                .object({
                    targetUrl: z.string(),
                    authToken: z.string().optional()
                })
                .parse(args);

            const scanResult = await runDastScan(targetUrl, authToken);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        if (name === "run_secret_scan") {
            const { targetPath } = z
                .object({ targetPath: z.string() })
                .parse(args);

            const scanResult = await runGitleaksScan(targetPath);
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(scanResult, null, 2),
                    },
                ],
            };
        }

        throw new Error(`Unknown tool: ${name}`);
    } catch (error: any) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error executing tool ${name}: ${error.message}`,
                },
            ],
            isError: true,
        };
    }
});

async function run() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("AI Auditor Scanner MCP Server running on stdio");
}

run().catch((error) => {
    console.error("Fatal error running server:", error);
    process.exit(1);
});
