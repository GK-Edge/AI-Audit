import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { generateCasaReport } from "./report-generator.js";
import { Finding } from "@ai-auditor/shared-types";

const server = new Server(
    {
        name: "ai-auditor-reporter",
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
                name: "generate_report",
                description: "Generate a compliance report based on a specific audit profile (CASA, CISSP, SOC2) in markdown or SARIF.",
                inputSchema: {
                    type: "object",
                    properties: {
                        findings: {
                            type: "array",
                            description: "List of findings from scanners.",
                            items: { type: "object" }
                        },
                        outputPath: {
                            type: "string",
                            description: "Path to write the report to."
                        },
                        format: {
                            type: "string",
                            description: "Report format (markdown or sarif). Defaults to markdown unless outputPath ends with .sarif.",
                            enum: ["markdown", "sarif"]
                        },
                        profileId: {
                            type: "string",
                            description: "The audit profile ID to use (e.g., 'CASA-Tier-2', 'CISSP-Domain-8', 'SOC2-CC'). Defaults to CASA.",
                            enum: ["CASA-Tier-2", "CISSP-Domain-8", "SOC2-CC"]
                        }
                    },
                    required: ["findings", "outputPath"],
                },
            },
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        if (name === "generate_report") {
            const params = z.object({
                findings: z.array(z.any()),
                outputPath: z.string(),
                profileId: z.string().optional(),
                format: z.enum(["markdown", "sarif"]).optional()
            }).parse(args);

            // Safe cast
            const findings = params.findings as Finding[];

            const result = await generateCasaReport(findings, params.outputPath, params.profileId || "CASA-Tier-2", params.format);
            return {
                content: [
                    {
                        type: "text",
                        text: `Report generated successfully at ${result.path}`,
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
    console.error("AI Auditor Reporter MCP Server running on stdio");
}

run().catch((error) => {
    console.error("Fatal error running server:", error);
    process.exit(1);
});
