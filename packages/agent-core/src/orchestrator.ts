import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import path from "path";
import { fileURLToPath } from "url";
import { Finding, ScanExecutionSummary, ScanResult, Severity, FindingGroup } from "@ai-auditor/shared-types";
import { Normalizer } from "./analysis/normalizer.js";
import { RiskEngine } from "./analysis/risk-engine.js";
import { Deduplicator } from "./analysis/deduplicator.js";

// Helper to start MCP client for a local package
async function createClient(packageName: string, scriptPath: string) {
    const transport = new StdioClientTransport({
        command: "node",
        args: [scriptPath],
    });

    const client = new Client(
        { name: "agent-core", version: "1.0.0" },
        { capabilities: {} }
    );

    await client.connect(transport);
    return client;
}

const severityOrder: Record<Severity, number> = {
    INFO: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
};

function getHighestSeverity(findings: Finding[]): Severity | null {
    if (findings.length === 0) return null;
    return findings.reduce((highest, finding) => {
        if (!highest) return finding.severity;
        return severityOrder[finding.severity] > severityOrder[highest] ? finding.severity : highest;
    }, null as Severity | null);
}

function summarizeScan(scanData: ScanResult): ScanExecutionSummary {
    return {
        tool: scanData.tool,
        success: scanData.success,
        findingsCount: scanData.findings.length,
        durationMs: scanData.durationMs,
        error: scanData.error
    };
}

function summarizeScannerError(tool: string, error: unknown): ScanExecutionSummary {
    return {
        tool,
        success: false,
        findingsCount: 0,
        durationMs: 0,
        error: error instanceof Error ? error.message : String(error)
    };
}

export async function runAudit(
    targetPath: string,
    outputPath: string,
    profileId: string = "CASA-Tier-2",
    targetUrl?: string,
    authToken?: string,
    reportFormat?: "markdown" | "sarif" | "both",
    failOn?: Severity
) {
    // Resolve paths to the MCP server scripts (dist/index.js)
    // Assuming monorepo structure: agent-core/../../mcp-scanner/dist/index.js
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const scannerScript = path.resolve(__dirname, "../../mcp-scanner/dist/index.js");
    const reporterScript = path.resolve(__dirname, "../../mcp-reporter/dist/index.js");

    console.log("Connecting to MCP Servers...");
    let scannerClient: Client | null = null;
    let reporterClient: Client | null = null;

    try {
        scannerClient = await createClient("scanner", scannerScript);
        reporterClient = await createClient("reporter", reporterScript);

        console.log("Connected. Starting Scans...");
        // Contextual Filter: Definitions
        const IGNORED_DIRS = ["test", "tests", "spec", "mock", "node_modules", "dist"];

        const allFindings: Finding[] = [];
        const scanSummary: ScanExecutionSummary[] = [];

        // 1. Run SAST Scan (Semgrep)
        console.log("Running SAST Scan (Semgrep)...");
        try {
            const sastResult = await scannerClient.request(
                {
                    method: "tools/call",
                    params: {
                        name: "run_sast_scan",
                        arguments: { targetPath }
                    }
                },
                CallToolResultSchema,
                { timeout: 600000 } // Increase timeout to 10 minutes for large repos
            );

            if (sastResult.content[0].type === "text") {
                const scanData = JSON.parse(sastResult.content[0].text) as ScanResult;
                scanSummary.push(summarizeScan(scanData));
                if (scanData.success) {
                    // Deep Audit Step: Validate Findings Context
                    const relevantFindings = scanData.findings.filter(f => {
                        const isIgnored = IGNORED_DIRS.some(dir => f.location.path.includes(`/${dir}/`) || f.location.path.startsWith(`${dir}/`));
                        if (isIgnored) return false;
                        return true;
                    });

                    allFindings.push(...relevantFindings);
                    console.log(`SAST Scan complete. Found ${scanData.findings.length} raw issues (${relevantFindings.length} relevant).`);
                } else {
                    console.error(`SAST Scan reported error: ${scanData.error}`);
                    if (scanData.error?.includes("not installed")) {
                        throw new Error("Critical Dependency Missing: Semgrep is not installed. Audit cannot proceed.");
                    }
                }
            }
        } catch (err) {
            scanSummary.push(summarizeScannerError("semgrep", err));
            console.error("Failed to run SAST scan:", err);
            throw err; // Re-throw to fail the process
        }

        // 2. Run Dependency Scan (Trivy)
        console.log("Running Dependency Scan (Trivy)...");
        try {
            const depResult = await scannerClient.request(
                {
                    method: "tools/call",
                    params: {
                        name: "run_dep_scan",
                        arguments: { targetPath }
                    }
                },
                CallToolResultSchema,
                { timeout: 600000 }
            );

            if (depResult.content[0].type === "text") {
                const scanData = JSON.parse(depResult.content[0].text) as ScanResult;
                scanSummary.push(summarizeScan(scanData));
                if (scanData.success) {
                    allFindings.push(...scanData.findings);
                    console.log(`Dependency Scan complete. Found ${scanData.findings.length} issues.`);
                } else {
                    console.error(`Dependency Scan reported error: ${scanData.error}`);
                    if (scanData.error?.includes("not installed")) {
                        throw new Error("Critical Dependency Missing: Trivy is not installed. Audit cannot proceed.");
                    }
                }
            }
        } catch (err) {
            scanSummary.push(summarizeScannerError("trivy", err));
            console.error("Failed to run Dependency scan:", err);
            throw err; // Re-throw to fail the process
        }

        // 3. Run Evidence Scan (Scopes, Docs, Privacy)
        console.log("Running Evidence Scan (Scopes, Docs, Privacy)...");
        try {
            const evidenceResult = await scannerClient.request(
                {
                    method: "tools/call",
                    params: {
                        name: "run_evidence_scan",
                        arguments: { targetPath }
                    }
                },
                CallToolResultSchema
            );

            if (evidenceResult.content[0].type === "text") {
                const scanData = JSON.parse(evidenceResult.content[0].text) as ScanResult;
                scanSummary.push(summarizeScan(scanData));
                if (scanData.success) {
                    allFindings.push(...scanData.findings);
                    console.log(`Evidence Scan complete. Found ${scanData.findings.length} issues/items.`);
                } else {
                    console.warn(`Evidence Scan reported error: ${scanData.error}`);
                }
            }
        } catch (err) {
            scanSummary.push(summarizeScannerError("evidence-scanner", err));
            console.error("Failed to run Evidence scan:", err);
        }

        // 4. Run Secret Scan (Gitleaks)
        console.log("Running Secret Scan (Gitleaks)...");
        try {
            const secretResult = await scannerClient.request(
                {
                    method: "tools/call",
                    params: {
                        name: "run_secret_scan",
                        arguments: { targetPath }
                    }
                },
                CallToolResultSchema
            );

            if (secretResult.content[0].type === "text") {
                const scanData = JSON.parse(secretResult.content[0].text) as ScanResult;
                scanSummary.push(summarizeScan(scanData));
                if (scanData.success) {
                    allFindings.push(...scanData.findings);
                    console.log(`Secret Scan complete. Found ${scanData.findings.length} issues.`);
                } else {
                    console.warn(`Secret Scan reported error: ${scanData.error}`);
                }
            }
        } catch (err) {
            scanSummary.push(summarizeScannerError("gitleaks", err));
            console.error("Failed to run Secret scan:", err);
        }

        // 5. Run Infra Scan (Docker, Secrets, CI/CD)
        console.log("Running Infrastructure Scan (Docker, Secrets, CI/CD)...");
        try {
            const infraResult = await scannerClient.request(
                {
                    method: "tools/call",
                    params: {
                        name: "run_infra_scan",
                        arguments: { targetPath }
                    }
                },
                CallToolResultSchema,
                { timeout: 600000 }
            );

            if (infraResult.content[0].type === "text") {
                const scanData = JSON.parse(infraResult.content[0].text) as ScanResult;
                scanSummary.push(summarizeScan(scanData));
                if (scanData.success) {
                    allFindings.push(...scanData.findings);
                    console.log(`Infra Scan complete. Found ${scanData.findings.length} issues.`);
                } else {
                    console.warn(`Infra Scan reported error: ${scanData.error}`);
                }
            }
        } catch (err) {
            scanSummary.push(summarizeScannerError("infra-scanner", err));
            console.error("Failed to run Infra scan:", err);
        }

        // 5. Run DAST Scan (if URL provided)
        if (targetUrl) {
            console.log(`Running DAST Scan on ${targetUrl}...`);
            try {
                const dastResult = await scannerClient.request(
                    {
                        method: "tools/call",
                        params: {
                            name: "run_dast_scan",
                            arguments: { targetUrl, authToken }
                        }
                    },
                    CallToolResultSchema
                );

                if (dastResult.content[0].type === "text") {
                    const scanData = JSON.parse(dastResult.content[0].text) as ScanResult;
                    scanSummary.push(summarizeScan(scanData));
                    if (scanData.success) {
                        allFindings.push(...scanData.findings);
                        console.log(`DAST Scan complete. Found ${scanData.findings.length} issues.`);
                    } else {
                        console.warn(`DAST Scan reported error: ${scanData.error}`);
                    }
                }
            } catch (err) {
                scanSummary.push(summarizeScannerError("dast-scanner", err));
                console.error("Failed to run DAST scan:", err);
            }
        } else {
            scanSummary.push({
                tool: "dast-scanner",
                success: true,
                findingsCount: 0,
                durationMs: 0,
                skipped: true,
                warnings: ["DAST skipped because no target URL was provided."]
            });
        }

        // --- PHASE 5: INTELLIGENCE ENGINE ---
        console.log("Running Intelligence Engine (Normalization, Risk Scoring, Deduplication)...");

        // 1. Normalization
        const normalizer = new Normalizer();
        const normalizedFindings = normalizer.normalize(allFindings);

        // 2. Risk Scoring
        const riskEngine = new RiskEngine();
        const riskScoredFindings = riskEngine.analyze(normalizedFindings);

        // 3. Deduplication
        const deduplicator = new Deduplicator();
        const finalGroups: FindingGroup[] = deduplicator.group(riskScoredFindings);

        console.log(`Intelligence Engine Reduced ${allFindings.length} raw findings to ${finalGroups.length} unique issues.`);


        // 6. Generate Report
        // 6. Generate Report
        console.log(`Generating Report(s) using profile ${profileId}...`);

        const formatsToGenerate: ("markdown" | "sarif")[] = [];
        if (reportFormat === "both") {
            formatsToGenerate.push("markdown", "sarif");
        } else if (reportFormat) {
            formatsToGenerate.push(reportFormat);
        } else {
            formatsToGenerate.push("markdown"); // Default
        }

        for (const fmt of formatsToGenerate) {
            // Determine output path with correct extension
            const ext = path.extname(outputPath);
            const base = outputPath.slice(0, outputPath.length - ext.length);
            const targetExt = fmt === "markdown" ? ".md" : ".sarif";
            // If the original output path already had the correct extension, use it (mostly for single file case), 
            // but for 'both' or mismatch, force the extension.
            // actually, always forcing it based on base name is safer to avoid "report.md.sarif" unless intended, 
            // but relying on 'base' handles "report.md" -> "report" -> "report.sarif".
            const currentOutputPath = `${base}${targetExt}`;

            console.log(`Generating ${fmt} report at ${currentOutputPath}...`);
            try {
                const reportResult = await reporterClient.request(
                    {
                        method: "tools/call",
                        params: {
                            name: "generate_report",
                            arguments: {
                                findings: finalGroups,
                                outputPath: currentOutputPath,
                                profileId,
                                format: fmt,
                                scanSummary
                            }
                        }
                    },
                    CallToolResultSchema
                );
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                console.log((reportResult.content[0] as any).text);
            } catch (err) {
                console.error(`Failed to generate ${fmt} report:`, err);
            }
        }

        if (failOn) {
            const threshold = severityOrder[failOn];
            const blockingGroups = finalGroups.filter((group) => severityOrder[group.severity] >= threshold);
            if (blockingGroups.length > 0) {
                const blockingFindings = blockingGroups.flatMap(group => group.findings);
                const highestSeverity = getHighestSeverity(blockingFindings);
                throw new Error(`Fail-on threshold met (${failOn}). ${blockingGroups.length} unique issue(s) affecting ${blockingFindings.length} finding instance(s) at or above ${failOn}. Highest severity: ${highestSeverity}.`);
            }
        }
    } finally {
        if (scannerClient) {
            await scannerClient.close();
        }
        if (reporterClient) {
            await reporterClient.close();
        }
    }
}
