import { exec } from "child_process";
import * as util from "util";
import * as path from "path";
import { ScanResult, Finding } from "@ai-auditor/shared-types";

import { fileURLToPath } from 'url';

const execAsync = util.promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runSemgrepScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    try {
        // Check if semgrep is available
        try {
            await execAsync("semgrep --version");
        } catch (e) {
            throw new Error("Semgrep is not installed or not in PATH.");
        }

        // Run semgrep with json output
        // Using auto configuration for broadest coverage without login requirement
        // Resolve absolute path to local rules
        const rulePath = path.resolve(__dirname, "../../src/rules/casa-token-security.yaml");
        const command = `semgrep scan --config=auto --config="${rulePath}" --json "${targetPath}"`;
        const { stdout } = await execAsync(command, { maxBuffer: 10 * 1024 * 1024 });

        const semgrepOutput = JSON.parse(stdout);

        // Map semgrep results to our unified Finding format
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const findings: Finding[] = semgrepOutput.results.map((r: any) => ({
            id: r.check_id + "-" + r.start.line,
            tool: "semgrep",
            title: r.check_id,
            description: r.extra.message,
            severity: mapSeverity(r.extra.severity),
            category: "SAST",
            location: {
                path: r.path,
                startLine: r.start.line,
                endLine: r.end.line,
                startCol: r.start.col,
                endCol: r.end.col
            },
            cweId: r.extra.metadata?.cwe ? (Array.isArray(r.extra.metadata.cwe) ? r.extra.metadata.cwe.map((c: string) => c.split(':')[0]) : [r.extra.metadata.cwe.split(':')[0]]) : [],
            metadata: r
        }));

        return {
            tool: "semgrep",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetPath,
            success: true
        };

    } catch (error: any) {
        // Semgrep returns non-zero exit code if findings are found in some configurations, 
        // but usually with --json it cleanly outputs. 
        // Dealing with actual execution errors here.
        return {
            tool: "semgrep",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetPath,
            success: false,
            error: error.message || "Unknown error during semgrep scan"
        };
    }
}

function mapSeverity(semgrepSeverity: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
    switch (semgrepSeverity.toUpperCase()) {
        case "ERROR": return "HIGH";
        case "WARNING": return "MEDIUM";
        case "INFO": return "LOW";
        default: return "INFO";
    }
}
