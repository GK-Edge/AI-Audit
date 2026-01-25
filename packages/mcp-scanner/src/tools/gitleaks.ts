import { exec } from "child_process";
import * as util from "util";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ScanResult, Finding } from "@ai-auditor/shared-types";

const execAsync = util.promisify(exec);
const readFileAsync = util.promisify(fs.readFile);
const unlinkAsync = util.promisify(fs.unlink);

export async function runGitleaksScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const tempReportPath = path.join(os.tmpdir(), `gitleaks-report-${Date.now()}.json`);

    try {
        // Check if gitleaks is available
        try {
            await execAsync("gitleaks version");
        } catch (e) {
            console.warn("Gitleaks not found. Skipping secret scan.");
            return {
                tool: "gitleaks",
                timestamp: new Date().toISOString(),
                durationMs: Date.now() - startTime,
                findings: [],
                scanPath: targetPath,
                success: false,
                error: "Gitleaks is not installed or not in PATH."
            };
        }

        // Check if target directory is a git repo (gitleaks needs .git for history scan, or use --no-git)
        // We want history scan if possible, but fallback to no-git if not.
        let isGitRepo = false;
        try {
            await execAsync("git rev-parse --is-inside-work-tree", { cwd: targetPath });
            isGitRepo = true;
        } catch (e) {
            isGitRepo = false;
        }

        let command = "";
        if (isGitRepo) {
            // Scan history
            command = `gitleaks detect --source="${targetPath}" --report-path="${tempReportPath}" --report-format=json --verbose`;
        } else {
            // Scan current files only (no history)
            command = `gitleaks detect --source="${targetPath}" --no-git --report-path="${tempReportPath}" --report-format=json --verbose`;
        }

        // Gitleaks returns exit code 1 if leaks are found, so we expect potential "failure" in execution
        try {
            await execAsync(command, { maxBuffer: 10 * 1024 * 1024 });
        } catch (error: any) {
            // If exit code is 1, it might just mean findings were found.
            // If report file exists, it was successful finding leaks.
            if (!fs.existsSync(tempReportPath) && error.code !== 1) {
                throw error; // Real error
            }
        }

        let findings: Finding[] = [];
        if (fs.existsSync(tempReportPath)) {
            const reportContent = await readFileAsync(tempReportPath, "utf-8");
            const gitleaksOutput = JSON.parse(reportContent);

            // Map gitleaks results to our unified Finding format
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            findings = gitleaksOutput.map((r: any, index: number) => ({
                id: `gitleaks-${r.RuleID}-${index}`,
                tool: "gitleaks",
                title: `Secret Detected: ${r.Description || r.RuleID}`,
                description: `Found potential secret in ${r.File}.
Match: ${r.Secret.substring(0, 5)}...
Commit: ${r.Commit}
Author: ${r.Author}
Date: ${r.Date}`,
                severity: "CRITICAL", // Secrets are always critical
                category: "Secrets",
                location: {
                    path: r.File,
                    startLine: r.StartLine,
                    endLine: r.EndLine,
                    startCol: r.StartColumn,
                    endCol: r.EndColumn
                },
                metadata: r
            }));

            // Clean up
            await unlinkAsync(tempReportPath);
        }

        return {
            tool: "gitleaks",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetPath,
            success: true
        };

    } catch (error: any) {
        return {
            tool: "gitleaks",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetPath,
            success: false,
            error: error.message || "Unknown error during gitleaks scan"
        };
    } finally {
        if (fs.existsSync(tempReportPath)) {
            try { await unlinkAsync(tempReportPath); } catch (e) { }
        }
    }
}
