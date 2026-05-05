import { execFile } from "child_process";
import * as util from "util";
import { ScanResult, Finding } from "@ai-auditor/shared-types";
import * as path from "path";

const execFileAsync = util.promisify(execFile);

export async function runTrivyScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    try {
        try {
            await execFileAsync("trivy", ["--version"]);
        } catch (e) {
            throw new Error("Trivy is not installed or not in PATH.");
        }

        // Parse .auditignore if it exists
        const skipArgs: string[] = [];
        try {
            const ignorePath = path.join(targetPath, ".auditignore");
            const fs = await import("fs/promises");
            const ignoreContent = await fs.readFile(ignorePath, "utf-8");
            const ignores = ignoreContent.split("\n").filter(line => line.trim() && !line.startsWith("#"));

            ignores.forEach(pattern => {
                const clean = pattern.trim();
                // Heuristic: if ends with / or has no extension, assume dir. Otherwise file.
                if (clean.endsWith("/") || !path.extname(clean)) {
                    skipArgs.push("--skip-dirs", clean.replace(/\/$/, ''));
                } else {
                    skipArgs.push("--skip-files", clean);
                }
            });
        } catch (e) {
            // No .auditignore found
        }

        // Run trivy fs scan with json output
        const args = ["fs", "--format", "json", ...skipArgs, targetPath];
        const { stdout } = await execFileAsync("trivy", args, { maxBuffer: 10 * 1024 * 1024 });

        const trivyOutput = JSON.parse(stdout);
        const findings: Finding[] = [];

        // Trivy struct: Results[] -> Vulnerabilities[]
        if (trivyOutput.Results) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            trivyOutput.Results.forEach((res: any) => {
                if (res.Vulnerabilities) {
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    res.Vulnerabilities.forEach((vuln: any) => {
                        findings.push({
                            id: vuln.VulnerabilityID,
                            tool: "trivy",
                            title: `${vuln.PkgName} - ${vuln.VulnerabilityID}`,
                            description: vuln.Description,
                            severity: mapSeverity(vuln.Severity),
                            category: "DEPENDENCY",
                            location: {
                                path: res.Target,
                                // Trivy fs scan often points to the lockfile/manifest, line numbers might not be available
                            },
                            // Trivy often provides CWE IDs in a field if available, but mapping varies. keeping simplified for now.
                            cweId: [],
                            metadata: vuln
                        });
                    });
                }
            });
        }

        return {
            tool: "trivy",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetPath,
            success: true
        };

    } catch (error: any) {
        return {
            tool: "trivy",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetPath,
            success: false,
            error: error.message || "Unknown error during trivy scan"
        };
    }
}

function mapSeverity(severity: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
    switch (severity.toUpperCase()) {
        case "CRITICAL": return "CRITICAL";
        case "HIGH": return "HIGH";
        case "MEDIUM": return "MEDIUM";
        case "LOW": return "LOW";
        default: return "INFO";
    }
}
