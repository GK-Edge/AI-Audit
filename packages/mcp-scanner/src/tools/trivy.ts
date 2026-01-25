import { exec } from "child_process";
import * as util from "util";
import { ScanResult, Finding } from "@ai-auditor/shared-types";

const execAsync = util.promisify(exec);

export async function runTrivyScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    try {
        try {
            await execAsync("trivy --version");
        } catch (e) {
            throw new Error("Trivy is not installed or not in PATH.");
        }

        // Run trivy fs scan with json output
        const command = `trivy fs --format json "${targetPath}"`;
        const { stdout } = await execAsync(command, { maxBuffer: 10 * 1024 * 1024 });

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
