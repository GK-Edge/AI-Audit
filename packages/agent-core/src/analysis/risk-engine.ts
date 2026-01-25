import { Finding, Severity } from "@ai-auditor/shared-types";

export class RiskEngine {

    public analyze(findings: Finding[]): Finding[] {
        return findings.map(f => this.analyzeSingle(f));
    }

    private analyzeSingle(finding: Finding): Finding {
        let riskScore = this.baseRiskScore(finding.severity);
        let newSeverity = finding.severity;

        // Context Factor: Test Files
        // If it's a test file, the risk is drastically lower
        const isTestFile = this.isTestFile(finding.location.path);
        if (isTestFile) {
            riskScore *= 0.1; // 90% reduction
            newSeverity = this.downgradeSeverity(newSeverity, 2); // Drop 2 levels (CRITICAL -> MEDIUM)
        }

        // Context Factor: Vendor Files (node_modules)
        // Usually ignored, but if scanned, we treat as low risk unless it's a direct CVE
        if (finding.location.path.includes("node_modules")) {
            // For dependency scans (Trivy), we keep severity as is. 
            // For SAST in node_modules, we downgrade.
            if (finding.category === 'SAST') {
                riskScore *= 0.1;
                newSeverity = "INFO";
            }
        }

        // Store the calculated risk score in metadata for debugging
        if (!finding.metadata) finding.metadata = {};
        finding.metadata.riskScore = riskScore;
        finding.metadata.originalSeverity = finding.severity;

        return {
            ...finding,
            severity: newSeverity
        };
    }

    private isTestFile(filePath: string): boolean {
        const lower = filePath.toLowerCase();
        return lower.includes(".test.") ||
            lower.includes(".spec.") ||
            lower.includes("/test/") ||
            lower.includes("/tests/") ||
            lower.includes("/__tests__/") ||
            lower.includes("/mock/");
    }

    private baseRiskScore(severity: Severity): number {
        switch (severity) {
            case "CRITICAL": return 100;
            case "HIGH": return 80;
            case "MEDIUM": return 50;
            case "LOW": return 20;
            case "INFO": return 0;
            default: return 0;
        }
    }

    private downgradeSeverity(current: Severity, levels: number): Severity {
        const severityOrder: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        let index = severityOrder.indexOf(current);
        index = Math.max(0, index - levels);
        return severityOrder[index];
    }
}
