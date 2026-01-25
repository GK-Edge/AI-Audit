import { Finding, FindingGroup } from "@ai-auditor/shared-types";
import crypto from "crypto";

export class Deduplicator {

    public group(findings: Finding[]): FindingGroup[] {
        const groups: Map<string, FindingGroup> = new Map();

        for (const finding of findings) {
            // Generate a fingerprint hash
            // Strategy: Group by "Rule ID" + "File Path" is too granular (doesn't solve '221 violations' across many files)
            // Strategy: Group by "Rule ID" is too broad (merges distinct issues)
            // Strategy for CASA: Group by "Rule ID". 
            // The goal is to say "You have 221 Path Traversal Issues".
            // So we group by Rule ID (Title).

            const fingerprint = this.generateFingerprint(finding);

            if (groups.has(fingerprint)) {
                const group = groups.get(fingerprint)!;
                group.findings.push(finding);

                // Keep the highest severity in the group
                if (this.severityWeight(finding.severity) > this.severityWeight(group.severity)) {
                    group.severity = finding.severity;
                }

                // Accumulate Risk Score (naive max for now, improved later by RiskEngine)
                // We'll let RiskEngine run BEFORE dedupe, so findings have scores.
                // Here we just take the max score of the group.
            } else {
                groups.set(fingerprint, {
                    id: fingerprint,
                    title: finding.title,
                    description: finding.description,
                    severity: finding.severity,
                    findings: [finding],
                    riskScore: 0, // Will be calculated/aggregated 
                    remediation: finding.remediation?.description
                });
            }
        }

        return Array.from(groups.values());
    }

    private generateFingerprint(finding: Finding): string {
        // We group strictly by ID (or mapped Title) to collapse the "221 violations" into 1 row
        // If the ID is generic, we might want to include category.
        return finding.title;
    }

    private severityWeight(severity: string): number {
        switch (severity.toUpperCase()) {
            case "CRITICAL": return 5;
            case "HIGH": return 4;
            case "MEDIUM": return 3;
            case "LOW": return 2;
            case "INFO": return 1;
            default: return 0;
        }
    }
}
