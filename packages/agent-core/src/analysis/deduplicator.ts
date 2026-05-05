import { Finding, FindingGroup, RegulationMapping } from "@ai-auditor/shared-types";

export class Deduplicator {

    public group(findings: Finding[]): FindingGroup[] {
        const groups: Map<string, FindingGroup> = new Map();

        for (const finding of findings) {
            const fingerprint = this.generateFingerprint(finding);

            if (groups.has(fingerprint)) {
                const group = groups.get(fingerprint)!;
                group.findings.push(finding);

                // Keep the highest severity in the group
                if (this.severityWeight(finding.severity) > this.severityWeight(group.severity)) {
                    group.severity = finding.severity;
                }

                group.riskScore = Math.max(group.riskScore, this.getRiskScore(finding));
                group.tools = this.unique([...(group.tools || []), finding.tool]);
                group.categories = this.unique([...(group.categories || []), finding.category]);
                group.cweId = this.unique([...(group.cweId || []), ...(finding.cweId || [])]);
                group.mappings = this.uniqueMappings([...(group.mappings || []), ...(finding.mappings || [])]);
            } else {
                groups.set(fingerprint, {
                    id: fingerprint,
                    title: finding.title,
                    description: finding.description,
                    severity: finding.severity,
                    findings: [finding],
                    riskScore: this.getRiskScore(finding),
                    remediation: finding.remediation?.description,
                    tools: [finding.tool],
                    categories: [finding.category],
                    cweId: finding.cweId || [],
                    mappings: finding.mappings || []
                });
            }
        }

        return Array.from(groups.values()).sort((a, b) => {
            const riskDiff = b.riskScore - a.riskScore;
            if (riskDiff !== 0) return riskDiff;
            return this.severityWeight(b.severity) - this.severityWeight(a.severity);
        });
    }

    private generateFingerprint(finding: Finding): string {
        const ruleId = this.getStableRuleId(finding);
        const packageKey = finding.category === "DEPENDENCY" ? `:${finding.metadata?.PkgName || finding.metadata?.pkgName || "unknown-package"}` : "";
        return [finding.tool, finding.category, ruleId + packageKey].join(":");
    }

    private getStableRuleId(finding: Finding): string {
        if (finding.metadata?.check_id) return String(finding.metadata.check_id);
        if (finding.metadata?.VulnerabilityID) return String(finding.metadata.VulnerabilityID);
        if (finding.metadata?.RuleID) return String(finding.metadata.RuleID);
        if (/^.+-\d+$/.test(finding.id)) return finding.id.replace(/-\d+$/, "");
        return finding.id || finding.title;
    }

    private getRiskScore(finding: Finding): number {
        const riskScore = finding.metadata?.riskScore;
        return typeof riskScore === "number" ? riskScore : this.severityWeight(finding.severity) * 20;
    }

    private unique<T extends string>(items: T[]): T[] {
        return [...new Set(items)];
    }

    private uniqueMappings(mappings: RegulationMapping[]): RegulationMapping[] {
        const seen = new Set<string>();
        return mappings.filter(mapping => {
            const key = `${mapping.standard}:${mapping.controlId}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
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
