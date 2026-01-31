import { Finding, FindingGroup, CASA_PROFILE, CISSP_PROFILE, SOC2_PROFILE, AuditProfile, Severity } from "@ai-auditor/shared-types";
import * as fs from "fs/promises";
import * as path from "path";

function isGroup(item: Finding | FindingGroup): item is FindingGroup {
    return (item as FindingGroup).findings !== undefined;
}

type ReportFormat = "markdown" | "sarif";

function resolveProfile(profileId: string): AuditProfile {
    switch (profileId) {
        case "CISSP-Domain-8":
            return CISSP_PROFILE;
        case "SOC2-CC":
            return SOC2_PROFILE;
        default:
            return CASA_PROFILE;
    }
}

function resolveReportFormat(outputPath: string, format?: ReportFormat): ReportFormat {
    if (format) return format;
    const lowerPath = outputPath.toLowerCase();
    if (lowerPath.endsWith(".sarif") || lowerPath.endsWith(".sarif.json")) return "sarif";
    return "markdown";
}

function mapSeverityToSarifLevel(severity: Severity): "error" | "warning" | "note" {
    switch (severity) {
        case "CRITICAL":
        case "HIGH":
            return "error";
        case "MEDIUM":
            return "warning";
        case "LOW":
        case "INFO":
        default:
            return "note";
    }
}

async function generateSarifReport(items: (Finding | FindingGroup)[], outputPath: string): Promise<{ path: string }> {
    const rulesMap = new Map<string, { id: string; title: string; description: string; severity: Severity; tool: string; cweId?: string[] }>();

    items.forEach((item) => {
        // Use representative finding for rule metadata
        const f = isGroup(item) ? item.findings[0] : item;

        if (!rulesMap.has(f.id)) {
            rulesMap.set(f.id, {
                id: f.id,
                title: isGroup(item) ? item.title : f.title, // Use grouped title if available
                description: isGroup(item) ? item.description : f.description,
                severity: isGroup(item) ? item.severity : f.severity,
                tool: f.tool,
                cweId: f.cweId
            });
        }
    });

    const rules = Array.from(rulesMap.values()).map((rule) => ({
        id: rule.id,
        shortDescription: { text: rule.title },
        fullDescription: { text: rule.description },
        defaultConfiguration: { level: mapSeverityToSarifLevel(rule.severity) },
        properties: {
            severity: rule.severity,
            tool: rule.tool,
            cweId: rule.cweId
        }
    }));

    const results = items.map((item) => {
        const findings = isGroup(item) ? item.findings : [item as Finding];
        const representative = findings[0];
        const isGroupItem = isGroup(item);

        const locations = findings.map(f => {
            const region: Record<string, number> = {};
            if (f.location.startLine) region.startLine = f.location.startLine;
            if (f.location.startCol) region.startColumn = f.location.startCol;
            if (f.location.endLine) region.endLine = f.location.endLine;
            if (f.location.endCol) region.endColumn = f.location.endCol;

            const physicalLocation: Record<string, unknown> = {
                artifactLocation: {
                    uri: f.location.path
                }
            };

            if (Object.keys(region).length > 0) {
                physicalLocation.region = region;
            }
            return { physicalLocation };
        });

        return {
            ruleId: representative.id,
            level: mapSeverityToSarifLevel(isGroupItem ? item.severity : representative.severity),
            message: {
                text: `${isGroupItem ? item.title : representative.title}: ${isGroupItem ? item.description : representative.description}`
            },
            locations: locations, // SARIF allows multiple locations for one result!
            properties: {
                severity: isGroupItem ? item.severity : representative.severity,
                category: representative.category,
                tool: representative.tool,
                cweId: representative.cweId,
                remediation: isGroupItem ? item.remediation : representative.remediation?.description
            }
        };
    });

    const sarifReport = {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "AI Auditor",
                        version: "1.0.0",
                        rules
                    }
                },
                results
            }
        ]
    };

    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(outputPath, JSON.stringify(sarifReport, null, 2), "utf-8");

    return { path: outputPath };
}

async function generateMarkdownReport(items: (Finding | FindingGroup)[], outputPath: string, profile: AuditProfile): Promise<{ path: string }> {
    const lines: string[] = [];

    // 1. Header
    lines.push(`# ${profile.name} Report`);
    lines.push(`**Date**: ${new Date().toISOString()}`);
    lines.push(`**Description**: ${profile.description}`);
    lines.push(`\n---`);

    // 2. Control Assessment Logic
    lines.push(`\n## Control Assessment`);

    let passedControls = 0;
    let totalFindingsCount = 0;

    for (const control of profile.controls) {
        // A. Automatic violations via CWE/Category
        const violations = items.filter(item => {
            const f = isGroup(item) ? item.findings[0] : item; // Use representative finding

            // 1. Check strict CWE match
            if (f.cweId && control.relatedCwes) {
                if (f.cweId.some(c => control.relatedCwes!.includes(c))) return true;
            }

            // 2. Fallback: Category-based mapping (Critical for generic findings)
            // This ensures logic like "All Dependencies" maps to "Vulnerability Management" control
            if (control.id === "CASA.4.1" && f.category === "DEPENDENCY") return true;
            if (control.id === "CASA.3.1") { // Secrets
                if (f.category === "SECRET") return true;
                if (f.id === "DOCKER-SECRETS-IN-ENV") return true;
                if (f.id === "DOT-ENV-FILE-DETECTED") return true;
                // Gitleaks
                if (f.tool === "gitleaks") return true;
            }

            // Map general SAST criticals to Input Validation or Data Protection as a catch-all if CWE is missing
            if (control.id === "CASA.1.1" && f.category === "SAST" && f.severity === "CRITICAL") return true;

            // 3. Evidence Mappings (CASA 5, 6, 7)
            if (control.id === "CASA.5.1" && (f.id === "RESTRICTED-SCOPE-WARNING" || f.id === "OAUTH-SCOPES-DETECTED")) return true;
            if (control.id === "CASA.6.1" && f.id === "NO-RETENTION-LOGIC") return true;
            if (control.id === "CASA.7.1" && (f.id.startsWith("MISSING-DOC-") || f.id === "MISSING-VDP-SECURITY-TXT")) return true;

            // 4. Advanced AppSec Mappings
            if (control.id === "CASA.2.1") { // Data Protection
                if (f.id === "SENSITIVE-LOG-DETECTED") return true;
                if (f.id === "INSECURE-COOKIE-CONFIG") return true;
            }
            if (control.id === "CASA.1.1") { // Input/Config/Auth Validation
                if (f.id === "MISSING-SECURITY-HEADERS") return true;
                if (f.id === "ADMIN-NO-MFA-DETECTED") return true;
                if (f.id === "SESSION-NO-TIMEOUT") return true;
                if (f.id === "DOCKER-RUNNING-AS-ROOT") return true;
                if (f.id === "DOCKER-TAG-LATEST") return true;
                if (f.id === "GHA-MISSING-PERMISSIONS") return true;
                if (f.id === "GHA-MISSING-PERMISSIONS") return true;
                // DAST Mappings
                if (f.id === "DAST-MISSING-CSP") return true;
                if (f.id === "DAST-MISSING-XFRAME") return true;
                if (f.id === "DAST-MISSING-NOSNIFF") return true;
                if (f.id === "DAST-COOKIE-NO-HTTPONLY") return true;
                if (f.id === "DAST-COOKIE-NO-SAMESITE") return true;
            }
            if (control.id === "CASA.2.1") { // Data Protection
                // ... existing static mappings (id="SENSITIVE-LOG-DETECTED" etc handled by catch-all above if I merge logs, but here I append DAST)
                if (f.id === "DAST-MISSING-HSTS") return true;
                if (f.id === "DAST-COOKIE-NO-SECURE") return true;
            }
            if (control.id === "CASA.3.1") { // Secrets
                if (f.id === "DAST-SENSITIVE-FILE") return true;
            }

            return false;
        });

        // Filter out INFO findings - they should be warnings, not failures
        const blockingViolations = violations.filter(item => {
            const f = isGroup(item) ? item.findings[0] : item;
            return f.severity !== "INFO";
        });

        const isPass = blockingViolations.length === 0;
        if (isPass) passedControls++;

        lines.push(`\n### ${isPass ? "✅" : "❌"} [${control.id}] ${control.name}`);
        lines.push(`> ${control.description}`);

        // B. Manual Checks Hint
        if (control.manualCheck) {
            lines.push(`\n**👮 Manual Verification Required**: ${control.manualCheck}`);
        }


        if (isPass) {
            lines.push(`\n*Status: Compliant (No automated violations found)*`);
        } else {
            // Calculated total count for this control
            let controlViolationCount = 0;
            violations.forEach(v => {
                if (isGroup(v)) controlViolationCount += v.findings.length;
                else controlViolationCount += 1;
            });
            lines.push(`\n**Status: Non-Compliant** - ${controlViolationCount} Violation(s) Found`);

            lines.push(`\n#### 🔍 Detailed Findings & Remediation`);

            // Iterate items directly (they are already grouped by Intelligence Engine if present, or raw if not)
            violations.forEach(item => {
                const isGroupItem = isGroup(item);
                const findings = isGroupItem ? item.findings : [item as Finding];
                const representative = findings[0];
                const title = isGroupItem ? item.title : representative.title;
                const description = isGroupItem ? item.description : representative.description;
                const severity = isGroupItem ? item.severity : representative.severity;
                const remediationText = isGroupItem ? item.remediation : representative.remediation?.description;

                lines.push(`\n**${severity}**: ${title}`);
                lines.push(`> **Issue**: ${description}`);

                // Add specific remediation advice based on the finding type
                let remediation = remediationText || "Investigate the code/configuration.";

                // Fallback heuristics if no specific remediation from engine
                if (!remediation || remediation === "Investigate the code/configuration.") {
                    if (representative.category === 'DEPENDENCY') {
                        remediation = `Upgrade the package **${representative.metadata?.pkgName || 'identified'}** to a secure version (Fixed in: ${representative.metadata?.fixedVersion || 'latest'}). Run \`npm update\` or \`trivy\` to verify.`;
                    } else if (representative.id.includes("path-traversal")) {
                        remediation = "Use secure path resolution methods like `path.resolve()` with a safe base directory check. Avoid direct concatenation of user input with file paths.";
                    }
                    // ... (keep existing heuristics as fallbacks) ...
                }

                lines.push(`> **🛠️ Recommendation**: ${remediation}`);

                lines.push(`\n| Location | Line |`);
                lines.push(`| :--- | :--- |`);
                // Limit to first 5 locations to avoid spamming the report
                findings.slice(0, 5).forEach(f => {
                    const relPath = f.location.path.split('/').pop() || f.location.path; // Show filename only for brevity
                    lines.push(`| \`${relPath}\` | ${f.location.startLine || 0} |`);
                });
                if (findings.length > 5) {
                    lines.push(`| *...and ${findings.length - 5} more instances* | |`);
                }
            });
        }
    }

    // 3. Scorecard
    const score = Math.round((passedControls / profile.controls.length) * 100);
    lines.push(`\n---\n## Audit Scorecard`);
    lines.push(`\n### Compliance Score: ${score}%`);
    lines.push(score === 100 ? "🎉 **READY FOR CERTIFICATION**" : "⚠️ **REMEDIATION REQUIRED**");

    // 4. Detailed Appendix
    lines.push(`\n---\n## Appendix: Raw Findings`);
    lines.push(`Total Findings Scanned: ${items.length} (Grouped)`);

    // Write to file
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(outputPath, lines.join("\n"), "utf-8");

    return { path: outputPath };
}

export async function generateCasaReport(findings: (Finding | FindingGroup)[], outputPath: string, profileId: string = "CASA-Tier-2", format?: ReportFormat): Promise<{ path: string }> {
    const profile = resolveProfile(profileId);
    const outputFormat = resolveReportFormat(outputPath, format);

    if (outputFormat === "sarif") {
        return generateSarifReport(findings, outputPath);
    }

    return generateMarkdownReport(findings, outputPath, profile);
}
