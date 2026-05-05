import { Finding, FindingGroup, CASA_PROFILE, CISSP_PROFILE, SOC2_PROFILE, AuditProfile, Severity, AuditControl, ScanExecutionSummary } from "@ai-auditor/shared-types";
import * as fs from "fs/promises";
import * as path from "path";

function isGroup(item: Finding | FindingGroup): item is FindingGroup {
    return (item as FindingGroup).findings !== undefined;
}

type ReportFormat = "markdown" | "sarif";
type ControlStatus = "PASS" | "FAIL" | "MANUAL_REVIEW";

function getFindings(item: Finding | FindingGroup): Finding[] {
    return isGroup(item) ? item.findings : [item];
}

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

async function generateSarifReport(items: (Finding | FindingGroup)[], outputPath: string, scanSummary: ScanExecutionSummary[] = []): Promise<{ path: string }> {
    const rulesMap = new Map<string, { id: string; title: string; description: string; severity: Severity; tool: string; cweId?: string[] }>();

    items.forEach((item) => {
        // Use representative finding for rule metadata
        const f = getFindings(item)[0];
        const ruleId = isGroup(item) ? item.id : f.id;

        if (!rulesMap.has(ruleId)) {
            rulesMap.set(ruleId, {
                id: ruleId,
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
        const findings = getFindings(item);
        const representative = findings[0];
        const isGroupItem = isGroup(item);
        const ruleId = isGroupItem ? item.id : representative.id;

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
            ruleId,
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
                remediation: isGroupItem ? item.remediation : representative.remediation?.description,
                riskScore: isGroupItem ? item.riskScore : representative.metadata?.riskScore,
                scanSummary
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
                results,
                invocations: [
                    {
                        executionSuccessful: scanSummary.every(scan => scan.success || scan.skipped),
                        properties: { scanSummary }
                    }
                ]
            }
        ]
    };

    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(outputPath, JSON.stringify(sarifReport, null, 2), "utf-8");

    return { path: outputPath };
}

function appendScanSummary(lines: string[], scanSummary: ScanExecutionSummary[]): void {
    if (scanSummary.length === 0) return;

    lines.push(`\n## Scan Coverage & Limitations`);
    lines.push(`\n| Tool | Status | Findings | Duration | Notes |`);
    lines.push(`| :--- | :--- | ---: | ---: | :--- |`);

    scanSummary.forEach(scan => {
        const status = scan.skipped ? "Skipped" : scan.success ? "Completed" : "Failed";
        const notes = [...(scan.warnings || []), scan.error].filter(Boolean).join(" ") || "-";
        lines.push(`| ${scan.tool} | ${status} | ${scan.findingsCount} | ${scan.durationMs}ms | ${notes} |`);
    });
}

function findingMatchesControl(f: Finding, control: AuditControl): boolean {
    if (f.mappings?.some(mapping => mapping.controlId === control.id)) return true;

    if (f.cweId && control.relatedCwes) {
        if (f.cweId.some(c => control.relatedCwes!.includes(c))) return true;
    }

    if (control.id === "CASA.4.1" && f.category === "DEPENDENCY") return true;
    if (control.id === "CASA.3.1") {
        if (f.category === "SECRET") return true;
        if (f.id === "DOCKER-SECRETS-IN-ENV") return true;
        if (f.id === "DOT-ENV-FILE-DETECTED") return true;
        if (f.tool === "gitleaks") return true;
        if (f.id === "DAST-SENSITIVE-FILE") return true;
    }

    if (control.id === "CASA.1.1" && f.category === "SAST" && f.severity === "CRITICAL") return true;
    if (control.id === "CASA.5.1" && (f.id === "RESTRICTED-SCOPE-WARNING" || f.id === "OAUTH-SCOPES-DETECTED")) return true;
    if (control.id === "CASA.6.1" && f.id === "NO-RETENTION-LOGIC") return true;
    if (control.id === "CASA.7.1" && (f.id.startsWith("MISSING-DOC-") || f.id === "MISSING-VDP-SECURITY-TXT")) return true;

    if (control.id === "CASA.2.1") {
        if (f.id === "SENSITIVE-LOG-DETECTED") return true;
        if (f.id === "INSECURE-COOKIE-CONFIG") return true;
        if (f.id === "DAST-MISSING-HSTS") return true;
        if (f.id === "DAST-COOKIE-NO-SECURE") return true;
    }

    if (control.id === "CASA.1.1") {
        if (f.id === "MISSING-SECURITY-HEADERS") return true;
        if (f.id === "ADMIN-NO-MFA-DETECTED") return true;
        if (f.id === "SESSION-NO-TIMEOUT") return true;
        if (f.id === "DOCKER-RUNNING-AS-ROOT") return true;
        if (f.id === "DOCKER-TAG-LATEST") return true;
        if (f.id === "GHA-MISSING-PERMISSIONS") return true;
        if (f.id === "DAST-MISSING-CSP") return true;
        if (f.id === "DAST-MISSING-XFRAME") return true;
        if (f.id === "DAST-MISSING-NOSNIFF") return true;
        if (f.id === "DAST-COOKIE-NO-HTTPONLY") return true;
        if (f.id === "DAST-COOKIE-NO-SAMESITE") return true;
    }

    return false;
}

function getControlStatus(hasBlockingViolations: boolean, hasManualCheck: boolean): ControlStatus {
    if (hasBlockingViolations) return "FAIL";
    if (hasManualCheck) return "MANUAL_REVIEW";
    return "PASS";
}

function statusLabel(status: ControlStatus): string {
    switch (status) {
        case "PASS": return "✅ Pass";
        case "FAIL": return "❌ Fail";
        case "MANUAL_REVIEW": return "⚠️ Manual Review";
    }
}

async function generateMarkdownReport(items: (Finding | FindingGroup)[], outputPath: string, profile: AuditProfile, scanSummary: ScanExecutionSummary[] = []): Promise<{ path: string }> {
    const lines: string[] = [];

    // 1. Header
    lines.push(`# ${profile.name} Report`);
    lines.push(`**Date**: ${new Date().toISOString()}`);
    lines.push(`**Description**: ${profile.description}`);
    lines.push(`\n---`);

    appendScanSummary(lines, scanSummary);

    // 2. Control Assessment Logic
    lines.push(`\n## Control Assessment`);

    let passedControls = 0;
    let failedControls = 0;
    let manualReviewControls = 0;

    for (const control of profile.controls) {
        // A. Automatic violations via CWE/Category
        const violations = items.filter(item => {
            return getFindings(item).some(f => findingMatchesControl(f, control));
        });

        // Filter out INFO findings - they should be warnings, not failures
        const blockingViolations = violations.filter(item => {
            return isGroup(item) ? item.severity !== "INFO" : item.severity !== "INFO";
        });

        const status = getControlStatus(blockingViolations.length > 0, Boolean(control.manualCheck));
        if (status === "PASS") passedControls++;
        if (status === "FAIL") failedControls++;
        if (status === "MANUAL_REVIEW") manualReviewControls++;

        lines.push(`\n### ${statusLabel(status)} [${control.id}] ${control.name}`);
        lines.push(`> ${control.description}`);

        // B. Manual Checks Hint
        if (control.manualCheck) {
            lines.push(`\n**👮 Manual Verification Required**: ${control.manualCheck}`);
        }


        if (status === "PASS") {
            lines.push(`\n*Status: Compliant (No automated violations found)*`);
        } else if (status === "MANUAL_REVIEW") {
            lines.push(`\n*Status: Manual review required (No automated violations found)*`);
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
                const findings = getFindings(item);
                const representative = findings[0];
                const title = isGroupItem ? item.title : representative.title;
                const description = isGroupItem ? item.description : representative.description;
                const severity = isGroupItem ? item.severity : representative.severity;
                const remediationText = isGroupItem ? item.remediation : representative.remediation?.description;

                lines.push(`\n**${severity}**: ${title}`);
                if (isGroupItem) {
                    lines.push(`> **Risk Score**: ${item.riskScore}/100 across ${findings.length} instance(s)`);
                }
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
                    lines.push(`| \`${f.location.path}\` | ${f.location.startLine || 0} |`);
                });
                if (findings.length > 5) {
                    lines.push(`| *...and ${findings.length - 5} more instances* | |`);
                }
            });
        }
    }

    // 3. Scorecard
    const automatedScore = Math.round(((profile.controls.length - failedControls) / profile.controls.length) * 100);
    lines.push(`\n---\n## Audit Scorecard`);
    lines.push(`\n### Automated Pass Score: ${automatedScore}%`);
    lines.push(`Passed: ${passedControls} | Failed: ${failedControls} | Manual Review: ${manualReviewControls}`);
    if (failedControls > 0) {
        lines.push("⚠️ **REMEDIATION REQUIRED**");
    } else if (manualReviewControls > 0) {
        lines.push("⚠️ **AUTOMATED CHECKS PASSED, MANUAL EVIDENCE REQUIRED**");
    } else {
        lines.push("🎉 **AUTOMATED CONTROLS PASSED**");
    }

    // 4. Detailed Appendix
    lines.push(`\n---\n## Appendix: Raw Findings`);
    lines.push(`Total Findings Scanned: ${items.length} (Grouped)`);

    // Write to file
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(outputPath, lines.join("\n"), "utf-8");

    return { path: outputPath };
}

export async function generateCasaReport(findings: (Finding | FindingGroup)[], outputPath: string, profileId: string = "CASA-Tier-2", format?: ReportFormat, scanSummary: ScanExecutionSummary[] = []): Promise<{ path: string }> {
    const profile = resolveProfile(profileId);
    const outputFormat = resolveReportFormat(outputPath, format);

    if (outputFormat === "sarif") {
        return generateSarifReport(findings, outputPath, scanSummary);
    }

    return generateMarkdownReport(findings, outputPath, profile, scanSummary);
}
