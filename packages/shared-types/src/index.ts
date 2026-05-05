export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory = 'SAST' | 'DAST' | 'DEPENDENCY' | 'INFRASTRUCTURE' | 'SECRET';

export interface Location {
    path: string;
    startLine?: number;
    endLine?: number;
    startCol?: number;
    endCol?: number;
}

export interface Remediation {
    description: string;
    codeFix?: string; // Diff or replacement code
}

export interface RegulationMapping {
    standard: 'CASA' | 'ASVS' | 'SOC2' | 'ISO27001';
    controlId: string; // e.g., "CASA.3.1", "ASVS.2.1.1"
    description?: string;
}

export interface Finding {
    id: string;
    tool: string; // e.g., "semgrep", "trivy"
    title: string;
    description: string;
    severity: Severity;
    category: FindingCategory;
    location: Location;
    cweId?: string[]; // e.g., ["CWE-79"]
    remediation?: Remediation;
    mappings?: RegulationMapping[];
    metadata?: Record<string, any>; // Raw tool output or extra context
    suppressed?: boolean;
    mitigationReason?: string;
}

export interface ScanResult {
    tool: string;
    timestamp: string;
    durationMs: number;
    findings: Finding[];
    scanPath: string;
    success: boolean;
    error?: string;
}

export interface ScanExecutionSummary {
    tool: string;
    success: boolean;
    findingsCount: number;
    durationMs: number;
    error?: string;
    skipped?: boolean;
    warnings?: string[];
}

export interface FindingGroup {
    id: string;              // generic-id (e.g., "input-validation-error")
    title: string;           // "Input Validation Error"
    description: string;     // Generic description
    severity: Severity;      // Highest severity in group
    findings: Finding[];     // The raw findings
    riskScore: number;       // 0-100 calculated score
    remediation?: string;    // AI-suggested fix
    tools?: string[];
    categories?: FindingCategory[];
    cweId?: string[];
    mappings?: RegulationMapping[];
}

export interface AuditPlan {
    targetPath: string;
    standards: string[]; // ["CASA-Tier-2"]
    tools: string[]; // ["semgrep", "trivy"]
}

// --- Deep Audit Extensions ---

// --- Deep Audit Extensions ---

export interface AuditControl {
    id: string; // e.g. "CASA.1.1", "CISSP.8.1"
    name: string;
    description: string;
    severity: Severity;
    relatedCwes?: string[]; // CWEs that automatically trigger this control
    manualCheck?: string; // "Check for PR templates in root"
}

export interface AuditProfile {
    id: string;
    name: string;
    description: string;
    controls: AuditControl[];
}

export const CASA_PROFILE: AuditProfile = {
    id: "CASA-Tier-2",
    name: "CASA Tier 2 (App Defense Alliance)",
    description: "Focuses on OWASP ASVS Level 2 requirements, OAuth scopes, and data protection.",
    controls: [
        {
            id: "CASA.1.1",
            name: "Input Validation (ASVS V5)",
            description: "Prevent injection attacks via strict input validation.",
            severity: "CRITICAL",
            relatedCwes: ["CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-20", "CWE-77", "CWE-94"]
        },
        {
            id: "CASA.2.1",
            name: "Data Protection (ASVS V6)",
            description: "Encrypt sensitive data in transit and at rest.",
            severity: "HIGH",
            relatedCwes: ["CWE-319", "CWE-295", "CWE-312", "CWE-327", "CWE-326"]
        },
        {
            id: "CASA.3.1",
            name: "Secrets Management (ASVS V2)",
            description: "No hardcoded secrets in source code.",
            severity: "CRITICAL",
            relatedCwes: ["CWE-798", "CWE-259"]
        },
        {
            id: "CASA.4.1",
            name: "Dependency Safety (ASVS V14)",
            description: "No known CVEs in third-party libraries.",
            severity: "HIGH",
            relatedCwes: ["CWE-1395"]
        },
        {
            id: "CASA.5.1",
            name: "OAuth Scope Review (Requirement 1)",
            description: "Ensure requested scopes are least-privilege.",
            severity: "CRITICAL",
            manualCheck: "Verify that 'https://mail.google.com/' or 'drive' are not used if read-only suffices."
        },
        {
            id: "CASA.6.1",
            name: "Privacy & Data Retention (Requirement 6)",
            description: "Evidence of data deletion logic and privacy policies.",
            severity: "HIGH",
            manualCheck: "Check for 'deleteUser' logic and PRIVACY.md."
        },
        {
            id: "CASA.7.1",
            name: "Documentation & Architecture (Requirement 7)",
            description: "Required security documentation must exist.",
            severity: "MEDIUM",
            manualCheck: "Check for SECURITY.md, ARCHITECTURE.md, and diagrams."
        }
    ]
};

export const CISSP_PROFILE: AuditProfile = {
    id: "CISSP-Domain-8",
    name: "CISSP Domain 8 (Software Development Security)",
    description: "Focuses on SDLC security, privacy by design, and resilience.",
    controls: [
        {
            id: "CISSP.8.1",
            name: "Secure SDLC Artifacts",
            description: "Evidence of security testing integration (linters, tests).",
            severity: "MEDIUM",
            manualCheck: "Check for .eslintrc, .pylintrc, and test/ directories."
        },
        {
            id: "CISSP.8.2",
            name: "Input/Output Controls",
            description: "Controls to prevent injection and ensure data integrity.",
            severity: "HIGH",
            relatedCwes: ["CWE-20", "CWE-116"] // Improper validation/encoding
        },
        {
            id: "CISSP.8.3",
            name: "Privacy by Design",
            description: "Minimization of PII and sensitive data exposure.",
            severity: "HIGH",
            relatedCwes: ["CWE-359"] // Privacy Violation
        }
    ]
};

export const SOC2_PROFILE: AuditProfile = {
    id: "SOC2-CC",
    name: "SOC 2 (Common Criteria)",
    description: "Focuses on Change Management (CC8) and Logical Access (CC6).",
    controls: [
        {
            id: "SOC2.CC8.1",
            name: "Change Management - Version Control",
            description: "Software changes must be tracked in a specialized system.",
            severity: "HIGH",
            manualCheck: "Verify .git directory exists."
        },
        {
            id: "SOC2.CC8.2",
            name: "Change Management - Pull Requests",
            description: "Changes must be reviewed before merging.",
            severity: "HIGH",
            manualCheck: "Check for PULL_REQUEST_TEMPLATE.md or .github/workflows/pr.yml"
        },
        {
            id: "SOC2.CC6.1",
            name: "Logical Access - Least Privilege",
            description: "Access to source code and secrets is restricted.",
            severity: "CRITICAL",
            relatedCwes: ["CWE-269", "CWE-732"]
        }
    ]
};

// Reasoning Engine Types
export interface AnalysisResult {
    findingId: string;
    verdict: 'CONFIRMED' | 'FALSE_POSITIVE' | 'LOW_RISK_CONTEXT' | 'NEEDS_MANUAL_REVIEW';
    reason: string;
    confidence: number; // 0.0 to 1.0
}
