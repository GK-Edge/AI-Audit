import * as fs from "fs/promises";
import * as path from "path";
import { Finding, ScanResult } from "@ai-auditor/shared-types";
import { exec } from "child_process";
import * as util from "util";

const execAsync = util.promisify(exec);

export async function runEvidenceScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
        // 1. Documentation Evidence Check
        const requiredDocs = ["PRIVACY.md", "SECURITY.md", "ARCHITECTURE.md", "TERMS.md"];
        const files = await fs.readdir(targetPath);

        // Normalize for case-insensitive check
        const lowerFiles = files.map(f => f.toLowerCase());

        for (const doc of requiredDocs) {
            const hasDoc = lowerFiles.some(f => f.includes(doc.split('.')[0].toLowerCase()));
            if (!hasDoc) {
                findings.push({
                    id: `MISSING-DOC-${doc}`,
                    tool: "evidence-scanner",
                    title: `Missing Required Documentation: ${doc}`,
                    description: `CASA Requirement 7 requires ${doc} or equivalent to be present in the root.`,
                    severity: "MEDIUM",
                    category: "INFRASTRUCTURE",
                    location: {
                        path: targetPath,
                        startLine: 0
                    },
                    cweId: [], // Infrastructure issue
                    metadata: { missingFile: doc }
                });
            }
        }

        // 2. OAuth Scope Scan (Regex in Code)
        try {
            // Grep returns exit code 1 if nothing found, which throws in execAsync.
            // We handle this catch block.
            const grepCommand = `grep -r "googleapis.com/auth" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git`;
            const { stdout } = await execAsync(grepCommand, { maxBuffer: 10 * 1024 * 1024 });

            const scopeLines = stdout.split('\n').filter(Boolean);
            if (scopeLines.length > 0) {
                // Info finding listing all found scopes
                const uniqueScopes = [...new Set(scopeLines.map(line => {
                    const match = line.match(/https:\/\/www\.googleapis\.com\/auth\/[\w.-]+/);
                    return match ? match[0] : null;
                }).filter((s): s is string => s !== null))]; // Type guard

                if (uniqueScopes.length > 0) {
                    findings.push({
                        id: "OAUTH-SCOPES-DETECTED",
                        tool: "evidence-scanner",
                        title: "OAuth Scopes Detected",
                        description: `The following Google OAuth scopes were found in code: ${uniqueScopes.join(", ")}. Ensure these are minimum privilege.`,
                        severity: "INFO",
                        category: "SAST",
                        location: { path: targetPath },
                        cweId: [],
                        metadata: { scopes: uniqueScopes }
                    });


                    // Check for restricted scopes
                    const restricted = uniqueScopes.filter(s => {
                        const sensitive = ["mail.google.com", "gmail", "calendar", "contacts", "admin", "drive", "cloud-platform"];
                        const isReadOnly = s.includes("readonly");
                        return sensitive.some(k => s.includes(k)) && !isReadOnly;
                    });
                    if (restricted.length > 0) {
                        findings.push({
                            id: "RESTRICTED-SCOPE-WARNING",
                            tool: "evidence-scanner",
                            title: "Restricted OAuth Scope Usage",
                            description: `Detected usage of restricted/sensitive scopes: ${restricted.join(", ")}. This triggers a Tier 2/3 CASA assessment level.`,
                            severity: "HIGH",
                            category: "SAST",
                            location: { path: targetPath },
                            cweId: [], // Maps to CASA.5.1 Policy
                            metadata: { restrictedScopes: restricted }
                        });
                    }
                }
            }
        } catch (e: any) {
            // Grep exit code 1 means no lines found - this is NOT an error for us
            if (e.code !== 1) {
                console.warn("Evidence Scanner: Grep failed for scopes", e.message);
            }
        }

        // 3. Data Retention Logic Check
        try {
            const retentionKeywords = ["deleteUser", "retentionPolicy", "purgeData", "GDPR", "hardDelete"];
            // Simple check: do ANY of these exist?
            let hasRetentionLogic = false;
            for (const kw of retentionKeywords) {
                try {
                    const grepCmd = `grep -r "${kw}" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git -m 1`;
                    const { stdout } = await execAsync(grepCmd);
                    if (stdout.trim().length > 0) {
                        hasRetentionLogic = true;
                        break;
                    }
                } catch (ignore) {
                    // Grep code 1 = not found, try next keyword
                }
            }

            if (!hasRetentionLogic) {
                findings.push({
                    id: "NO-RETENTION-LOGIC",
                    tool: "evidence-scanner",
                    title: "Missing Data Retention/Deletion Logic",
                    description: "No code references found for 'deleteUser', 'purge', or 'retention'. CASA Requirement 6 mandates automated data deletion capabilities.",
                    severity: "HIGH",
                    category: "SAST",
                    location: { path: targetPath },
                    cweId: [],
                    metadata: { keywordsChecked: retentionKeywords }
                });
            }

        } catch (e: any) {
            console.warn("Evidence Scanner: General error in retention check", e);
        }

        // 4. Sensitive Logs Check (ASVS V7 / V9)
        try {
            const sensitiveKeywords = ["password", "token", "secret", "api_key", "bearer"];
            const logPatterns = sensitiveKeywords.map(k => `console.log.*${k}`);
            // Simple check: do ANY of these exist?
            for (const pattern of logPatterns) {
                try {
                    // -i for case insensitive
                    const grepCmd = `grep -r -i "${pattern}" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist -m 5`;
                    const { stdout } = await execAsync(grepCmd);

                    if (stdout.trim().length > 0) {
                        // Parse the lines to create findings
                        const lines = stdout.split('\n').filter(Boolean);
                        lines.forEach(line => {
                            // Try to extract filename if grep didn't give it cleanly (grep -r usually gives file:line)
                            const parts = line.split(':');
                            const file = parts[0] || targetPath;

                            findings.push({
                                id: "SENSITIVE-LOG-DETECTED",
                                tool: "evidence-scanner",
                                title: "Potential Sensitive Data in Logs",
                                description: `Detected logging statement containing sensitive keyword: '${pattern}'. Ensure secrets are not written to stdout/logs.`,
                                severity: "MEDIUM",
                                category: "SAST",
                                location: { path: file },
                                cweId: ["CWE-532"], // Insertion of Sensitive Information into Log File
                                metadata: { pattern }
                            });
                        });
                        // Break after first keyword match to avoid spamming thousands of findings
                        break;
                    }
                } catch (ignore) {
                    // Grep code 1 = not found
                }
            }
        } catch (e: any) {
            console.warn("Evidence Scanner: General error in log check", e);
        }


        // 5. AppSec Hardening Check (ASVS V14 / V3)
        try {
            // A. Security Headers
            const headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"];
            let foundHeaders = 0;
            for (const header of headers) {
                try {
                    const grepCmd = `grep -r -i "${header}" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist -m 1`;
                    const { stdout } = await execAsync(grepCmd);
                    if (stdout.trim().length > 0) foundHeaders++;
                } catch (ignore) { }
            }

            if (foundHeaders === 0) {
                findings.push({
                    id: "MISSING-SECURITY-HEADERS",
                    tool: "evidence-scanner",
                    title: "Missing Security Headers",
                    description: "No evidence of security headers (CSP, HSTS, etc.) found in code. CASA/ASVS requires hardening headers.",
                    severity: "MEDIUM",
                    category: "INFRASTRUCTURE",
                    location: { path: targetPath },
                    cweId: ["CWE-693"],
                    metadata: { checked: headers }
                });
            }

            // B. Secure Cookie Check
            try {
                // Look for 'cookie' setting but missing 'secure' or 'httpOnly'
                const cookieCmd = `grep -r -i "cookie" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist | grep -v "secure" | grep -v "HttpOnly"`;
                // This is a naive heuristic; might be noisy, so we set severity to LOW/INFO
                // Actually, better to just check if 'secure: true' appears ANYWHERE near 'cookie' to give benefit of doubt
                const secureCookieCmd = `grep -r -i "secure.*true" "${targetPath}" --exclude-dir=node_modules --exclude-dir=.git`;
                const { stdout } = await execAsync(secureCookieCmd);
                if (stdout.trim().length === 0) {
                    findings.push({
                        id: "INSECURE-COOKIE-CONFIG",
                        tool: "evidence-scanner",
                        title: "Potential Insecure Cookie Config",
                        description: "Could not find 'secure: true' configuration for cookies. Ensure cookies have Secure, HttpOnly, and SameSite attributes.",
                        severity: "LOW",
                        category: "SAST",
                        location: { path: targetPath },
                        cweId: ["CWE-614"]
                    });
                }
            } catch (ignore) { }

            // C. VDP (security.txt)
            const vdpCheck = await fs.readdir(targetPath).catch(() => [] as string[]);
            // Also check .well-known if it exists
            let hasVdp = false;
            try {
                const wellKnown = await fs.readdir(path.join(targetPath, ".well-known")).catch(() => [] as string[]);
                if (wellKnown.includes("security.txt")) hasVdp = true;
            } catch (e) { }


            if (!hasVdp) {
                findings.push({
                    id: "MISSING-VDP-SECURITY-TXT",
                    tool: "evidence-scanner",
                    title: "Missing Vulnerability Disclosure Policy (security.txt)",
                    description: "No security.txt found in root or .well-known/. CASA highly recommends a VDP for researchers to report issues.",
                    severity: "LOW",
                    category: "INFRASTRUCTURE",
                    location: { path: targetPath },
                    cweId: [],
                    metadata: { missing: "security.txt" }
                });
            }

        } catch (e: any) {
            console.warn("Evidence Scanner: General error in hardening check", e);
        }

        // 6. Auth & Session Heuristics (ASVS V2 / V3)
        try {
            // A. Admin without MFA hint
            // Look for "admin" routes or controllers
            const adminCmd = `grep -r -i "admin" "${targetPath}" --include="*routes.ts" --include="*controller.ts" --include="*.js" --exclude-dir=node_modules -m 1`;
            const { stdout: adminOut } = await execAsync(adminCmd).catch(() => ({ stdout: "" }));

            if (adminOut.trim().length > 0) {
                // Admin exists, check for MFA/2FA keywords
                const mfaCmd = `grep -r -i -E "mfa|2fa|totp|two-factor" "${targetPath}" --exclude-dir=node_modules -m 1`;
                const { stdout: mfaOut } = await execAsync(mfaCmd).catch(() => ({ stdout: "" }));

                if (mfaOut.trim().length === 0) {
                    findings.push({
                        id: "ADMIN-NO-MFA-DETECTED",
                        tool: "evidence-scanner",
                        title: "Potential Admin Interface without MFA",
                        description: "Deep scan detected 'admin' routes but no references to MFA/2FA/TOTP. CASA Tier 2 requires MFA for administrative access.",
                        severity: "HIGH",
                        category: "SAST",
                        location: { path: targetPath },
                        cweId: ["CWE-308"], // Weak Password Recovery Mechanism for Password Authentication (Close enough)
                        metadata: { heuristic: "admin found, mfa missing" }
                    });
                }
            }

            // B. Session Timeout
            const sessionCmd = `grep -r "express-session" "${targetPath}" --exclude-dir=node_modules -m 1`;
            const { stdout: sessionOut } = await execAsync(sessionCmd).catch(() => ({ stdout: "" }));
            if (sessionOut.trim().length > 0) {
                // Check for "maxAge" or "ttl"
                const timeoutCmd = `grep -r -E "maxAge|ttl|expires" "${targetPath}" --exclude-dir=node_modules -C 3`;
                const { stdout: timeoutOut } = await execAsync(timeoutCmd).catch(() => ({ stdout: "" }));

                if (timeoutOut.trim().length === 0) {
                    findings.push({
                        id: "SESSION-NO-TIMEOUT",
                        tool: "evidence-scanner",
                        title: "Missing Session Timeout Configuration",
                        description: "Detected session middleware usage but no 'maxAge' or 'expires' settings found. Sessions must have absolute timeouts.",
                        severity: "MEDIUM",
                        category: "SAST",
                        location: { path: targetPath },
                        cweId: ["CWE-613"]
                    });
                }
            }

        } catch (e: any) {
            console.warn("Evidence Scanner: General error in auth check", e);
        }

        return {
            tool: "evidence-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetPath,
            success: true
        };

    } catch (error: any) {
        return {
            tool: "evidence-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetPath,
            success: false,
            error: error.message
        };
    }
}
