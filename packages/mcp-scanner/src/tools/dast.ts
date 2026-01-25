
import axios from 'axios';
import { Finding, ScanResult } from "@ai-auditor/shared-types";

interface DastCheck {
    id: string;
    title: string;
    check: (url: string, headers: any, body: string, status: number) => Promise<Finding | null>;
}

export async function runDastScan(targetUrl: string, authToken?: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    // Normalize URL
    if (!targetUrl.startsWith('http')) {
        targetUrl = 'http://' + targetUrl; // Default to http for local dev
    }

    try {
        // Main Request
        const requestConfig: any = {
            validateStatus: () => true, // resolve promise for all status codes
            timeout: 5000,
            headers: {}
        };

        if (authToken) {
            requestConfig.headers['Authorization'] = `Bearer ${authToken}`;
        }

        const response = await axios.get(targetUrl, requestConfig);

        const { headers, data, status } = response;
        const bodyStr = typeof data === 'string' ? data : JSON.stringify(data);

        // --- HTTP HEADERS CHECKS ---

        // 1. Missing HSTS (Strict-Transport-Security)
        if (!headers['strict-transport-security'] && targetUrl.startsWith('https')) {
            findings.push({
                id: "DAST-MISSING-HSTS",
                tool: "dast-scanner",
                title: "Missing HSTS Header",
                description: "The 'Strict-Transport-Security' header is missing. This exposes users to MITM attacks by allowing cleartext HTTP connections.",
                severity: "HIGH",
                category: "DAST",
                location: { path: targetUrl },
                cweId: ["CWE-523"],
                metadata: { header: "Strict-Transport-Security" }
            });
        }

        // 2. Missing/Weak CSP (Content-Security-Policy)
        if (!headers['content-security-policy']) {
            findings.push({
                id: "DAST-MISSING-CSP",
                tool: "dast-scanner",
                title: "Missing Content Security Policy (CSP)",
                description: "No CSP header found. This increases susceptibility to XSS and data injection attacks.",
                severity: "MEDIUM",
                category: "DAST",
                location: { path: targetUrl },
                cweId: ["CWE-1021"],
                metadata: { header: "Content-Security-Policy" }
            });
        }

        // 3. Missing X-Frame-Options (Clickjacking)
        if (!headers['x-frame-options']) {
            findings.push({
                id: "DAST-MISSING-XFRAME",
                tool: "dast-scanner",
                title: "Missing X-Frame-Options",
                description: "The 'X-Frame-Options' header is missing, making the site vulnerable to Clickjacking attacks.",
                severity: "MEDIUM",
                category: "DAST",
                location: { path: targetUrl },
                cweId: ["CWE-1021"],
                metadata: { header: "X-Frame-Options" }
            });
        }

        // 4. Missing X-Content-Type-Options
        if (!headers['x-content-type-options'] || headers['x-content-type-options'] !== 'nosniff') {
            findings.push({
                id: "DAST-MISSING-NOSNIFF",
                tool: "dast-scanner",
                title: "Missing X-Content-Type-Options",
                description: "The 'X-Content-Type-Options: nosniff' header is missing. Browsers may MIME-sniff the response, leading to XSS.",
                severity: "LOW",
                category: "DAST",
                location: { path: targetUrl },
                cweId: ["CWE-116"],
                metadata: { header: "X-Content-Type-Options" }
            });
        }

        // --- COOKIE CHECKS ---

        const setCookie = headers['set-cookie'];
        if (setCookie && Array.isArray(setCookie)) {
            for (const cookie of setCookie) {
                const lowerCookie = cookie.toLowerCase();
                const name = cookie.split('=')[0];

                if (!lowerCookie.includes('httponly')) {
                    findings.push({
                        id: "DAST-COOKIE-NO-HTTPONLY",
                        tool: "dast-scanner",
                        title: `Cookie '${name}' missing HttpOnly`,
                        description: `The cookie '${name}' does not have the HttpOnly flag. It can be accessed by JavaScript, increasing XSS impact.`,
                        severity: "MEDIUM",
                        category: "DAST",
                        location: { path: targetUrl },
                        cweId: ["CWE-1004"],
                        metadata: { cookie: name }
                    });
                }

                if (!lowerCookie.includes('secure') && targetUrl.startsWith('https')) {
                    findings.push({
                        id: "DAST-COOKIE-NO-SECURE",
                        tool: "dast-scanner",
                        title: `Cookie '${name}' missing Secure flag`,
                        description: `The cookie '${name}' is not marked Secure. It could be transmitted over unencrypted HTTP.`,
                        severity: "MEDIUM",
                        category: "DAST",
                        location: { path: targetUrl },
                        cweId: ["CWE-614"],
                        metadata: { cookie: name }
                    });
                }

                if (!lowerCookie.includes('samesite')) {
                    findings.push({
                        id: "DAST-COOKIE-NO-SAMESITE",
                        tool: "dast-scanner",
                        title: `Cookie '${name}' missing SameSite`,
                        description: `The cookie '${name}' does not specify SameSite attribute. This may increase CSRF risk.`,
                        severity: "LOW",
                        category: "DAST",
                        location: { path: targetUrl },
                        cweId: ["CWE-1275"],
                        metadata: { cookie: name }
                    });
                }
            }
        }

        // --- SENSITIVE FILE ENUMERATION ---

        const sensitiveFiles = [
            '/.env',
            '/.git/HEAD',
            '/.vscode/settings.json',
            '/package.json',
            '/server.js',
            '/app.js'
        ];

        for (const file of sensitiveFiles) {
            try {
                const fileUrl = targetUrl.replace(/\/$/, '') + file;
                const fileRes = await axios.get(fileUrl, {
                    validateStatus: () => true,
                    timeout: 2000
                });

                if (fileRes.status === 200) {
                    // Verify it's not a soft 404 (e.g. checks if it returns the same HTML as homepage)
                    // Simple heuristic: if length is small or content-type is text/plain or application/json
                    const cType = fileRes.headers['content-type'] || '';
                    const isHtml = cType.includes('text/html');

                    // If we asked for .env and got HTML, it's likely a redirect/Soft 404
                    // If we asked for .env and got "DB_HOST=...", it's a finding.

                    const probableLeak = !isHtml || (fileRes.data && (fileRes.data.toString().includes('DB_') || fileRes.data.toString().includes('ref: refs/')));

                    if (probableLeak) {
                        findings.push({
                            id: "DAST-SENSITIVE-FILE",
                            tool: "dast-scanner",
                            title: `Sensitive File Exposed: ${file}`,
                            description: `The file '${file}' is accessible via HTTP. This may expose source code or credentials.`,
                            severity: "CRITICAL",
                            category: "DAST",
                            location: { path: fileUrl },
                            cweId: ["CWE-538"],
                            metadata: { file: file }
                        });
                    }
                }
            } catch (err) {
                // Ignore connection errors for file checking
            }
        }


        return {
            tool: "dast-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetUrl,
            success: true
        };

    } catch (error: any) {
        return {
            tool: "dast-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetUrl,
            success: false,
            error: error.message
        };
    }
}
