import { Finding } from "@ai-auditor/shared-types";

export class Normalizer {
    /**
     * Map of raw tool IDs to readable titles.
     * This is a "living knowledge base" that grows as we encounter more rule IDs.
     */
    private static ID_TITLE_MAP: Record<string, string> = {
        // Semgrep - JavaScript/TypeScript
        "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal": "Path Traversal Risk",
        "javascript.browser.security.insecure-document-method.insecure-document-method": "Potential XSS via DOM Sink",
        "javascript.lang.security.audit.spawn-shell-true.spawn-shell-true": "Command Injection Risk (Shell Spawn)",
        "javascript.lang.security.detect-child-process.detect-child-process": "Unsafe Child Process Execution",
        "javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal": "Express Path Traversal",
        "javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag": "Potential XSS (Unknown Script Tag)",
        "javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket": "Insecure WebSocket (Use WSS)",

        // Semgrep - Python
        "python.lang.security.unverified-ssl-context.unverified-ssl-context": "Unverified SSL Context",

        // Custom Rules
        "detect-plaintext-token-storage": "Plaintext Token Storage",
        "detect-token-leak-to-external-api": "Token Leak to 3rd Party API"
    };

    /**
     * Main entry point to normalize a list of raw findings.
     */
    public normalize(findings: Finding[]): Finding[] {
        return findings.map(f => this.normalizeSingle(f));
    }

    private normalizeSingle(finding: Finding): Finding {
        // 1. Normalize Title
        // If we have a mapped title, use it. Otherwise, clean up the raw ID if it's messy.
        let title = finding.title;
        // Check exact match first
        if (Normalizer.ID_TITLE_MAP[finding.title]) {
            title = Normalizer.ID_TITLE_MAP[finding.title];
        }
        // Some Semgrep rules are like "rules.detect-something" or "javascript.express..."
        // If title looks like a long dot-notation ID (has dots, NO spaces), try to make it readable
        else if (title.includes(".") && !title.includes(" ") && title.length > 30) {
            const parts = title.split(".");
            // Take the last part, replace hyphens with spaces, capitalize
            const lastPart = parts[parts.length - 1];
            title = this.toTitleCase(lastPart.replace(/-/g, " "));
        }

        // 2. Normalize Description (truncate if massive)
        let description = finding.description;
        if (description.length > 1000) {
            description = description.substring(0, 997) + "...";
        }

        return {
            ...finding,
            title,
            description
        };
    }

    private toTitleCase(str: string): string {
        return str.replace(
            /\w\S*/g,
            text => text.charAt(0).toUpperCase() + text.substring(1).toLowerCase()
        );
    }
}
