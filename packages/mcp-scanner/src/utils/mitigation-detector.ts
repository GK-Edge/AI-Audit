
import { Finding } from '@ai-auditor/shared-types';
import fs from 'fs/promises';
import path from 'path';

/**
 * Intelligent Mitigation Detector
 * 
 * Analyze the code context around findings to detect if they are already mitigated
 * by known safe patterns (sanitization, validation, configuration).
 */
export class MitigationDetector {
    private readonly CONTEXT_LINES = 10;

    /**
     * Analyze a list of findings and mark mitigated ones as suppressed
     */
    async processFindings(findings: Finding[], baseDir: string): Promise<Finding[]> {
        const processedFindings: Finding[] = [];

        // Group by file to minimize file reads
        const findingsByFile = this.groupByFile(findings);

        for (const [relPath, fileFindings] of Object.entries(findingsByFile)) {
            try {
                // Resolve absolute path
                const absolutePath = path.resolve(baseDir, relPath);

                // Skip if file doesn't exist or isn't accessible
                const content = await fs.readFile(absolutePath, 'utf-8');
                const lines = content.split('\n');

                for (const finding of fileFindings) {
                    const result = await this.checkMitigation(finding, lines, content);
                    processedFindings.push(result);
                }
            } catch (error) {
                // If file read fails, just return original findings
                // console.warn(`[MitigationDetector] Failed to read file ${relPath}: ${error}`);
                processedFindings.push(...fileFindings);
            }
        }

        return processedFindings;
    }

    private groupByFile(findings: Finding[]): Record<string, Finding[]> {
        return findings.reduce((acc, finding) => {
            const path = finding.location.path;
            if (!acc[path]) acc[path] = [];
            acc[path].push(finding);
            return acc;
        }, {} as Record<string, Finding[]>);
    }

    private async checkMitigation(finding: Finding, lines: string[], fullContent: string): Promise<Finding> {
        // Clone finding to avoid mutation side effects
        const result = { ...finding };
        const startLine = (finding.location.startLine || 1) - 1; // 0-indexed

        // Get context window (+/- N lines)
        const contextStart = Math.max(0, startLine - this.CONTEXT_LINES);
        const contextEnd = Math.min(lines.length, startLine + this.CONTEXT_LINES);
        const contextLines = lines.slice(contextStart, contextEnd).join('\n');

        // Strategy based on finding type/description
        const description = finding.description.toLowerCase();
        const title = finding.title.toLowerCase();

        // 1. Check for XSS Mitigations
        if (title.includes('xss') || description.includes('innerhtml') || description.includes('dangerouslysetinnerhtml')) {
            if (this.isXssMitigated(contextLines)) {
                result.suppressed = true;
                result.mitigationReason = 'Protected by sanitizer (DOMPurify/escapeHtml)';
            }
        }

        // 2. Check for Path Traversal Mitigations
        if (title.includes('path traversal') || description.includes('path.join') || description.includes('path.resolve')) {
            if (this.isPathTraversalMitigated(contextLines, lines[startLine])) {
                result.suppressed = true;
                result.mitigationReason = 'Path validated with startsWith() check';
            }
        }

        // 3. Check for Command Injection Mitigations
        if (title.includes('command injection') || description.includes('spawn') || description.includes('exec')) {
            // Special case: If description explicitly warns about shell: true, DON'T suppress
            if (result.description.includes('DANGER: spawn with shell: true')) {
                return result;
            }

            if (this.isCommandInjectionMitigated(contextLines)) {
                result.suppressed = true;
                result.mitigationReason = 'Command execution configured with shell: false';
            }
        }

        return result;
    }

    /**
     * Detects DOMPurify, escapeHtml, or other sanitizers
     */
    private isXssMitigated(context: string): boolean {
        const patterns = [
            /DOMPurify\.sanitize\s*\(/,
            /escapeHtml\s*\(/,
            /htmlEscape\s*\(/,
            /sanitize\s*\(/,
            /sanitizeHtml\s*\(/
        ];
        return patterns.some(p => p.test(context));
    }

    /**
     * Detects startsWith checks for path validation
     */
    private isPathTraversalMitigated(context: string, line: string): boolean {
        // Simple heuristic: Looking for .startsWith() check nearby
        // A more robust check would analyze control flow, but this is a tier-1 heuristic
        return context.includes('.startsWith(');
    }

    /**
     * Detects shell: false configuration
     */
    private isCommandInjectionMitigated(context: string): boolean {
        // Look for shell: false in the options object passed to spawn/exec
        return /shell\s*:\s*false/.test(context);
    }
}
