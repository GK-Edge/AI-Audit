
import * as fs from "fs/promises";
import * as path from "path";
import { Finding, ScanResult } from "@ai-auditor/shared-types";
import { exec } from "child_process";
import * as util from "util";

const execAsync = util.promisify(exec);

export async function runInfraScan(targetPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
        // 1. Dockerfile Analysis (CIS Benchmarks subset)
        try {
            // Find all Dockerfiles
            const findDockerfiles = `find "${targetPath}" -name "*Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*"`;
            const { stdout: dockerFilesOut } = await execAsync(findDockerfiles).catch(() => ({ stdout: "" }));
            const dockerfiles = dockerFilesOut.split('\n').filter(Boolean);

            for (const dfPath of dockerfiles) {
                const content = await fs.readFile(dfPath, 'utf8');
                const relPath = path.relative(targetPath, dfPath);

                // Check 1: Running as Root (Missing USER)
                if (!content.includes('USER ') || content.includes('USER root')) {
                    findings.push({
                        id: "DOCKER-RUNNING-AS-ROOT",
                        tool: "infra-scanner",
                        title: "Container Running as Root",
                        description: `Dockerfile at ${relPath} does not specify a non-root USER or explicitly switches to root. This violates least privilege.`,
                        severity: "HIGH",
                        category: "INFRASTRUCTURE",
                        location: { path: dfPath },
                        cweId: ["CWE-250"], // Execution with Unnecessary Privileges
                        metadata: { file: relPath }
                    });
                }

                // Check 2: Using 'latest' tag
                if (/FROM\s+[\w-/]+:latest/.test(content)) {
                    findings.push({
                        id: "DOCKER-TAG-LATEST",
                        tool: "infra-scanner",
                        title: "Base Image Using 'latest' Tag",
                        description: `Dockerfile at ${relPath} uses ':latest' tag. This makes builds non-reproducible and can introduce unexpected breaking changes or vulnerabilities. Pin to a specific version or hash.`,
                        severity: "MEDIUM",
                        category: "INFRASTRUCTURE",
                        location: { path: dfPath },
                        cweId: [],
                        metadata: { file: relPath }
                    });
                }

                // Check 3: Secrets in ENV or ARG
                if (/ENV\s+(PASSWORD|SECRET|KEY|TOKEN)/i.test(content) || /ARG\s+(PASSWORD|SECRET|KEY|TOKEN)/i.test(content)) {
                    findings.push({
                        id: "DOCKER-SECRETS-IN-ENV",
                        tool: "infra-scanner",
                        title: "Potential Secrets in Dockerfile",
                        description: `Dockerfile at ${relPath} seems to set secrets via ENV or ARG. These values persist in image layers. Use Docker Secrets or run-time environment variables instead.`,
                        severity: "HIGH",
                        category: "INFRASTRUCTURE",
                        location: { path: dfPath },
                        cweId: ["CWE-526"], // Information Exposure Through Environmental Variables
                        metadata: { file: relPath }
                    });
                }
            }

        } catch (e) {
            console.warn("Infra Scanner: Docker check failed", e);
        }

        // 2. Sensitive Config Files
        try {
            // Check for .env files that are NOT in gitignore (heuristic: if we see them, they exist on disk, we hope they aren't in git)
            // Ideally we'd check git status but let's just warn if we see .env in root
            const items = await fs.readdir(targetPath);
            if (items.includes(".env")) {
                const envContent = await fs.readFile(path.join(targetPath, ".env"), 'utf8');
                // Basic check if it looks like it has real secrets, not just examples
                if (!envContent.includes("EXAMPLE") && (envContent.includes("KEY=") || envContent.includes("SECRET="))) {
                    findings.push({
                        id: "DOT-ENV-FILE-DETECTED",
                        tool: "infra-scanner",
                        title: ".env File Detected in Root",
                        description: "Found a .env file in the root directory. Ensure this is NOT committed to version control (.gitignore).",
                        severity: "LOW",
                        category: "INFRASTRUCTURE",
                        location: { path: path.join(targetPath, ".env") },
                        cweId: ["CWE-200"],
                        metadata: { file: ".env" }
                    });
                }
            }
        } catch (e) { }

        // 3. CI/CD Checks (GitHub Actions)
        try {
            const githubWorkflowsPath = path.join(targetPath, ".github", "workflows");
            const workflows = await fs.readdir(githubWorkflowsPath).catch(() => []);

            for (const wf of workflows) {
                if (!wf.endsWith('.yml') && !wf.endsWith('.yaml')) continue;
                const wfPath = path.join(githubWorkflowsPath, wf);
                const content = await fs.readFile(wfPath, 'utf8');

                // Check: Permissions not pinned? (Hard to do with regex, but let's check for 'permissions:' key)
                if (!content.includes("permissions:")) {
                    findings.push({
                        id: "GHA-MISSING-PERMISSIONS",
                        tool: "infra-scanner",
                        title: "GitHub Actions Missing Permissions",
                        description: `Workflow ${wf} does not specify 'permissions:'. By default, this may grant excessive Token privileges. Explicitly set permissions: read-all or stricter.`,
                        severity: "MEDIUM",
                        category: "INFRASTRUCTURE",
                        location: { path: wfPath },
                        cweId: ["CWE-269"],
                        metadata: { file: wf }
                    });
                }
            }

        } catch (e) { }


        return {
            tool: "infra-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings,
            scanPath: targetPath,
            success: true
        };

    } catch (error: any) {
        return {
            tool: "infra-scanner",
            timestamp: new Date().toISOString(),
            durationMs: Date.now() - startTime,
            findings: [],
            scanPath: targetPath,
            success: false,
            error: error.message
        };
    }
}
