# AI Auditor Agent

```
 █████╗ ██╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗ 
██╔══██╗██║    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗
███████║██║    ███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝
██╔══██║██║    ██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║    ██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

[![Website](https://img.shields.io/badge/GK%20Edge-gkedgemedia.com-0b7285?style=for-the-badge)](https://gkedgemedia.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2b8a3e?style=for-the-badge)](LICENSE)

**AI Auditor Agent** is an AI-native security auditing CLI that helps startups achieve compliance with standards like **CASA Tier 2**. It orchestrates industry-standard scanners, maps findings to compliance requirements, and produces compliance-ready reports.

Website: https://gkedgemedia.com/

Leave us a star 🌟 if you like our project. Thank you!

Authored by [Manos Koulouris](https://github.com/ManosKoulouris).

## Why it exists

Compliance is VERY expensive, slow, manual, and usually starts too late. This project turns security evidence collection into a repeatable, developer-friendly workflow so teams can ship faster without losing audit readiness.

## How it works

1. You select a compliance standard (CASA Tier 2 today, with more on the way).
2. The agent runs static analysis and dependency scans across your codebase.
3. It maps results to compliance requirements and generates a structured report.
4. The CLI guides you through optional dynamic analysis and protected route testing.
5. All tools are MCP servers, so they seamlessly integrate with any AI agent.

## Prerequisites

The agent relies on a set of tools to perform the underlying scans. You must have the following installed in your environment:

1.  **Semgrep** (Static Analysis)
    ```bash
    pip install semgrep
    # or
    brew install semgrep
    ```

2.  **Trivy** (Dependency & Container Scanning)
    ```bash
    brew install trivy
    # or see https://aquasecurity.github.io/trivy/
    ```

## Installation

1.  Clone the repository.
2.  Install dependencies and build the monorepo:
    ```bash
    npm install
    npm run build --workspaces
    ```

## Launch the CLI

From the repo root:

```bash
npm install
npm run build --workspaces
npm run onboard
```

### Onboarding flow

You will be prompted to choose a standard and provide the target app and optional runtime inputs:

```
? Select the Audit Standard to perform (Type the number):
  1) CASA Tier 2 (App Defense Alliance)
  2) CISSP (Under Development - Not Ready)
  3) SOC 2 (Under Development - Not Ready)

? Where is your application located? (Absolute path) (/Users/manos/Desktop/code/GK Edge Projects/Security-Certify/packages/agent-core)

? Enter local URL for Dynamic Analysis (ie. http://localhost:3000) [Optional]:

? Enter Authorization Bearer Token (optional) to scan protected routes:

? Report output options (select any):
❯◯ Generate SARIF (helps LLMs triage faster, CI tools like GitHub/AWS/Azure ingest results)
```

## CLI usage (advanced)

Run the agent directly from the build output:

```bash
# Standard CASA Tier 2 Audit
node packages/agent-core/dist/index.js scan /path/to/your/repo --output ./report.md

# CISSP Domain 8 Audit (SDLC Focus)
node packages/agent-core/dist/index.js scan /path/to/your/repo --standard CISSP-Domain-8 --output ./cissp-report.md

# SOC 2 Common Criteria Audit (Change Management)
node packages/agent-core/dist/index.js scan /path/to/your/repo --standard SOC2-CC --output ./soc2-report.md

# SARIF output for CI integrations
node packages/agent-core/dist/index.js scan /path/to/your/repo --output ./report.sarif --format sarif --fail-on high
```

## Supported Standards

*   **CASA Tier 2** (`CASA-Tier-2`): Default. Checks for OWASP ASVS validation relative to Google Cloud requirements. Now includes **Evidence Scanning** for:
    *   Required Documentation (PRIVACY.md, SECURITY.md).
    *   OAuth Scope usage (verifying least privilege).
    *   Data Retention/Deletion logic detection.
*   **CISSP Domain 8** (`CISSP-Domain-8`): Audits Software Development Security artifacts (Tests, Linters, Privacy).
*   **SOC 2 Common Criteria** (`SOC2-CC`): Audits Change Management and Access Control evidence (.git, PR templates).

## Architecture

*   **`@ai-auditor/agent-core`**: The main CLI and orchestrator.
*   **`@ai-auditor/mcp-scanner`**: An MCP server that wraps Semgrep and Trivy.
*   **`@ai-auditor/mcp-reporter`**: An MCP server responsible for generating compliance reports.
*   **`@ai-auditor/shared-types`**: Unified data models for findings and compliance mappings.

## Roadmap

*   Add support for DAST (OWASP ZAP).
*   Implement "Auto-Remediation" to generate Pull Requests for findings.
*   Expand compliance mapping to SOC 2 and ISO 27001.

## License

MIT License. Copyright (c) 2026 [GK Edge](https://gkedgemedia.com/).
