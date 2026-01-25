#!/usr/bin/env node
import { Command } from "commander";
import dotenv from "dotenv";
import { runAudit } from "./orchestrator.js";

dotenv.config();

const program = new Command();

program
    .name("ai-auditor")
    .description("AI-powered Security Auditor Agent")
    .version("1.0.0");

program
    .command("scan")
    .description("Run a security audit on a target repository")
    .argument("<path>", "Path to the repository to scan")
    .option("-o, --output <path>", "Output path for the report", "./audit-report.md")
    .option("--standard <type>", "Compliance standard to check against", "CASA-Tier-2")
    .option("--format <format>", "Report format (markdown or sarif)")
    .option("--fail-on <severity>", "Exit non-zero if findings meet severity threshold (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    .option("--url <url>", "Target URL for DAST scan (e.g. http://localhost:3000)")
    .option("--token <token>", "Authorization Bearer Token for protected routes")
    .action(async (targetPath, options) => {
        console.log(`Starting audit for ${targetPath} with standard ${options.standard}`);
        try {
            const allowedFormats = ["markdown", "sarif"] as const;
            const allowedFailOn = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

            const reportFormat = options.format ? (String(options.format).toLowerCase() as typeof allowedFormats[number]) : undefined;
            if (reportFormat && !allowedFormats.includes(reportFormat)) {
                throw new Error(`Invalid format: ${options.format}. Use one of: ${allowedFormats.join(", ")}.`);
            }

            const failOn = options.failOn ? (String(options.failOn).toUpperCase() as typeof allowedFailOn[number]) : undefined;
            if (failOn && !allowedFailOn.includes(failOn)) {
                throw new Error(`Invalid fail-on severity: ${options.failOn}. Use one of: ${allowedFailOn.join(", ")}.`);
            }

            await runAudit(
                targetPath,
                options.output,
                options.standard,
                options.url,
                options.token,
                reportFormat,
                failOn
            );
        } catch (error) {
            console.error("Audit failed:", error);
            process.exit(1);
        }
    });

program.parse();
