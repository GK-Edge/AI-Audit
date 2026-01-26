

import inquirer from 'inquirer';
import ora from 'ora';
import chalk from 'chalk';
import figlet from 'figlet';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    console.clear();
    console.log(
        chalk.cyan(
            figlet.textSync('AI AUDITOR', { font: 'ANSI Shadow', horizontalLayout: 'full' })
        )
    );
    console.log(chalk.white('Welcome to the AI-Powered Security Compliance Agent. Created with ❤️  by GK Edge. Authored by Manos Koulouris'));
    console.log(chalk.yellow('⚠️  Disclaimer: Passing this audit clears ~90% of technical hurdles but does NOT replace a manual penetration test for complex business logic.\n'));

    const answers = await inquirer.prompt([
        {
            type: 'rawlist',
            name: 'auditType',
            message: 'Select the Audit Standard to perform (Type the number):',
            choices: [
                'CASA Tier 2 (App Defense Alliance)',
                'CISSP (Under Development - Not Ready)',
                'SOC 2 (Under Development - Not Ready)'
            ]
        },
        {
            type: 'input',
            name: 'targetPath',
            message: 'Where is your application located? (Absolute path)',
            default: process.cwd(),
            validate: (input) => {
                if (fs.existsSync(input)) return true;
                return 'Path does not exist. Please try again.';
            }
        },
        {
            type: 'input',
            name: 'targetUrl',
            message: 'Enter local URL for Dynamic Analysis (ie. http://localhost:3000) [Optional]:',
            default: '',
            filter: (input: string) => input.trim()

        },
        {
            type: 'input', // Changed from password to input to allow user to verify token paste
            name: 'authToken',
            message: 'Enter Authorization Bearer Token (optional) to scan protected routes:',
            default: '',
            filter: (input: string) => input.trim()
        },
        {
            type: 'checkbox',
            name: 'reportFormats',
            message: 'Report output options (select any):',
            choices: [
                {
                    name: 'Generate SARIF (helps LLMs triage faster, CI tools like GitHub/AWS/Azure ingest results)',
                    value: 'sarif'
                }
            ],
            default: []
        }
    ]);

    const auditProfile = "CASA-Tier-2"; // Currently the only fully supported profile
    const wantsSarif = Array.isArray(answers.reportFormats) && answers.reportFormats.includes('sarif');
    const reportExtension = wantsSarif ? 'sarif' : 'md';
    const reportName = `audit_report_${Date.now()}.${reportExtension}`;
    const outputPath = path.join(process.cwd(), reportName);

    console.log(`\n${chalk.blue('ℹ')} Selected Audit: ${chalk.bold(answers.auditType)}`);
    console.log(`${chalk.blue('ℹ')} Target: ${chalk.dim(answers.targetPath)}`);
    console.log(`${chalk.blue('ℹ')} Profile: ${chalk.bold(auditProfile)}\n`);

    const spinner = ora('Initializing AI Auditor...').start();

    // Determine path to the CLI entry point
    // We assume this script is run via 'node dist/wizard.js' so 'dist/index.js' is sibling
    // Or if run via ts-node, we might need adjustments. 
    // Best bet: assume we are in package root or dist.

    // Construct absolute path to dist/index.js
    const cliPath = path.resolve(__dirname, 'index.js'); // Assuming wizard.js and index.js are in same dir (dist)

    const args = [cliPath, 'scan', answers.targetPath, '--output', outputPath, '--standard', auditProfile];
    if (wantsSarif) {
        args.push('--format', 'sarif');
    }
    if (answers.targetUrl) {
        args.push('--url', answers.targetUrl);
    }
    if (answers.authToken) {
        args.push('--token', answers.authToken);
    }

    const child = spawn('node', args, {
        cwd: process.cwd(),
        env: process.env // Pass environment variables (PATH, etc)
    });

    let lastLog = '';

    child.stdout.on('data', (data) => {
        const line = data.toString().trim();
        if (!line) return;
        lastLog = line;

        // Update spinner based on keywords
        if (line.includes('Running SAST Scan')) {
            spinner.text = 'Phase 1/6: Running Static Analysis (SAST)...';
            spinner.color = 'yellow';
        } else if (line.includes('Dependency Scan')) {
            spinner.text = 'Phase 2/6: Checking Dependencies (SCA)...';
            spinner.color = 'cyan';
        } else if (line.includes('Evidence Scan')) {
            spinner.text = 'Phase 3/6: Gathering Evidence (Scopes, Docs)...';
            spinner.color = 'magenta';
        } else if (line.includes('Infrastructure Scan')) {
            spinner.text = 'Phase 4/6: Checking Infrastructure (Docker, Secrets)...';
            spinner.color = 'blue';
        } else if (line.includes('DAST Scan')) {
            spinner.text = 'Phase 5/6: Running Dynamic Analysis (DAST)...';
            spinner.color = 'red';
        } else if (line.includes('Generating Report')) {
            spinner.text = 'Phase 6/6: Generating Compliance Report...';
            spinner.color = 'green';
        }
    });

    let errorLog = '';

    child.stderr.on('data', (data) => {
        const line = data.toString().trim();
        if (!line) return;
        errorLog += line + '\n';
        // Optional: Uncomment to see live errors in verbose mode
        // console.error(chalk.red(line)); 
    });

    child.on('close', (code) => {
        if (code === 0) {
            spinner.succeed(chalk.green('Audit Complete!'));
            console.log('\n' + chalk.bold.green('✔ Report Generated Successfully'));
            console.log(`  Path: ${chalk.underline(outputPath)}`);
            console.log('\n' + chalk.dim('Open this file to view your detailed compliance score and remediation steps.'));
        } else {
            spinner.fail(chalk.red('Audit Failed'));
            console.error(chalk.red(`Process exited with code ${code}`));
            console.error(chalk.yellow('Last stdout log:'), lastLog);
            if (errorLog) {
                console.error(chalk.red('\nError Details (stderr):'));
                console.error(errorLog);
            }
        }
    });
}

main().catch(console.error);
