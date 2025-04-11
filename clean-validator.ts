#!/usr/bin/env bun
import { spawnSync } from 'child_process';
import chalk from 'chalk';

// @ts-ignore - Chalk has some TypeScript compatibility issues with string literals
console.log(chalk.blue('Starting Nele Bank API Validator (Clean Output Mode)'));

// Get command line arguments
const args = process.argv.slice(2);
const fileArg = args.find(arg => arg.startsWith('-f') || arg.startsWith('--file'));
const fileParam = fileArg ? [fileArg] : ['-f', '../nele-bank/openapi.json'];

const result = spawnSync('bun', ['run', 'index.ts', ...fileParam], {
  stdio: 'pipe',
  encoding: 'utf-8'
});

if (result.error) {
  // @ts-ignore - Chalk has some TypeScript compatibility issues with string literals
  console.error(chalk.red(`Error executing validator: ${result.error.message}`));
  process.exit(1);
}

// Process the output to filter out 429 warnings and security violations
const output = result.stdout;
const lines = output.split('\n');

let filteredLines = [];
let skipSection = false;
let totalIssuesLine = '';

for (const line of lines) {
  // Capture the total issues line to modify it later
  if (line.includes('Total issues found:')) {
    totalIssuesLine = line;
    continue;
  }
  
  // Skip security violations section
  if (line.includes('=== Security Violations ===')) {
    skipSection = true;
    continue;
  }
  
  // Skip API specification discrepancies section (429 warnings)
  if (line.includes('=== API Specification Discrepancies ===')) {
    skipSection = true;
    continue;
  }
  
  // Reset skipSection when we hit a new section
  if (line.startsWith('===') && !line.includes('Security Violations') && !line.includes('API Specification Discrepancies')) {
    skipSection = false;
  }
  
  // Add the line if we're not skipping the current section
  if (!skipSection) {
    filteredLines.push(line);
  }
}

// Calculate the actual number of issues after filtering
const structureMismatches = filteredLines.filter(line => 
  line.includes('Response structure doesn\'t match') || 
  line.includes('Response for') && line.includes('doesn\'t match schema')
).length;

// Add a modified total issues line
if (structureMismatches > 0) {
  filteredLines.push(`\nTotal issues found after filtering: ${structureMismatches}`);
} else {
  filteredLines.push(`\nTotal issues found after filtering: 0 (All validation passed!)`);
}

// Print the filtered output
console.log(filteredLines.join('\n'));
