#!/usr/bin/env bun
import { spawnSync } from 'child_process';
import chalk from 'chalk';

// @ts-ignore - Chalk has some TypeScript compatibility issues with string literals
console.log(chalk.blue('Starting Eero API Validator (Clean Output Mode)'));

const result = spawnSync('bun', ['run', 'index.ts'], {
  stdio: 'pipe',
  encoding: 'utf-8'
});

if (result.error) {
  // @ts-ignore - Chalk has some TypeScript compatibility issues with string literals
  console.error(chalk.red(`Error executing validator: ${result.error.message}`));
  process.exit(1);
}

// Process the output to remove duplicate error messages
const output = result.stdout;
const lines = output.split('\n');

const seenErrors = new Set();
const cleanedLines = [];

for (const line of lines) {
  // Skip empty lines
  if (!line.trim()) {
    cleanedLines.push(line);
    continue;
  }
  
  // Always keep section headers
  if (line.includes('===')) {
    cleanedLines.push(line);
    continue;
  }
  
  // For error messages, check if we've seen this before
  const errorHash = line.trim().toLowerCase();
  
  if (!seenErrors.has(errorHash)) {
    seenErrors.add(errorHash);
    cleanedLines.push(line);
  }
}

console.log(cleanedLines.join('\n'));

// Report exit code from the main validator
process.exit(result.status);
