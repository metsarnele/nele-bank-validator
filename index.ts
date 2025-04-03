#!/usr/bin/env bun
import * as path from 'path';
import axios from 'axios';
import chalk from 'chalk';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { Command } from 'commander';
import SwaggerParser from '@apidevtools/swagger-parser';

// Setup command line interface
const program = new Command();
program
  .name('eero-api-validator')
  .description('Validates the API against the OpenAPI specification')
  .version('1.0.0')
  .option('-v, --verbose', 'Show verbose output')
  .option('-u, --url <url>', 'API base URL', 'https://bank.eerovallistu.site')
  .option('-f, --file <file>', 'OpenAPI specification file', './openapi.json')
  .parse(process.argv);

const options = program.opts();
const API_BASE_URL = options.url as string;
const OPENAPI_FILE = options.file as string;
const VERBOSE = options.verbose as boolean;

// Initialize validation tools
const ajv = new Ajv({ 
  allErrors: true,
  strict: false, // Allow additional keywords like 'example'
  validateFormats: false // Don't validate formats strictly
});
addFormats(ajv); // This already adds 'format' keyword

// Add custom keywords that are used in OpenAPI but not in JSON Schema
ajv.addKeyword('example');

// @ts-ignore - Chalk has some TypeScript compatibility issues with string literals
// Utility for colorized logging
const logger = {
  info: (msg: string): void => console.log(chalk.blue(msg)),
  success: (msg: string): void => console.log(chalk.green(msg)),
  warning: (msg: string): void => console.log(chalk.yellow(msg)),
  error: (msg: string): void => console.log(chalk.red(msg)),
  verbose: (msg: string): void => { if (VERBOSE) console.log(chalk.gray(msg)); }
};

// Types
interface OpenAPIInfo {
  title: string;
  version: string;
  description?: string;
}

interface OpenAPISpec {
  openapi: string;
  info: OpenAPIInfo;
  paths: Record<string, PathItem>;
  components?: {
    securitySchemes?: Record<string, any>;
    schemas?: Record<string, any>;
    responses?: Record<string, any>;
  };
  servers?: Array<{ url: string }>;
}

interface PathItem {
  [method: string]: OperationObject;
}

interface OperationObject {
  summary?: string;
  tags?: string[];
  parameters?: any[];
  requestBody?: RequestBodyObject;
  responses?: Record<string, ResponseObject>;
  security?: Array<Record<string, string[]>>;
}

interface RequestBodyObject {
  description?: string;
  content?: Record<string, ContentObject>;
  required?: boolean;
}

interface ResponseObject {
  description: string;
  content?: Record<string, ContentObject>;
}

interface ContentObject {
  schema?: any;
  examples?: Record<string, { value: any }>;
}

interface ValidationResult {
  endpoint: string;
  method: string;
  issues: ValidationIssue[];
}

interface ValidationIssue {
  type: 'unimplemented' | 'missing_example' | 'structure_mismatch' | 'security_violation' | 'spec_discrepancy';
  message: string;
  details?: any;
}

// Load and validate OpenAPI specification
async function loadOpenAPISpec(): Promise<OpenAPISpec> {
  try {
    const filePath = path.resolve(process.cwd(), OPENAPI_FILE);
    
    // Use SwaggerParser to validate the spec
    const api = await SwaggerParser.validate(filePath) as OpenAPISpec;
    logger.success('OpenAPI specification is valid!');
    
    return api;
  } catch (error) {
    logger.error(`Failed to load or validate OpenAPI specification: ${error}`);
    process.exit(1);
    throw error; // This will never be reached, but satisfies TypeScript
  }
}

// Validate examples for all endpoints requiring request bodies
function validateRequestExamples(spec: OpenAPISpec): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (['post', 'put', 'patch'].includes(method.toLowerCase()) && operation.requestBody) {
        const hasRequestExample = hasExample(operation.requestBody);
        
        if (!hasRequestExample) {
          issues.push({
            type: 'missing_example',
            message: `Missing request example for ${method.toUpperCase()} ${path}`
          });
        }
      }
    }
  }

  return issues;
}

// Validate examples for all response statuses
function validateResponseExamples(spec: OpenAPISpec): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (operation.responses) {
        let hasAnyExample = false;
        
        // Check if any response status has examples
        for (const [_, response] of Object.entries(operation.responses)) {
          if (hasExample(response)) {
            hasAnyExample = true;
            break;
          }
        }
        
        if (!hasAnyExample) {
          issues.push({
            type: 'missing_example',
            message: `No response examples found for ${method.toUpperCase()} ${path}`
          });
        }
      }
    }
  }

  return issues;
}

// Check if a requestBody or response has examples or a schema that could be used for validation
function hasExample(obj: RequestBodyObject | ResponseObject): boolean {
  if (!obj || !obj.content) return false;
  
  for (const contentObj of Object.values(obj.content)) {
    // Check for content.examples
    if (contentObj.examples && Object.keys(contentObj.examples).length > 0) {
      return true;
    }
    
    // Check for content.schema.example
    if (contentObj.schema && 'example' in contentObj.schema) {
      return true;
    }
    
    // Check for examples in schema properties
    if (contentObj.schema && 
        contentObj.schema.type === 'object' && 
        contentObj.schema.properties) {
      // Check if at least one property has an example
      for (const propSchema of Object.values(contentObj.schema.properties as Record<string, any>)) {
        if (propSchema && typeof propSchema === 'object' && 'example' in propSchema) {
          return true;
        }
      }
      
      // Even if no examples, consider a well-defined schema to be sufficient for validation
      if (Object.keys(contentObj.schema.properties).length > 0) {
        return true;
      }
    }
    
    // Also accept arrays with defined item types as valid for validation
    if (contentObj.schema && 
        contentObj.schema.type === 'array' && 
        contentObj.schema.items) {
      return true;
    }
  }
  
  return false;
}

// Test API endpoints against the spec
async function testEndpoints(spec: OpenAPISpec): Promise<ValidationResult[]> {
  const results: ValidationResult[] = [];

  // Get authentication token if needed
  let authToken: string | null = null;
  try {
    const loginResponse = await axios.post(`${API_BASE_URL}/sessions`, {
      username: 'testuser',
      password: 'password123'
    });
    
    if (loginResponse.data && loginResponse.data.token) {
      authToken = loginResponse.data.token;
      logger.success('Authenticated successfully');
    }
  } catch (error) {
    logger.warning('Could not authenticate. Some tests may fail for protected endpoints.');
  }

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      // Skip non-HTTP methods
      if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method.toLowerCase())) {
        continue;
      }

      const endpoint = path.replace(/{([^}]+)}/g, '1'); // Replace path parameters with '1'
      const requiresAuth = operation.security && operation.security.length > 0;
      
      const endpointResult: ValidationResult = {
        endpoint,
        method: method.toUpperCase(),
        issues: []
      };

      try {
        const headers: Record<string, string> = {};
        if (requiresAuth && authToken) {
          headers['Authorization'] = `Bearer ${authToken}`;
        }

        // Prepare request body if needed
        let requestBody: any = undefined;
        if (['post', 'put', 'patch'].includes(method.toLowerCase()) && operation.requestBody) {
          requestBody = extractRequestExample(operation.requestBody);
        }

        // Log request details if verbose
        logger.verbose(`Testing ${method.toUpperCase()} ${API_BASE_URL}${endpoint}`);
        if (requestBody) {
          logger.verbose(`Request body: ${JSON.stringify(requestBody, null, 2)}`);
        }

        // Make the request
        const response = await axios({
          method: method.toLowerCase() as any,
          url: `${API_BASE_URL}${endpoint}`,
          headers,
          data: requestBody,
          validateStatus: () => true // Don't throw on error status codes
        });

        // Check if endpoint is implemented
        if (response.status === 404) {
          endpointResult.issues.push({
            type: 'unimplemented',
            message: `Endpoint ${method.toUpperCase()} ${endpoint} is not implemented (404)`
          });
          results.push(endpointResult);
          continue;
        }

        // Check security enforcement
        if (requiresAuth && !authToken) {
          if (response.status !== 401 && response.status !== 403) {
            endpointResult.issues.push({
              type: 'security_violation',
              message: `Endpoint ${method.toUpperCase()} ${endpoint} doesn't properly enforce authentication`
            });
          }
        }

        // Check if response status is documented
        const hasDocumentedStatus = operation.responses && Object.keys(operation.responses).some(
          status => status === response.status.toString() || status === 'default'
        );

        if (!hasDocumentedStatus) {
          endpointResult.issues.push({
            type: 'spec_discrepancy',
            message: `Undocumented status code ${response.status} for ${method.toUpperCase()} ${endpoint}`
          });
        }

        // Validate response structure against examples if status is documented
        if (hasDocumentedStatus && operation.responses) {
          const responseKey = response.status.toString() in operation.responses 
            ? response.status.toString() 
            : 'default';
          
          if (operation.responses[responseKey]) {
            const responseObj = operation.responses[responseKey];
            const contentType = response.headers['content-type']?.toString().split(';')[0] || 'application/json';
            
            if (responseObj.content && responseObj.content[contentType]) {
              const contentObj = responseObj.content[contentType];
              
              if (contentObj.schema) {
                // Validate response against schema
                const validate = ajv.compile(contentObj.schema);
                const valid = validate(response.data);
                
                if (!valid) {
                  endpointResult.issues.push({
                    type: 'structure_mismatch',
                    message: `Response for ${method.toUpperCase()} ${endpoint} doesn't match schema`,
                    details: validate.errors
                  });
                }
              }
              
              // Check against example if available
              if (contentObj.examples || (contentObj.schema && 'example' in contentObj.schema)) {
                let example: any;
                
                if (contentObj.examples && Object.keys(contentObj.examples).length > 0) {
                  const firstExample = Object.values(contentObj.examples)[0];
                  if (firstExample && 'value' in firstExample) {
                    example = firstExample.value;
                  }
                } else if (contentObj.schema && 'example' in contentObj.schema) {
                  example = contentObj.schema.example;
                }
                
                if (example) {
                  const structureMismatch = compareStructure(example, response.data);
                  if (structureMismatch) {
                    endpointResult.issues.push({
                      type: 'structure_mismatch',
                      message: `Response structure doesn't match example for ${method.toUpperCase()} ${endpoint}`,
                      details: structureMismatch
                    });
                  }
                }
              }
            }
          }
        }
      } catch (error) {
        endpointResult.issues.push({
          type: 'spec_discrepancy',
          message: `Error testing ${method.toUpperCase()} ${endpoint}: ${error}`
        });
      }

      if (endpointResult.issues.length > 0) {
        results.push(endpointResult);
      }
    }
  }

  return results;
}

// Extract a sample request body from the spec
function extractRequestExample(requestBody: RequestBodyObject): any {
  if (!requestBody || !requestBody.content) return {};
  
  for (const [_, content] of Object.entries(requestBody.content)) {
    if (content.examples && Object.keys(content.examples).length > 0) {
      const firstExample = Object.values(content.examples)[0];
      if (firstExample && 'value' in firstExample) {
        return firstExample.value || {};
      }
    }
    
    if (content.schema && 'example' in content.schema) {
      return content.schema.example;
    }
    
    if (content.schema) {
      return generateExampleFromSchema(content.schema);
    }
  }
  
  return {};
}

// Generate example data from schema
function generateExampleFromSchema(schema: any): any {
  if (!schema) return undefined;
  
  if ('example' in schema) return schema.example;
  
  if (schema.type === 'object') {
    const result: Record<string, any> = {};
    
    if (schema.properties) {
      for (const [prop, propSchema] of Object.entries(schema.properties)) {
        result[prop] = generateExampleFromSchema(propSchema as any);
      }
    }
    
    return result;
  }
  
  if (schema.type === 'array') {
    if (schema.items) {
      return [generateExampleFromSchema(schema.items)];
    }
    return [];
  }
  
  if (schema.type === 'string') {
    if (schema.enum && Array.isArray(schema.enum) && schema.enum.length > 0) return schema.enum[0];
    if (schema.format === 'date-time') return new Date().toISOString();
    if (schema.format === 'email') return 'user@example.com';
    return 'string';
  }
  
  if (schema.type === 'number' || schema.type === 'integer') {
    return 1;
  }
  
  if (schema.type === 'boolean') {
    return true;
  }
  
  return undefined;
}

// Compare response structure against example
function compareStructure(example: any, actual: any): string | null {
  // Different types
  if (typeof example !== typeof actual) {
    return `Type mismatch: expected ${typeof example}, got ${typeof actual}`;
  }
  
  // Arrays
  if (Array.isArray(example)) {
    if (!Array.isArray(actual)) {
      return `Expected array, got ${typeof actual}`;
    }
    
    if (example.length > 0 && actual.length > 0) {
      return compareStructure(example[0], actual[0]);
    }
    
    return null;
  }
  
  // Objects
  if (typeof example === 'object' && example !== null) {
    if (typeof actual !== 'object' || actual === null) {
      return `Expected object, got ${typeof actual}`;
    }
    
    // Check all example keys exist in actual
    for (const key of Object.keys(example)) {
      if (!(key in (actual as Record<string, any>))) {
        return `Missing property '${key}' in response`;
      }
      
      const nestedResult = compareStructure(example[key], (actual as Record<string, any>)[key]);
      if (nestedResult) {
        return `For property '${key}': ${nestedResult}`;
      }
    }
  }
  
  return null;
}

// Display validation results
function displayResults(results: ValidationResult[]): void {
  if (results.length === 0) {
    logger.success('No validation issues found!');
    return;
  }
  
  logger.info('\n=== Validation Results ===\n');
  
  // Group by issue type
  const unimplemented: ValidationResult[] = [];
  const missingExamples: ValidationResult[] = [];
  const structureMismatches: ValidationResult[] = [];
  const securityViolations: ValidationResult[] = [];
  const specDiscrepancies: ValidationResult[] = [];
  
  for (const result of results) {
    for (const issue of result.issues) {
      const resultCopy = { ...result, issues: [issue] };
      
      switch (issue.type) {
        case 'unimplemented':
          unimplemented.push(resultCopy);
          break;
        case 'missing_example':
          missingExamples.push(resultCopy);
          break;
        case 'structure_mismatch':
          structureMismatches.push(resultCopy);
          break;
        case 'security_violation':
          securityViolations.push(resultCopy);
          break;
        case 'spec_discrepancy':
          specDiscrepancies.push(resultCopy);
          break;
      }
    }
  }
  
  // Display each category
  if (unimplemented.length > 0) {
    logger.error('\n=== Unimplemented Endpoints ===');
    for (const result of unimplemented) {
      console.log(`${result.method} ${result.endpoint}: ${result.issues[0].message}`);
    }
  }
  
  if (missingExamples.length > 0) {
    logger.warning('\n=== Missing Response Examples ===');
    for (const result of missingExamples) {
      console.log(`${result.issues[0].message}`);
    }
  }
  
  if (structureMismatches.length > 0) {
    logger.error('\n=== Response Example Structure Mismatches ===');
    for (const result of structureMismatches) {
      console.log(`${result.method} ${result.endpoint}: ${result.issues[0].message}`);
      if (result.issues[0].details && VERBOSE) {
        console.log(`  Details: ${JSON.stringify(result.issues[0].details, null, 2)}`);
      }
    }
  }
  
  if (securityViolations.length > 0) {
    logger.error('\n=== Security Violations ===');
    for (const result of securityViolations) {
      console.log(`${result.method} ${result.endpoint}: ${result.issues[0].message}`);
    }
  }
  
  if (specDiscrepancies.length > 0) {
    logger.warning('\n=== API Specification Discrepancies ===');
    for (const result of specDiscrepancies) {
      console.log(`${result.method} ${result.endpoint}: ${result.issues[0].message}`);
    }
  }
  
  const totalIssues = unimplemented.length + missingExamples.length + 
    structureMismatches.length + securityViolations.length + specDiscrepancies.length;
  
  logger.info(`\nTotal issues found: ${totalIssues}`);
}

// Main function
async function main() {
  logger.info('Starting Eero API Validator');
  logger.info(`Using OpenAPI spec: ${OPENAPI_FILE}`);
  logger.info(`API base URL: ${API_BASE_URL}`);
  
  const spec = await loadOpenAPISpec();
  
  logger.info(`Loaded OpenAPI spec: ${spec.info.title} v${spec.info.version}`);
  
  const requestExampleIssues = validateRequestExamples(spec);
  const responseExampleIssues = validateResponseExamples(spec);
  
  // Convert example issues to ValidationResult format
  const exampleResults: ValidationResult[] = [
    ...requestExampleIssues.map(issue => ({ 
      endpoint: '', 
      method: '', 
      issues: [issue] 
    })),
    ...responseExampleIssues.map(issue => ({ 
      endpoint: '', 
      method: '', 
      issues: [issue] 
    }))
  ];
  
  logger.info('Testing API endpoints...');
  const testResults = await testEndpoints(spec);
  
  // Combine all results
  const allResults = [...exampleResults, ...testResults];
  
  displayResults(allResults);
}

// Run the validator
main().catch(error => {
  logger.error(`Error: ${error.message}`);
  process.exit(1);
});
