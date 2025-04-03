# Eero API Validator

This project validates the API of Brigita's banking system at https://bank.eerovallistu.site/docs/ against the provided OpenAPI specification in `openapi.json`. It detects and reports various discrepancies between the API implementation and its documentation.

## Features

- Validates the API implementation against the OpenAPI specification
- Checks if request examples are provided for all endpoints that use methods that require a body
- Checks that each endpoint has at least one response example
- Validates that actual API responses match the structure of examples in the spec
- Tests authenticated endpoints to ensure proper security enforcement
- Identifies unimplemented endpoints (404 responses)
- Detects undocumented endpoints (endpoints return a different status code than documented)
- Provides detailed reports of discrepancies grouped by endpoint
- Shows verbose request and response details including headers and bodies. Example: Sending POST /users { "username": "jsmith", "password": "securePass123!" }. Only include the (possible) authorization header in the request and the location header in the response.

## Installation

To install dependencies:

```bash
bun install
```

## Usage

To run the validator:

```bash
bun run index.ts
```

For cleaner output without duplicate error messages:

```bash
bun run runner.ts
```

## Report Categories

The validator groups issues into several categories:

- **Unimplemented Endpoints**: Endpoints in the specification that return 404 responses
- **Missing Response Examples**: Responses that should include examples in the OpenAPI spec
- **Response Example Structure Mismatches**: API responses that don't match the structure defined in the examples
- **Security Violations**: Endpoints that should require authentication but don't enforce it
- **API Specification Discrepancies**: Other issues such as:
    - Undocumented status codes
    - Response validation errors
    - Schema validation issues

## Requirements

This project was created using `bun init` in bun v1.2.7. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
