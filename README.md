# Rego Policy as Code - Application Security Scanner Policies

This project uses Open Policy Agent (OPA) to enforce policy-as-code checks for SAST, DAST, MAST, and SCA scan results.

## Project Structure

```
Rego-policy-as-code/
├── opa-pac-demo/
│   ├── Dockerfile                 # Custom OPA Docker image
│   ├── inputs/                    # Sample JSON inputs for each scanner
│   │   ├── dast.json             # DAST scan results
│   │   ├── mast.json             # MAST scan results
│   │   ├── sast.json             # SAST scan results
│   │   └── sca.json              # SCA scan results
│   └── policies/                  # Rego policy files
│       ├── dast.rego             # DAST policy rules
│       ├── mast.rego             # MAST policy rules
│       ├── sast.rego             # SAST policy rules
│       └── sca.rego              # SCA policy rules
└── README.md
```

## Prerequisites

- Docker installed and running
- Basic understanding of Rego policy language
- Familiarity with application security scanning concepts

## Policy Overview

### 1. SAST (Static Application Security Testing)
- **Policy**: `policies/sast.rego`
- **Input**: `inputs/sast.json`
- **Threshold**: Deny on `HIGH` and `CRITICAL`

### 2. DAST (Dynamic Application Security Testing)
- **Policy**: `policies/dast.rego`
- **Input**: `inputs/dast.json`
- **Threshold**: Deny on `HIGH` and `CRITICAL`

### 3. MAST (Mobile Application Security Testing)
- **Policy**: `policies/mast.rego`
- **Input**: `inputs/mast.json`
- **Threshold**: Deny on `HIGH` and `CRITICAL`

### 4. SCA (Software Composition Analysis)
- **Policy**: `policies/sca.rego`
- **Input**: `inputs/sca.json`
- **Threshold**: Deny on `HIGH` and `CRITICAL`

## Quick Start

### 1. Build the Docker Image

```bash
cd opa-pac-demo
docker build -t opa-appsec-policies .
```

### 2. Run OPA Server

```bash
docker run --rm -p 8181:8181 -v $(pwd)/policies:/policies opa-appsec-policies run --server --addr 0.0.0.0:8181 /policies
```

**Important**: Use `--addr 0.0.0.0:8181` to bind to all interfaces for external access.

### 3. Test the API

```bash
# Health check
curl http://localhost:8181/health

# Test SCA policy with critical vulnerability
curl -X POST http://localhost:8181/v1/data/sca/policy \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "dependencies": [
        {
          "pkg": "log4j",
          "version": "2.14.1",
          "cve": "CVE-2021-44228",
          "severity": "CRITICAL"
        }
      ]
    }
  }'
```

## Policy Source of Truth (Actual Implementation)

Use this section as the canonical reference for policy behavior in `opa-pac-demo/policies/*.rego`.

### 1) SAST

- **Policy package**: `sast.policy`
- **Endpoint**: `POST /v1/data/sast/policy`
- **Expected input schema**:
  - `input.vulnerabilities[]`
  - Fields used by policy: `id`, `severity`, `file`, `line`
  - Optional waiver list: `input.exceptions[]` with `id` values to skip
- **Deny condition**: `severity` is `HIGH` or `CRITICAL` (unless waived)

```bash
curl -X POST http://localhost:8181/v1/data/sast/policy \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "vulnerabilities": [
        {
          "id": "SQL_INJECTION",
          "severity": "HIGH",
          "file": "src/db.py",
          "line": 45
        }
      ],
      "exceptions": [
        {
          "id": "EXAMPLE_WAIVER_ID"
        }
      ]
    }
  }'
```

### 2) DAST

- **Policy package**: `dast.policy`
- **Endpoint**: `POST /v1/data/dast/policy`
- **Expected input schema**:
  - `input.issues[]`
  - Fields used by policy: `name`, `severity`
  - Optional waiver list: `input.exceptions[]` with `id` values to skip
- **Deny condition**: `severity` is `HIGH` or `CRITICAL` (unless waived)

```bash
curl -X POST http://localhost:8181/v1/data/dast/policy \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "issues": [
        {
          "name": "Cross-Site Scripting",
          "severity": "HIGH"
        }
      ],
      "exceptions": [
        {
          "id": "EXAMPLE_WAIVER_ID"
        }
      ]
    }
  }'
```

### 3) MAST

- **Policy package**: `mast.policy`
- **Endpoint**: `POST /v1/data/mast/policy`
- **Expected input schema**:
  - `input.findings[]`
  - Fields used by policy: `type`, `severity`, `location`
  - Optional waiver list: `input.exceptions[]` with `id` values to skip
- **Deny condition**: `severity` is `HIGH` or `CRITICAL` (unless waived)

```bash
curl -X POST http://localhost:8181/v1/data/mast/policy \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "findings": [
        {
          "type": "Hardcoded API Key",
          "severity": "HIGH",
          "location": "MainActivity.java"
        }
      ],
      "exceptions": [
        {
          "id": "EXAMPLE_WAIVER_ID"
        }
      ]
    }
  }'
```

### 4) SCA

- **Policy package**: `sca.policy`
- **Endpoint**: `POST /v1/data/sca/policy`
- **Expected input schema**:
  - `input.dependencies[]`
  - Fields used by policy: `pkg`, `version`, `cve`, `severity`
  - Optional waiver list: `input.exceptions[]` with `id` values to skip
- **Deny condition**: `severity` is `HIGH` or `CRITICAL` (unless waived)

```bash
curl -X POST http://localhost:8181/v1/data/sca/policy \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "dependencies": [
        {
          "pkg": "log4j",
          "version": "2.14.1",
          "cve": "CVE-2021-44228",
          "severity": "CRITICAL"
        }
      ],
      "exceptions": [
        {
          "id": "CVE-2021-44228"
        }
      ]
    }
  }'
```

### Notes

- All policies deny on `HIGH` and `CRITICAL` severities.
- Field names are scanner-specific and must match exactly:
  - SAST: `vulnerabilities`
  - DAST: `issues`
  - MAST: `findings`
  - SCA: `dependencies`
- Waivers are optional and scanner-agnostic via `input.exceptions[]`:
  - Example: `{ "id": "CVE-2021-44228" }`
  - Match behavior: if exception `id` matches the policy identifier, that result is skipped.

## Common Errors and Fixes

### 1. Rego Parse Error: Unexpected `package` Keyword

**Error:**
```
rego_parse_error: unexpected package keyword: expected identifier
msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.package, dep.version])
```

**Cause:** `package` is a reserved keyword in Rego, so `dep.package` is invalid.

**Fix:** Use `dep.pkg` in both policy and input JSON.

**Before:**
```rego
msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.package, dep.version])
```

**After:**
```rego
msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.pkg, dep.version])
```

### 2. API Endpoint Unresponsive

**Error:** `curl: (56) Recv failure: Connection reset by peer`

**Cause:** OPA server binding to `localhost:8181` inside container, not accessible externally.

**Fix:** Use `--addr 0.0.0.0:8181` flag when starting OPA server.

**Before:**
```bash
docker run --rm -p 8181:8181 -v $(pwd)/policies:/policies opa-appsec-policies run --server /policies
```

**After:**
```bash
docker run --rm -p 8181:8181 -v $(pwd)/policies:/policies opa-appsec-policies run --server --addr 0.0.0.0:8181 /policies
```

### 3. Policy Validation Errors

If policy loading fails, validate syntax with:
```bash
docker run --rm -v $(pwd)/policies:/policies openpolicyagent/opa:latest check /policies/*.rego
```

## API Usage Examples

### Evaluate All Policies
```bash
curl -X POST http://localhost:8181/v1/data \
  -H "Content-Type: application/json" \
  -d '{"input": {}}'
```

### Evaluate Specific Policy
```bash
# SCA Policy
curl -X POST http://localhost:8181/v1/data/sca/policy \
  -H "Content-Type: application/json" \
  -d @inputs/sca.json

# SAST Policy
curl -X POST http://localhost:8181/v1/data/sast/policy \
  -H "Content-Type: application/json" \
  -d @inputs/sast.json
```

### Expected Responses

**No Violations:**
```json
{"result":{"deny":{}}}
```

**With Violations:**
```json
{
  "result": {
    "deny": {
      "SCA - Critical vulnerability CVE-2021-44228 in log4j 2.14.1": true
    }
  }
}
```

## Docker Build Process

### Dockerfile Analysis
```dockerfile
FROM openpolicyagent/opa:latest

# Copy policies and sample inputs to container
COPY policies/ /policies/
COPY inputs/ /inputs/

# Use OPA binary as container entrypoint
ENTRYPOINT ["opa"]
```

### Build Commands
```bash
# Build image
docker build -t opa-appsec-policies .

# Run container
docker run --rm -p 8181:8181 opa-appsec-policies run --server --addr 0.0.0.0:8181 /policies

# Run with volume mount for development
docker run --rm -p 8181:8181 -v $(pwd)/policies:/policies opa-appsec-policies run --server --addr 0.0.0.0:8181 /policies
```

## Testing

### Manual Testing
```bash
# Test health endpoint
curl http://localhost:8181/health

# Test policy evaluation
curl -X POST http://localhost:8181/v1/data/sca/policy \
  -H "Content-Type: application/json" \
  -d '{"input": {"dependencies": [{"pkg": "test", "version": "1.0.0", "cve": "CVE-TEST", "severity": "CRITICAL"}]}}'
```

### Automated Testing
Add automated tests (for example, OPA/Rego test cases) to validate policy behavior across multiple input variants.

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Run Security Policy Check
  run: |
    curl -X POST http://localhost:8181/v1/data/sca/policy \
      -H "Content-Type: application/json" \
      -d @scan-results.json
```

### Kubernetes Admission Controller
Use OPA as an admission controller to enforce policies on Kubernetes resources.

## Troubleshooting

### Check Container Status
```bash
docker ps
docker logs <container-id>
```

### Validate Policies
```bash
docker run --rm -v $(pwd)/policies:/policies openpolicyagent/opa:latest check /policies/*.rego
```

### Test Network Connectivity
```bash
curl -v http://localhost:8181/health
# Linux/macOS:
netstat -an | grep 8181
# Windows PowerShell:
netstat -an | findstr 8181
```

## Additional Resources

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA REST API Documentation](https://www.openpolicyagent.org/docs/latest/rest-api/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Test thoroughly
5. Submit a pull request

## License
