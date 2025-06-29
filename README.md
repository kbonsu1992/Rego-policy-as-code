# Rego Policy as Code - Application Security Scanner Policies

This project demonstrates how to implement Open Policy Agent (OPA) policies for various application security scanners including SAST, DAST, MAST, and SCA. The policies are designed to evaluate security scan results and provide automated compliance checks.

## 📁 Project Structure

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

## 🔧 Prerequisites

- Docker installed and running
- Basic understanding of Rego policy language
- Familiarity with application security scanning concepts

## 📋 Policy Overview

### 1. SAST (Static Application Security Testing)
- **Policy File**: `policies/sast.rego`
- **Input**: `inputs/sast.json`
- **Purpose**: Evaluates static code analysis results for security vulnerabilities
- **Rules**: Denies builds with critical or high severity vulnerabilities

### 2. DAST (Dynamic Application Security Testing)
- **Policy File**: `policies/dast.rego`
- **Input**: `inputs/dast.json`
- **Purpose**: Evaluates runtime security testing results
- **Rules**: Denies deployments with critical security findings

### 3. MAST (Mobile Application Security Testing)
- **Policy File**: `policies/mast.rego`
- **Input**: `inputs/mast.json`
- **Purpose**: Evaluates mobile app security scan results
- **Rules**: Denies mobile app releases with critical vulnerabilities

### 4. SCA (Software Composition Analysis)
- **Policy File**: `policies/sca.rego`
- **Input**: `inputs/sca.json`
- **Purpose**: Evaluates third-party dependency vulnerabilities
- **Rules**: Denies builds with critical dependency vulnerabilities

## 🚀 Quick Start

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

## 🔍 Policy Details

### SAST Policy (`policies/sast.rego`)
```rego
package sast.policy

deny[msg] if {
  some vuln in input.vulnerabilities
  vuln.severity == "CRITICAL"
  msg = sprintf("SAST - Critical vulnerability %s in %s", [vuln.cve, vuln.file])
}
```

### DAST Policy (`policies/dast.rego`)
```rego
package dast.policy

deny[msg] if {
  some finding in input.findings
  finding.severity == "CRITICAL"
  msg = sprintf("DAST - Critical finding %s at %s", [finding.id, finding.url])
}
```

### MAST Policy (`policies/mast.rego`)
```rego
package mast.policy

deny[msg] if {
  some issue in input.issues
  issue.severity == "CRITICAL"
  msg = sprintf("MAST - Critical issue %s in %s", [issue.id, issue.component])
}
```

### SCA Policy (`policies/sca.rego`)
```rego
package sca.policy

deny[msg] if {
  some dep in input.dependencies
  dep.severity == "CRITICAL"
  msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.pkg, dep.version])
}
```

## 📊 Sample Inputs

### SCA Input (`inputs/sca.json`)
```json
{
  "dependencies": [
    {
      "pkg": "log4j",
      "version": "2.14.1",
      "cve": "CVE-2021-44228",
      "severity": "CRITICAL"
    }
  ]
}
```

### SAST Input (`inputs/sast.json`)
```json
{
  "vulnerabilities": [
    {
      "cve": "CVE-2021-1234",
      "severity": "CRITICAL",
      "file": "src/main/java/Example.java",
      "line": 42
    }
  ]
}
```

### DAST Input (`inputs/dast.json`)
```json
{
  "findings": [
    {
      "id": "SQL_INJECTION_001",
      "severity": "CRITICAL",
      "url": "https://example.com/api/users",
      "description": "SQL injection vulnerability detected"
    }
  ]
}
```

### MAST Input (`inputs/mast.json`)
```json
{
  "issues": [
    {
      "id": "INSECURE_STORAGE_001",
      "severity": "CRITICAL",
      "component": "DataStorage.java",
      "description": "Sensitive data stored in plain text"
    }
  ]
}
```

## 🐛 Common Errors and Fixes

### 1. Rego Parse Error: Unexpected Package Keyword

**Error:**
```
rego_parse_error: unexpected package keyword: expected identifier
msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.package, dep.version])
```

**Cause:** Using `dep.package` where `package` is a reserved keyword in Rego.

**Fix:** Rename the field from `package` to `pkg` in both the policy and input JSON.

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

**Error:** `1 error occurred during loading`

**Cause:** Syntax errors in Rego policies or missing dependencies.

**Fix:** Validate policies using OPA check command:
```bash
docker run --rm -v $(pwd)/policies:/policies openpolicyagent/opa:latest check /policies/*.rego
```

## 🔄 API Usage Examples

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

## 🏗️ Docker Build Process

### Dockerfile Analysis
```dockerfile
FROM openpolicyagent/opa:latest

# Copy policies to container
COPY policies /policies

# Set working directory
WORKDIR /policies

# Expose OPA server port
EXPOSE 8181

# Default command to run OPA server
CMD ["run", "--server", "/policies"]
```

### Build Commands
```bash
# Build image
docker build -t opa-appsec-policies .

# Run container
docker run --rm -p 8181:8181 opa-appsec-policies

# Run with volume mount for development
docker run --rm -p 8181:8181 -v $(pwd)/policies:/policies opa-appsec-policies
```

## 🧪 Testing

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
Create test scripts to validate policy behavior with various inputs.

## 📈 Integration Examples

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

## 🔧 Troubleshooting

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
netstat -an | grep 8181
```

## 📚 Additional Resources

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA REST API Documentation](https://www.openpolicyagent.org/docs/latest/rest-api/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 