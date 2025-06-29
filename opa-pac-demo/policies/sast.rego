package sast.policy

deny[msg] {
  vuln := input.vulnerabilities[_]
  vuln.severity == "HIGH"
  msg := sprintf("❌ High severity: %s in %s at line %d", [vuln.id, vuln.file, vuln.line])
}
