package sast.policy

deny[msg] if {
  some vuln in input.vulnerabilities
  vuln.severity == "HIGH"
  msg = sprintf("SAST - High severity issue: %s in %s at line %d", [vuln.id, vuln.file, vuln.line])
}
