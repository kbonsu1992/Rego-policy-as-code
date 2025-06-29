package mast.policy

deny[msg] if {
  some finding in input.findings
  finding.severity == "HIGH"
  msg = sprintf("MAST - High severity issue: %s in %s", [finding.type, finding.location])
}
