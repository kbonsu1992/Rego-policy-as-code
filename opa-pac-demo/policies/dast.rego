package dast.policy

deny[msg] if {
  some issue in input.issues
  issue.severity == "HIGH"
  msg = sprintf("DAST - High severity issue: %s", [issue.name])
}
