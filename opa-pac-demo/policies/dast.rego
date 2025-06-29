package dast.policy

deny[msg] {
  issue := input.issues[_]
  issue.severity == "HIGH"
  msg := sprintf("❌ DAST issue: %s (HIGH)", [issue.name])
}
