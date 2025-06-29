package mast.policy

deny[msg] {
  f := input.findings[_]
  f.severity == "HIGH"
  msg := sprintf("❌ MAST issue: %s in %s", [f.type, f.location])
}
