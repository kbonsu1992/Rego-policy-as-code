package sca.policy

deny[msg] {
  dep := input.dependencies[_]
  dep.severity == "CRITICAL"
  msg := sprintf("❌ Critical vulnerability: %s in %s %s", [dep.cve, dep.package, dep.version])
}
