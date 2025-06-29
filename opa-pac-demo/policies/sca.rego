package sca.policy

deny[msg] if {
  some dep in input.dependencies
  dep.severity == "CRITICAL"
  msg = sprintf("SCA - Critical vulnerability %s in %s %s", [dep.cve, dep.pkg, dep.version])
}
