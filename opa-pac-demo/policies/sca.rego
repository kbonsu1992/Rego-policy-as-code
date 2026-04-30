package sca.policy

# Deny vulnerable dependencies that are HIGH/CRITICAL unless waived.
deny[msg] if {
  some dep in object.get(input, "dependencies", [])
  sev := normalized_severity(dep)
  is_blocking_severity(sev)
  dep_id := dependency_identifier(dep)
  not is_waived(dep_id)
  pkg := sprintf("%v", [object.get(dep, "pkg", "unknown_pkg")])
  version := sprintf("%v", [object.get(dep, "version", "unknown_version")])
  cve := sprintf("%v", [object.get(dep, "cve", dep_id)])
  msg = sprintf("SCA - %s vulnerability %s in %s %s", [sev, cve, pkg, version])
}

# Normalize scanner-provided severity values for consistent comparisons.
normalized_severity(item) := sev if {
  raw := object.get(item, "severity", "")
  sev := upper(sprintf("%v", [raw]))
}

# Production gate: block both HIGH and CRITICAL severities.
is_blocking_severity(sev) if { sev == "HIGH" }
is_blocking_severity(sev) if { sev == "CRITICAL" }

# Prefer CVE, then package:version; fallback keeps output deterministic.
dependency_identifier(item) := cve if {
  cve := sprintf("%v", [object.get(item, "cve", "")])
  cve != ""
} else := pkg_ver if {
  pkg := sprintf("%v", [object.get(item, "pkg", "")])
  ver := sprintf("%v", [object.get(item, "version", "")])
  pkg != ""
  ver != ""
  pkg_ver := sprintf("%s:%s", [pkg, ver])
} else := "UNKNOWN_SCA_DEPENDENCY"

# Waivers are provided as input.exceptions[].id values.
is_waived(dep_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == dep_id
}
