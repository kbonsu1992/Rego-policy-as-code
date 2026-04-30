package sast.policy

# Deny SAST findings that are HIGH/CRITICAL unless explicitly waived.
deny[msg] if {
  some vuln in object.get(input, "vulnerabilities", [])
  sev := normalized_severity(vuln)
  is_blocking_severity(sev)
  issue_id := issue_identifier(vuln)
  not is_waived(issue_id)
  file := sprintf("%v", [object.get(vuln, "file", "unknown_file")])
  line := sprintf("%v", [object.get(vuln, "line", "unknown_line")])
  msg = sprintf("SAST - %s severity issue: %s in %s at line %s", [sev, issue_id, file, line])
}

# Normalize scanner-provided severity values for consistent comparisons.
normalized_severity(item) := sev if {
  raw := object.get(item, "severity", "")
  sev := upper(sprintf("%v", [raw]))
}

# Production gate: block both HIGH and CRITICAL severities.
is_blocking_severity(sev) if { sev == "HIGH" }
is_blocking_severity(sev) if { sev == "CRITICAL" }

# Prefer scanner ID, then CVE; fallback keeps decision output stable.
issue_identifier(item) := id if {
  id := sprintf("%v", [object.get(item, "id", "")])
  id != ""
} else := cve if {
  cve := sprintf("%v", [object.get(item, "cve", "")])
  cve != ""
} else := "UNKNOWN_SAST_ISSUE"

# Waivers are provided as input.exceptions[].id values.
is_waived(issue_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == issue_id
}
