package sast.policy

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

normalized_severity(item) := sev if {
  raw := object.get(item, "severity", "")
  sev := upper(sprintf("%v", [raw]))
}

is_blocking_severity(sev) if { sev == "HIGH" }
is_blocking_severity(sev) if { sev == "CRITICAL" }

issue_identifier(item) := id if {
  id := sprintf("%v", [object.get(item, "id", "")])
  id != ""
} else := cve if {
  cve := sprintf("%v", [object.get(item, "cve", "")])
  cve != ""
} else := "UNKNOWN_SAST_ISSUE"

is_waived(issue_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == issue_id
}
