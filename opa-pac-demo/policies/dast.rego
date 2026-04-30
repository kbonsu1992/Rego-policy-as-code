package dast.policy

deny[msg] if {
  some issue in object.get(input, "issues", [])
  sev := normalized_severity(issue)
  is_blocking_severity(sev)
  issue_id := issue_identifier(issue)
  not is_waived(issue_id)
  name := sprintf("%v", [object.get(issue, "name", "unknown_issue")])
  msg = sprintf("DAST - %s severity issue: %s (%s)", [sev, name, issue_id])
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
} else := name if {
  name := sprintf("%v", [object.get(item, "name", "")])
  name != ""
} else := "UNKNOWN_DAST_ISSUE"

is_waived(issue_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == issue_id
}
