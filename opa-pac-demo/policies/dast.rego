package dast.policy

# Deny DAST findings that are HIGH/CRITICAL unless explicitly waived.
deny[msg] if {
  some issue in object.get(input, "issues", [])
  sev := normalized_severity(issue)
  is_blocking_severity(sev)
  issue_id := issue_identifier(issue)
  not is_waived(issue_id)
  name := sprintf("%v", [object.get(issue, "name", "unknown_issue")])
  msg = sprintf("DAST - %s severity issue: %s (%s)", [sev, name, issue_id])
}

# Normalize scanner-provided severity values for consistent comparisons.
normalized_severity(item) := sev if {
  raw := object.get(item, "severity", "")
  sev := upper(sprintf("%v", [raw]))
}

# Production gate: block both HIGH and CRITICAL severities.
is_blocking_severity(sev) if { sev == "HIGH" }
is_blocking_severity(sev) if { sev == "CRITICAL" }

# Prefer explicit ID, then issue name; fallback avoids empty identifiers.
issue_identifier(item) := id if {
  id := sprintf("%v", [object.get(item, "id", "")])
  id != ""
} else := name if {
  name := sprintf("%v", [object.get(item, "name", "")])
  name != ""
} else := "UNKNOWN_DAST_ISSUE"

# Waivers are provided as input.exceptions[].id values.
is_waived(issue_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == issue_id
}
