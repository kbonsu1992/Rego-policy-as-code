package mast.policy

# Deny MAST findings that are HIGH/CRITICAL unless explicitly waived.
deny[msg] if {
  some finding in object.get(input, "findings", [])
  sev := normalized_severity(finding)
  is_blocking_severity(sev)
  issue_id := issue_identifier(finding)
  not is_waived(issue_id)
  finding_type := sprintf("%v", [object.get(finding, "type", "unknown_type")])
  location := sprintf("%v", [object.get(finding, "location", "unknown_location")])
  msg = sprintf("MAST - %s severity issue: %s in %s (%s)", [sev, finding_type, location, issue_id])
}

# Normalize scanner-provided severity values for consistent comparisons.
normalized_severity(item) := sev if {
  raw := object.get(item, "severity", "")
  sev := upper(sprintf("%v", [raw]))
}

# Production gate: block both HIGH and CRITICAL severities.
is_blocking_severity(sev) if { sev == "HIGH" }
is_blocking_severity(sev) if { sev == "CRITICAL" }

# Prefer explicit ID, then finding type; fallback avoids empty identifiers.
issue_identifier(item) := id if {
  id := sprintf("%v", [object.get(item, "id", "")])
  id != ""
} else := finding_type if {
  finding_type := sprintf("%v", [object.get(item, "type", "")])
  finding_type != ""
} else := "UNKNOWN_MAST_ISSUE"

# Waivers are provided as input.exceptions[].id values.
is_waived(issue_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == issue_id
}
