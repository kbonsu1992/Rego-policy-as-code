package dast.policy_test

import data.dast.policy

test_deny_on_high_severity if {
  result := policy.deny with input as {
    "issues": [{"id": "XSS-1", "name": "Cross-Site Scripting", "severity": "HIGH"}]
  }
  count(result) == 1
}

test_deny_on_critical_severity if {
  result := policy.deny with input as {
    "issues": [{"id": "SQLI-1", "name": "SQL Injection", "severity": "CRITICAL"}]
  }
  count(result) == 1
}

test_no_deny_on_low_severity if {
  result := policy.deny with input as {
    "issues": [{"id": "LOW-1", "name": "Info Leak", "severity": "LOW"}]
  }
  count(result) == 0
}

test_waiver_by_id_skips_deny if {
  result := policy.deny with input as {
    "issues": [{"id": "XSS-1", "name": "Cross-Site Scripting", "severity": "HIGH"}],
    "exceptions": [{"id": "XSS-1"}]
  }
  count(result) == 0
}

test_waiver_by_name_fallback_skips_deny if {
  result := policy.deny with input as {
    "issues": [{"name": "Cross-Site Scripting", "severity": "HIGH"}],
    "exceptions": [{"id": "Cross-Site Scripting"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
