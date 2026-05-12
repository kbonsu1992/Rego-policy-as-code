package sast.policy_test

import data.sast.policy

test_deny_on_high_severity if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "SQL_INJECTION", "severity": "HIGH", "file": "src/db.py", "line": 45}
    ]
  }
  count(result) == 1
}

test_deny_on_critical_severity if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "RCE_001", "severity": "CRITICAL", "file": "src/exec.py", "line": 10}
    ]
  }
  count(result) == 1
}

test_no_deny_on_low_severity if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "INFO_1", "severity": "LOW", "file": "src/x.py", "line": 1}
    ]
  }
  count(result) == 0
}

test_no_deny_on_medium_severity if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "M1", "severity": "MEDIUM", "file": "src/y.py", "line": 7}
    ]
  }
  count(result) == 0
}

test_waiver_skips_deny if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "SQL_INJECTION", "severity": "HIGH", "file": "src/db.py", "line": 45}
    ],
    "exceptions": [{"id": "SQL_INJECTION"}]
  }
  count(result) == 0
}

test_severity_case_insensitive if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"id": "X1", "severity": "high", "file": "src/a.py", "line": 1}
    ]
  }
  count(result) == 1
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}

test_missing_optional_fields_uses_fallback if {
  result := policy.deny with input as {
    "vulnerabilities": [
      {"severity": "HIGH"}
    ]
  }
  count(result) == 1
}
