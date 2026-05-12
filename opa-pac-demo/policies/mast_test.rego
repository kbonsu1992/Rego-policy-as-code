package mast.policy_test

import data.mast.policy

test_deny_on_high_severity if {
  result := policy.deny with input as {
    "findings": [{"id": "HC-1", "type": "Hardcoded API Key", "severity": "HIGH", "location": "MainActivity.java"}]
  }
  count(result) == 1
}

test_deny_on_critical_severity if {
  result := policy.deny with input as {
    "findings": [{"id": "JB-1", "type": "Jailbreak Bypass", "severity": "CRITICAL", "location": "RootCheck.kt"}]
  }
  count(result) == 1
}

test_no_deny_on_medium_severity if {
  result := policy.deny with input as {
    "findings": [{"id": "M-1", "type": "Info Disclosure", "severity": "MEDIUM", "location": "App.swift"}]
  }
  count(result) == 0
}

test_waiver_skips_deny if {
  result := policy.deny with input as {
    "findings": [{"id": "HC-1", "type": "Hardcoded API Key", "severity": "HIGH", "location": "MainActivity.java"}],
    "exceptions": [{"id": "HC-1"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
