package sca.policy_test

import data.sca.policy

test_deny_on_critical_cve if {
  result := policy.deny with input as {
    "dependencies": [{"pkg": "log4j", "version": "2.14.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"}]
  }
  count(result) == 1
}

test_deny_on_high_cve if {
  result := policy.deny with input as {
    "dependencies": [{"pkg": "lodash", "version": "4.17.20", "cve": "CVE-2020-8203", "severity": "HIGH"}]
  }
  count(result) == 1
}

test_no_deny_on_low if {
  result := policy.deny with input as {
    "dependencies": [{"pkg": "left-pad", "version": "1.3.0", "cve": "CVE-XXXX", "severity": "LOW"}]
  }
  count(result) == 0
}

test_waiver_by_cve_skips_deny if {
  result := policy.deny with input as {
    "dependencies": [{"pkg": "log4j", "version": "2.14.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"}],
    "exceptions": [{"id": "CVE-2021-44228"}]
  }
  count(result) == 0
}

test_waiver_by_pkg_version_fallback if {
  result := policy.deny with input as {
    "dependencies": [{"pkg": "log4j", "version": "2.14.1", "severity": "CRITICAL"}],
    "exceptions": [{"id": "log4j:2.14.1"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
