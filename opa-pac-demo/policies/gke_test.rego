package gke.policy_test

import data.gke.policy

test_deny_when_private_nodes_disabled if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "public-cluster",
        "privateClusterConfig": {"enablePrivateNodes": false},
        "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "legacyAbac": {"enabled": false},
        "masterAuthorizedNetworksConfig": {"enabled": true},
        "masterAuth": {}
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_workload_identity_missing if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "no-wi-cluster",
        "privateClusterConfig": {"enablePrivateNodes": true},
        "workloadIdentityConfig": {"workloadPool": ""},
        "legacyAbac": {"enabled": false},
        "masterAuthorizedNetworksConfig": {"enabled": true},
        "masterAuth": {}
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_legacy_abac_enabled if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "legacy-abac-cluster",
        "privateClusterConfig": {"enablePrivateNodes": true},
        "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "legacyAbac": {"enabled": true},
        "masterAuthorizedNetworksConfig": {"enabled": true},
        "masterAuth": {}
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_master_authorized_networks_disabled if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "open-control-plane",
        "privateClusterConfig": {"enablePrivateNodes": true},
        "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "legacyAbac": {"enabled": false},
        "masterAuthorizedNetworksConfig": {"enabled": false},
        "masterAuth": {}
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_basic_auth_enabled if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "basic-auth-cluster",
        "privateClusterConfig": {"enablePrivateNodes": true},
        "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "legacyAbac": {"enabled": false},
        "masterAuthorizedNetworksConfig": {"enabled": true},
        "masterAuth": {"username": "admin"}
      }
    ]
  }
  count(result) >= 1
}

test_no_deny_for_compliant_cluster if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "secure-cluster",
        "privateClusterConfig": {"enablePrivateNodes": true},
        "workloadIdentityConfig": {"workloadPool": "p.svc.id.goog"},
        "legacyAbac": {"enabled": false},
        "masterAuthorizedNetworksConfig": {"enabled": true},
        "masterAuth": {}
      }
    ]
  }
  count(result) == 0
}

test_waiver_skips_findings_for_cluster if {
  result := policy.deny with input as {
    "clusters": [
      {
        "name": "legacy-cluster",
        "privateClusterConfig": {"enablePrivateNodes": false},
        "workloadIdentityConfig": {"workloadPool": ""},
        "legacyAbac": {"enabled": true},
        "masterAuthorizedNetworksConfig": {"enabled": false},
        "masterAuth": {"username": "admin"}
      }
    ],
    "exceptions": [{"id": "legacy-cluster"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
