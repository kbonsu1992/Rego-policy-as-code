package iam.policy_test

import data.iam.policy

test_deny_public_member_allUsers if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "b1", "role": "roles/storage.objectViewer", "members": ["allUsers"]}
    ]
  }
  count(result) >= 1
}

test_deny_public_member_allAuthenticatedUsers if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "b2", "role": "roles/run.invoker", "members": ["allAuthenticatedUsers"]}
    ]
  }
  count(result) >= 1
}

test_deny_primitive_role_owner if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "owner-binding", "role": "roles/owner", "members": ["user:admin@example.com"]}
    ]
  }
  count(result) >= 1
}

test_deny_primitive_role_editor if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "editor-binding", "role": "roles/editor", "members": ["user:dev@example.com"]}
    ]
  }
  count(result) >= 1
}

test_deny_primitive_role_viewer if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "viewer-binding", "role": "roles/viewer", "members": ["user:auditor@example.com"]}
    ]
  }
  count(result) >= 1
}

test_deny_user_managed_sa_key if {
  result := policy.deny with input as {
    "serviceAccounts": [
      {
        "email": "legacy@p.iam.gserviceaccount.com",
        "keys": [{"name": "k1", "keyType": "USER_MANAGED"}]
      }
    ]
  }
  count(result) >= 1
}

test_no_deny_for_compliant_binding if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "ok", "role": "roles/run.invoker", "members": ["serviceAccount:app@p.iam.gserviceaccount.com"]}
    ],
    "serviceAccounts": [
      {"email": "app@p.iam.gserviceaccount.com", "keys": [{"name": "k1", "keyType": "SYSTEM_MANAGED"}]}
    ]
  }
  count(result) == 0
}

test_waiver_skips_binding_by_id if {
  result := policy.deny with input as {
    "iamBindings": [
      {"id": "owner-binding", "role": "roles/owner", "members": ["user:admin@example.com"]}
    ],
    "exceptions": [{"id": "owner-binding"}]
  }
  count(result) == 0
}

test_waiver_skips_sa_by_email if {
  result := policy.deny with input as {
    "serviceAccounts": [
      {
        "email": "legacy@p.iam.gserviceaccount.com",
        "keys": [{"name": "k1", "keyType": "USER_MANAGED"}]
      }
    ],
    "exceptions": [{"id": "legacy@p.iam.gserviceaccount.com"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
