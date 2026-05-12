package gcs.policy_test

import data.gcs.policy

test_deny_public_bucket_allUsers if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "public-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": true},
          "publicAccessPrevention": "enforced"
        },
        "iamBindings": [
          {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        ]
      }
    ]
  }
  count(result) >= 1
}

test_deny_public_bucket_allAuthenticatedUsers if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "public-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": true},
          "publicAccessPrevention": "enforced"
        },
        "iamBindings": [
          {"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}
        ]
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_ubla_disabled if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "no-ubla-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": false},
          "publicAccessPrevention": "enforced"
        },
        "iamBindings": []
      }
    ]
  }
  count(result) >= 1
}

test_deny_when_pap_not_enforced if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "no-pap-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": true},
          "publicAccessPrevention": "inherited"
        },
        "iamBindings": []
      }
    ]
  }
  count(result) >= 1
}

test_no_deny_for_compliant_bucket if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "secure-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": true},
          "publicAccessPrevention": "enforced"
        },
        "iamBindings": [
          {"role": "roles/storage.objectViewer", "members": ["serviceAccount:app@project.iam.gserviceaccount.com"]}
        ]
      }
    ]
  }
  count(result) == 0
}

test_waiver_skips_all_findings_for_bucket if {
  result := policy.deny with input as {
    "buckets": [
      {
        "name": "legacy-bucket",
        "iamConfiguration": {
          "uniformBucketLevelAccess": {"enabled": false},
          "publicAccessPrevention": "inherited"
        },
        "iamBindings": [
          {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        ]
      }
    ],
    "exceptions": [{"id": "legacy-bucket"}]
  }
  count(result) == 0
}

test_missing_input_is_safe if {
  result := policy.deny with input as {}
  count(result) == 0
}
