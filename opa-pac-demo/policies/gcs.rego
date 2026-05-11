package gcs.policy

# Deny GCS buckets that are publicly accessible via allUsers / allAuthenticatedUsers.
deny[msg] if {
  some bucket in object.get(input, "buckets", [])
  some binding in object.get(bucket, "iamBindings", [])
  some member in object.get(binding, "members", [])
  is_public_member(member)
  bucket_id := bucket_identifier(bucket)
  not is_waived(bucket_id)
  role := sprintf("%v", [object.get(binding, "role", "unknown_role")])
  msg = sprintf("GCS - Public access on bucket %s via %s (role: %s)", [bucket_id, member, role])
}

# Deny GCS buckets without Uniform Bucket-Level Access enabled.
deny[msg] if {
  some bucket in object.get(input, "buckets", [])
  ubla_enabled := object.get(object.get(object.get(bucket, "iamConfiguration", {}), "uniformBucketLevelAccess", {}), "enabled", false)
  ubla_enabled == false
  bucket_id := bucket_identifier(bucket)
  not is_waived(bucket_id)
  msg = sprintf("GCS - Bucket %s does not enforce Uniform Bucket-Level Access", [bucket_id])
}

# Deny GCS buckets that do not enforce Public Access Prevention.
deny[msg] if {
  some bucket in object.get(input, "buckets", [])
  pap := upper(sprintf("%v", [object.get(object.get(bucket, "iamConfiguration", {}), "publicAccessPrevention", "")]))
  pap != "ENFORCED"
  bucket_id := bucket_identifier(bucket)
  not is_waived(bucket_id)
  msg = sprintf("GCS - Bucket %s does not have publicAccessPrevention=ENFORCED", [bucket_id])
}

# allUsers and allAuthenticatedUsers are the GCP public principals.
is_public_member(member) if { member == "allUsers" }
is_public_member(member) if { member == "allAuthenticatedUsers" }

# Stable identifier: prefer name, fallback to selfLink, then unknown.
bucket_identifier(bucket) := name if {
  name := sprintf("%v", [object.get(bucket, "name", "")])
  name != ""
} else := link if {
  link := sprintf("%v", [object.get(bucket, "selfLink", "")])
  link != ""
} else := "UNKNOWN_GCS_BUCKET"

# Waivers are provided as input.exceptions[].id values (match bucket identifier).
is_waived(bucket_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == bucket_id
}
