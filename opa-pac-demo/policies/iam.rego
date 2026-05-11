package iam.policy

# Deny IAM bindings that grant access to allUsers or allAuthenticatedUsers.
deny[msg] if {
  some binding in object.get(input, "iamBindings", [])
  some member in object.get(binding, "members", [])
  is_public_member(member)
  binding_id := binding_identifier(binding)
  not is_waived(binding_id)
  role := sprintf("%v", [object.get(binding, "role", "unknown_role")])
  msg = sprintf("IAM - Public access granted: %s -> %s (%s)", [role, member, binding_id])
}

# Deny use of primitive roles (Owner / Editor / Viewer) at project, folder, or org scope.
deny[msg] if {
  some binding in object.get(input, "iamBindings", [])
  role := sprintf("%v", [object.get(binding, "role", "")])
  is_primitive_role(role)
  binding_id := binding_identifier(binding)
  not is_waived(binding_id)
  members := concat(", ", [sprintf("%v", [m]) | some m in object.get(binding, "members", [])])
  msg = sprintf("IAM - Primitive role used: %s for [%s] (%s)", [role, members, binding_id])
}

# Deny user-managed service account keys (long-lived credentials).
deny[msg] if {
  some sa in object.get(input, "serviceAccounts", [])
  some key in object.get(sa, "keys", [])
  key_type := upper(sprintf("%v", [object.get(key, "keyType", "")]))
  key_type == "USER_MANAGED"
  sa_id := service_account_identifier(sa)
  not is_waived(sa_id)
  key_id := sprintf("%v", [object.get(key, "name", "unknown_key")])
  msg = sprintf("IAM - User-managed service account key on %s (%s)", [sa_id, key_id])
}

# allUsers and allAuthenticatedUsers are the GCP public principals.
is_public_member(member) if { member == "allUsers" }
is_public_member(member) if { member == "allAuthenticatedUsers" }

# Primitive roles to avoid in production.
is_primitive_role(role) if { role == "roles/owner" }
is_primitive_role(role) if { role == "roles/editor" }
is_primitive_role(role) if { role == "roles/viewer" }

# Stable identifier: prefer explicit ID, then role, then unknown.
binding_identifier(binding) := id if {
  id := sprintf("%v", [object.get(binding, "id", "")])
  id != ""
} else := role if {
  role := sprintf("%v", [object.get(binding, "role", "")])
  role != ""
} else := "UNKNOWN_IAM_BINDING"

# Stable identifier for service accounts: prefer email, then name.
service_account_identifier(sa) := email if {
  email := sprintf("%v", [object.get(sa, "email", "")])
  email != ""
} else := name if {
  name := sprintf("%v", [object.get(sa, "name", "")])
  name != ""
} else := "UNKNOWN_SERVICE_ACCOUNT"

# Waivers are provided as input.exceptions[].id values.
is_waived(id_value) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == id_value
}
