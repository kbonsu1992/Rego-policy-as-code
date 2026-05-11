package gke.policy

# Deny GKE clusters without private nodes enabled.
deny[msg] if {
  some cluster in object.get(input, "clusters", [])
  private_nodes := object.get(object.get(cluster, "privateClusterConfig", {}), "enablePrivateNodes", false)
  private_nodes == false
  cluster_id := cluster_identifier(cluster)
  not is_waived(cluster_id)
  msg = sprintf("GKE - Cluster %s does not have private nodes enabled", [cluster_id])
}

# Deny GKE clusters without Workload Identity configured.
deny[msg] if {
  some cluster in object.get(input, "clusters", [])
  wi_pool := sprintf("%v", [object.get(object.get(cluster, "workloadIdentityConfig", {}), "workloadPool", "")])
  wi_pool == ""
  cluster_id := cluster_identifier(cluster)
  not is_waived(cluster_id)
  msg = sprintf("GKE - Cluster %s does not have Workload Identity enabled", [cluster_id])
}

# Deny GKE clusters with legacy ABAC enabled.
deny[msg] if {
  some cluster in object.get(input, "clusters", [])
  abac_disabled := object.get(object.get(cluster, "legacyAbac", {}), "enabled", false)
  abac_disabled == true
  cluster_id := cluster_identifier(cluster)
  not is_waived(cluster_id)
  msg = sprintf("GKE - Cluster %s has legacy ABAC enabled", [cluster_id])
}

# Deny GKE clusters without Master Authorized Networks restricting control plane access.
deny[msg] if {
  some cluster in object.get(input, "clusters", [])
  man_enabled := object.get(object.get(cluster, "masterAuthorizedNetworksConfig", {}), "enabled", false)
  man_enabled == false
  cluster_id := cluster_identifier(cluster)
  not is_waived(cluster_id)
  msg = sprintf("GKE - Cluster %s does not enforce Master Authorized Networks", [cluster_id])
}

# Deny GKE clusters that allow basic auth / client cert (legacy auth methods).
deny[msg] if {
  some cluster in object.get(input, "clusters", [])
  master_auth := object.get(cluster, "masterAuth", {})
  username := sprintf("%v", [object.get(master_auth, "username", "")])
  username != ""
  cluster_id := cluster_identifier(cluster)
  not is_waived(cluster_id)
  msg = sprintf("GKE - Cluster %s has legacy basic auth enabled", [cluster_id])
}

# Stable identifier: prefer name, fallback to selfLink, then unknown.
cluster_identifier(cluster) := name if {
  name := sprintf("%v", [object.get(cluster, "name", "")])
  name != ""
} else := link if {
  link := sprintf("%v", [object.get(cluster, "selfLink", "")])
  link != ""
} else := "UNKNOWN_GKE_CLUSTER"

# Waivers are provided as input.exceptions[].id values (match cluster identifier).
is_waived(cluster_id) if {
  some ex in object.get(input, "exceptions", [])
  ex_id := sprintf("%v", [object.get(ex, "id", "")])
  ex_id == cluster_id
}
