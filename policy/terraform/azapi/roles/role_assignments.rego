package terraform.azapi.roles

import rego.v1

# Built-in Azure RBAC role definition IDs (the trailing GUID of
# `.../providers/Microsoft.Authorization/roleDefinitions/<guid>`) that require
# review, keyed to their display name.
#
# The azapi provider assigns roles via a raw ARM `roleAssignments` resource
# whose body references the role by definition ID, not by name. We therefore
# match on these well-known built-in GUIDs. Keep this in sync with
# `sensitive_azure_role_names` in the azurerm.roles policy.
sensitive_builtin_role_ids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
}

# azapi role assignments being created or updated
role_assignment_changes contains resource if {
	some resource in input.resource_changes
	resource.type in {"azapi_resource", "azapi_update_resource"}
	some action in resource.change.actions
	action in ["create", "update"]
	startswith(resource.change.after.type, "Microsoft.Authorization/roleAssignments")
}

# azapi role assignments being deleted
role_assignment_deletions contains resource if {
	some resource in input.resource_changes
	resource.type in {"azapi_resource", "azapi_update_resource"}
	some action in resource.change.actions
	action == "delete"
	startswith(resource.change.before.type, "Microsoft.Authorization/roleAssignments")
}

# Extract the trailing role-definition GUID from an azapi change body.
#
# azapi v2 exposes `body` as a decoded object; azapi v1 exposes it as a
# JSON-encoded string. Handle both.
role_definition_guid(change) := guid if {
	is_object(change.body)
	guid := _trailing_segment(change.body.properties.roleDefinitionId)
}

role_definition_guid(change) := guid if {
	is_string(change.body)
	decoded := json.unmarshal(change.body)
	guid := _trailing_segment(decoded.properties.roleDefinitionId)
}

_trailing_segment(path) := segment if {
	parts := split(path, "/")
	segment := parts[count(parts) - 1]
}

# Warn for sensitive azapi role assignment changes (create/update)
warn contains result if {
	some resource in role_assignment_changes
	guid := role_definition_guid(resource.change.after)
	role_name := sensitive_builtin_role_ids[guid]

	result := {
		"msg": sprintf("Sensitive Azure role change: %s (role: %s)", [
			resource.address,
			role_name,
		]),
		"severity": "medium",
	}
}

# Warn for sensitive azapi role assignment deletions
warn contains result if {
	some resource in role_assignment_deletions
	guid := role_definition_guid(resource.change.before)
	role_name := sensitive_builtin_role_ids[guid]

	result := {
		"msg": sprintf("Sensitive Azure role deletion: %s (role: %s)", [
			resource.address,
			role_name,
		]),
		"severity": "medium",
	}
}
