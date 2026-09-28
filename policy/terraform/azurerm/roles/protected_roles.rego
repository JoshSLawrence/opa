package terraform.azurerm.roles

import rego.v1

# All sensitive Azure RBAC role names that require review
sensitive_azure_role_names := {
	"Owner",
	"User Access Administrator",
	"Contributor",
}

# Get Azure role assignments being created or updated
role_assignment_changes contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_role_assignment"
	some action in resource.change.actions
	action in ["create", "update"]
}

# Get Azure role assignments being deleted
role_assignment_deletions contains resource if {
	some resource in input.resource_changes
	resource.type == "azurerm_role_assignment"
	some action in resource.change.actions
	action == "delete"
}

# Warn for sensitive Azure RBAC role changes (create/update)
warn contains result if {
	some assignment in role_assignment_changes
	role_name := assignment.change.after.role_definition_name
	role_name in sensitive_azure_role_names

	result := {
		"msg": sprintf("Sensitive Azure role change: %s (role: %s)", [
			assignment.address,
			role_name,
		]),
		"severity": "medium",
	}
}

# Warn for sensitive Azure RBAC role deletions
warn contains result if {
	some assignment in role_assignment_deletions
	role_name := assignment.change.before.role_definition_name
	role_name in sensitive_azure_role_names

	result := {
		"msg": sprintf("Sensitive Azure role deletion: %s (role: %s)", [
			assignment.address,
			role_name,
		]),
		"severity": "medium",
	}
}
