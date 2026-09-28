package terraform.azuread.roles

import rego.v1

# Sensitive Entra directory roles, by built-in role template ID.
#
# Role-granting resources (`azuread_directory_role_assignment`,
# `azuread_directory_role_eligibility_schedule_request`) reference the role by
# its template ID. For built-in roles this is a well-known, stable GUID that is
# known at plan time. Keep this in sync with `sensitive_azuread_role_names`.
sensitive_directory_role_ids := {"62e90394-69f5-4237-9190-012177145e10": "Global Administrator"}

# Sensitive Entra directory role display names.
#
# The `azuread_directory_role` resource (which *activates* a role in the tenant)
# exposes `display_name` but no principal, so it is matched by name. Its
# companion assignment's `role_id` may be "known after apply" when it references
# the activated role's object ID rather than the built-in template ID.
sensitive_azuread_role_names := {"Global Administrator"}

# Resource types that grant a directory role to a principal.
role_grant_resource_types := {
	"azuread_directory_role_assignment",
	"azuread_directory_role_eligibility_schedule_request",
}

# Normalize a role-granting resource's change state into a common shape,
# since the assignment and eligibility resources use different attribute names.
_grant(resource, state) := {"principal_id": state.principal_object_id, "role_id": state.role_id} if {
	resource.type == "azuread_directory_role_assignment"
}

_grant(resource, state) := {"principal_id": state.principal_id, "role_id": state.role_definition_id} if {
	resource.type == "azuread_directory_role_eligibility_schedule_request"
}

# Get Azure AD directory roles being created or updated
directory_role_changes contains resource if {
	some resource in input.resource_changes
	resource.type == "azuread_directory_role"
	some action in resource.change.actions
	action in ["create", "update"]
}

# Get Azure AD directory roles being deleted
directory_role_deletions contains resource if {
	some resource in input.resource_changes
	resource.type == "azuread_directory_role"
	some action in resource.change.actions
	action == "delete"
}

# Warn for sensitive directory role grants (create/update)
warn contains result if {
	some resource in input.resource_changes
	resource.type in role_grant_resource_types
	some action in resource.change.actions
	action in ["create", "update"]

	grant := _grant(resource, resource.change.after)
	role_name := sensitive_directory_role_ids[grant.role_id]

	result := {
		"msg": sprintf(
			"Sensitive Entra role grant: %s (role: %s, principal: %s)",
			[resource.address, role_name, grant.principal_id],
		),
		"severity": "medium",
	}
}

# Warn for sensitive directory role grant removals (delete)
warn contains result if {
	some resource in input.resource_changes
	resource.type in role_grant_resource_types
	some action in resource.change.actions
	action == "delete"

	grant := _grant(resource, resource.change.before)
	role_name := sensitive_directory_role_ids[grant.role_id]

	result := {
		"msg": sprintf(
			"Sensitive Entra role grant removal: %s (role: %s, principal: %s)",
			[resource.address, role_name, grant.principal_id],
		),
		"severity": "medium",
	}
}

# Warn for sensitive Azure AD role activation (create/update)
warn contains result if {
	some resource in directory_role_changes
	role_name := resource.change.after.display_name
	role_name in sensitive_azuread_role_names

	result := {
		"msg": sprintf("Sensitive Azure AD role change: %s (role: %s)", [
			resource.address,
			role_name,
		]),
		"severity": "medium",
	}
}

# Warn for sensitive Azure AD role deactivation (delete)
warn contains result if {
	some resource in directory_role_deletions
	role_name := resource.change.before.display_name
	role_name in sensitive_azuread_role_names

	result := {
		"msg": sprintf("Sensitive Azure AD role deletion: %s (role: %s)", [
			resource.address,
			role_name,
		]),
		"severity": "medium",
	}
}
