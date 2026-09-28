package terraform.azuread.roles_test

import rego.v1

import data.terraform.azuread.roles

# =============================================================================
# Test fixtures
#
# These mocks mirror the structure of `tofu show -json` output. To test with
# real data, replace any fixture with sanitized output from a real plan:
#
#   tofu show -json plan.out | jq '{resource_changes: [.resource_changes[] | select(...)]}'
#
# The `azuread_directory_role` resource (role activation) is matched by
# `display_name`. Role grants — `azuread_directory_role_assignment` and
# `azuread_directory_role_eligibility_schedule_request` — are matched by the
# built-in role template ID and carry the principal being granted the role.
# =============================================================================

global_admin_template_id := "62e90394-69f5-4237-9190-012177145e10"

directory_reader_template_id := "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"

# The principal (here a role-assignable group) being granted the role.
grant_principal := "11111111-2222-3333-4444-555555555555"

mock_create_global_admin := {"resource_changes": [{
	"address": "azuread_directory_role.this[\"Global Administrator\"]",
	"type": "azuread_directory_role",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"display_name": "Global Administrator"},
	},
}]}

mock_delete_global_admin := {"resource_changes": [{
	"address": "azuread_directory_role.this[\"Global Administrator\"]",
	"type": "azuread_directory_role",
	"change": {
		"actions": ["delete"],
		"before": {"display_name": "Global Administrator"},
		"after": null,
	},
}]}

mock_create_directory_reader := {"resource_changes": [{
	"address": "azuread_directory_role.this[\"Directory Readers\"]",
	"type": "azuread_directory_role",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"display_name": "Directory Readers"},
	},
}]}

# azuread_directory_role_assignment granting Global Administrator.
mock_assign_global_admin := {"resource_changes": [{
	"address": "azuread_directory_role_assignment.ga",
	"type": "azuread_directory_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"role_id": global_admin_template_id,
			"principal_object_id": grant_principal,
		},
	},
}]}

mock_delete_assign_global_admin := {"resource_changes": [{
	"address": "azuread_directory_role_assignment.ga",
	"type": "azuread_directory_role_assignment",
	"change": {
		"actions": ["delete"],
		"before": {
			"role_id": global_admin_template_id,
			"principal_object_id": grant_principal,
		},
		"after": null,
	},
}]}

# azuread_directory_role_assignment for a non-sensitive role.
mock_assign_directory_reader := {"resource_changes": [{
	"address": "azuread_directory_role_assignment.reader",
	"type": "azuread_directory_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"role_id": directory_reader_template_id,
			"principal_object_id": grant_principal,
		},
	},
}]}

# PIM eligibility request making a principal eligible for Global Administrator.
mock_eligible_global_admin := {"resource_changes": [{
	"address": "azuread_directory_role_eligibility_schedule_request.ga",
	"type": "azuread_directory_role_eligibility_schedule_request",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"role_definition_id": global_admin_template_id,
			"principal_id": grant_principal,
		},
	},
}]}

mock_other_resource := {"resource_changes": [{
	"address": "azurerm_virtual_machine.test",
	"type": "azurerm_virtual_machine",
	"change": {
		"actions": ["create"],
		"after": {"name": "test-vm"},
	},
}]}

# =============================================================================
# Tests - directory role activation
# =============================================================================

test_create_global_admin_warns if {
	result := roles.warn with input as mock_create_global_admin
	count(result) == 1
	some r in result
	contains(r.msg, "Global Administrator")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_delete_global_admin_warns if {
	result := roles.warn with input as mock_delete_global_admin
	count(result) == 1
	some r in result
	contains(r.msg, "Global Administrator")
	contains(r.msg, "deletion")
	r.severity == "medium"
}

test_create_directory_reader_no_warn if {
	result := roles.warn with input as mock_create_directory_reader
	count(result) == 0
}

# =============================================================================
# Tests - role grants (assignment + eligibility)
# =============================================================================

test_assign_global_admin_warns if {
	result := roles.warn with input as mock_assign_global_admin
	count(result) == 1
	some r in result
	contains(r.msg, "Global Administrator")
	contains(r.msg, grant_principal)
	r.severity == "medium"
}

test_delete_assign_global_admin_warns if {
	result := roles.warn with input as mock_delete_assign_global_admin
	count(result) == 1
	some r in result
	contains(r.msg, "removal")
}

test_eligible_global_admin_warns if {
	result := roles.warn with input as mock_eligible_global_admin
	count(result) == 1
	some r in result
	contains(r.msg, "Global Administrator")
	contains(r.msg, grant_principal)
}

test_assign_directory_reader_no_warn if {
	result := roles.warn with input as mock_assign_directory_reader
	count(result) == 0
}

test_other_resource_no_warn if {
	result := roles.warn with input as mock_other_resource
	count(result) == 0
}

# =============================================================================
# Tests - Result structure
# =============================================================================

test_warn_message_includes_address if {
	result := roles.warn with input as mock_create_global_admin
	some r in result
	contains(r.msg, "azuread_directory_role.this[\"Global Administrator\"]")
}

test_warn_result_has_required_keys if {
	result := roles.warn with input as mock_create_global_admin
	some r in result
	r.msg
	r.severity
}
