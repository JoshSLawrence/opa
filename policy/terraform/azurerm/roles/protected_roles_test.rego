package terraform.azurerm.roles_test

import rego.v1

import data.terraform.azurerm.roles as security

# =============================================================================
# Test fixtures
#
# These mocks mirror the structure of `tofu show -json` output. To test with
# real data, replace any fixture with sanitized output from a real plan:
#
#   tofu show -json plan.out | jq '{resource_changes: [.resource_changes[] | select(...)]}'
#
# =============================================================================

# -----------------------------------------------------------------------------
# Create actions
# -----------------------------------------------------------------------------

mock_create_owner := {"resource_changes": [{
	"address": "azurerm_role_assignment.owner",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"role_definition_name": "Owner"},
	},
}]}

mock_create_user_access_admin := {"resource_changes": [{
	"address": "azurerm_role_assignment.uaa",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"role_definition_name": "User Access Administrator"},
	},
}]}

mock_create_contributor := {"resource_changes": [{
	"address": "azurerm_role_assignment.contributor",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"role_definition_name": "Contributor"},
	},
}]}

mock_create_reader := {"resource_changes": [{
	"address": "azurerm_role_assignment.reader",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"role_definition_name": "Reader"},
	},
}]}

# -----------------------------------------------------------------------------
# Update actions
# -----------------------------------------------------------------------------

mock_update_owner := {"resource_changes": [{
	"address": "azurerm_role_assignment.owner",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["update"],
		"before": {"role_definition_name": "Owner"},
		"after": {"role_definition_name": "Owner"},
	},
}]}

mock_update_user_access_admin := {"resource_changes": [{
	"address": "azurerm_role_assignment.uaa",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["update"],
		"before": {"role_definition_name": "User Access Administrator"},
		"after": {"role_definition_name": "User Access Administrator"},
	},
}]}

mock_update_contributor := {"resource_changes": [{
	"address": "azurerm_role_assignment.contributor",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["update"],
		"before": {"role_definition_name": "Contributor"},
		"after": {"role_definition_name": "Contributor"},
	},
}]}

mock_update_reader := {"resource_changes": [{
	"address": "azurerm_role_assignment.reader",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["update"],
		"before": {"role_definition_name": "Reader"},
		"after": {"role_definition_name": "Reader"},
	},
}]}

# -----------------------------------------------------------------------------
# Delete actions
# -----------------------------------------------------------------------------

mock_delete_owner := {"resource_changes": [{
	"address": "azurerm_role_assignment.owner",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["delete"],
		"before": {"role_definition_name": "Owner"},
		"after": null,
	},
}]}

mock_delete_user_access_admin := {"resource_changes": [{
	"address": "azurerm_role_assignment.uaa",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["delete"],
		"before": {"role_definition_name": "User Access Administrator"},
		"after": null,
	},
}]}

mock_delete_contributor := {"resource_changes": [{
	"address": "azurerm_role_assignment.contributor",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["delete"],
		"before": {"role_definition_name": "Contributor"},
		"after": null,
	},
}]}

mock_delete_reader := {"resource_changes": [{
	"address": "azurerm_role_assignment.reader",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["delete"],
		"before": {"role_definition_name": "Reader"},
		"after": null,
	},
}]}

# -----------------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------------

mock_noop_owner := {"resource_changes": [{
	"address": "azurerm_role_assignment.owner",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["no-op"],
		"before": {"role_definition_name": "Owner"},
		"after": {"role_definition_name": "Owner"},
	},
}]}

mock_missing_role_name := {"resource_changes": [{
	"address": "azurerm_role_assignment.test",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {},
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
# Tests - Create actions warn
# =============================================================================

test_create_owner_warns if {
	result := security.warn with input as mock_create_owner
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_create_user_access_admin_warns if {
	result := security.warn with input as mock_create_user_access_admin
	count(result) == 1
	some r in result
	contains(r.msg, "User Access Administrator")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_create_contributor_warns if {
	result := security.warn with input as mock_create_contributor
	count(result) == 1
	some r in result
	contains(r.msg, "Contributor")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_create_reader_no_warn if {
	result := security.warn with input as mock_create_reader
	count(result) == 0
}

# =============================================================================
# Tests - Update actions warn
# =============================================================================

test_update_owner_warns if {
	result := security.warn with input as mock_update_owner
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_update_user_access_admin_warns if {
	result := security.warn with input as mock_update_user_access_admin
	count(result) == 1
	some r in result
	contains(r.msg, "User Access Administrator")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_update_contributor_warns if {
	result := security.warn with input as mock_update_contributor
	count(result) == 1
	some r in result
	contains(r.msg, "Contributor")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_update_reader_no_warn if {
	result := security.warn with input as mock_update_reader
	count(result) == 0
}

# =============================================================================
# Tests - Delete actions warn
# =============================================================================

test_delete_owner_warns if {
	result := security.warn with input as mock_delete_owner
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
	contains(r.msg, "deletion")
	r.severity == "medium"
}

test_delete_user_access_admin_warns if {
	result := security.warn with input as mock_delete_user_access_admin
	count(result) == 1
	some r in result
	contains(r.msg, "User Access Administrator")
	contains(r.msg, "deletion")
	r.severity == "medium"
}

test_delete_contributor_warns if {
	result := security.warn with input as mock_delete_contributor
	count(result) == 1
	some r in result
	contains(r.msg, "Contributor")
	contains(r.msg, "deletion")
	r.severity == "medium"
}

test_delete_reader_no_warn if {
	result := security.warn with input as mock_delete_reader
	count(result) == 0
}

# =============================================================================
# Tests - Edge cases
# =============================================================================

test_noop_no_warn if {
	result := security.warn with input as mock_noop_owner
	count(result) == 0
}

test_missing_role_name_no_warn if {
	result := security.warn with input as mock_missing_role_name
	count(result) == 0
}

test_other_resource_no_warn if {
	result := security.warn with input as mock_other_resource
	count(result) == 0
}

# =============================================================================
# Tests - Result structure
# =============================================================================

test_warn_message_includes_address if {
	result := security.warn with input as mock_create_owner
	some r in result
	contains(r.msg, "azurerm_role_assignment.owner")
}

test_warn_result_has_required_keys if {
	result := security.warn with input as mock_create_owner
	some r in result
	r.msg
	r.severity
}
