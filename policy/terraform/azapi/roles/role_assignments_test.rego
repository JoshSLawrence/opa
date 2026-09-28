package terraform.azapi.roles_test

import rego.v1

import data.terraform.azapi.roles

# =============================================================================
# Test fixtures
#
# These mocks mirror the structure of `tofu show -json` output for the azapi
# provider's raw `Microsoft.Authorization/roleAssignments` resource. The role
# is referenced by its definition ID, whose trailing GUID identifies the
# built-in role.
#
#   Owner       8e3af657-a8ff-443c-a75c-2fe8c4bcb635
#   Contributor b24988ac-6180-42a0-ab88-20f7382dd24c
#   Reader      acdd72a7-3385-48ef-bd42-f606fba81ae7 (not sensitive)
# =============================================================================

_role_def_prefix := "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions"

owner_role_id := sprintf("%s/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", [_role_def_prefix])

contributor_role_id := sprintf("%s/b24988ac-6180-42a0-ab88-20f7382dd24c", [_role_def_prefix])

reader_role_id := sprintf("%s/acdd72a7-3385-48ef-bd42-f606fba81ae7", [_role_def_prefix])

# azapi v2: body is a decoded object.
mock_create_owner := {"resource_changes": [{
	"address": "azapi_resource.owner",
	"type": "azapi_resource",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": owner_role_id}},
		},
	},
}]}

# azapi v1: body is a JSON-encoded string.
mock_create_owner_string_body := {"resource_changes": [{
	"address": "azapi_resource.owner_v1",
	"type": "azapi_resource",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"type": "Microsoft.Authorization/roleAssignments@2020-04-01-preview",
			"body": json.marshal({"properties": {"roleDefinitionId": owner_role_id}}),
		},
	},
}]}

mock_update_contributor := {"resource_changes": [{
	"address": "azapi_resource.contributor",
	"type": "azapi_resource",
	"change": {
		"actions": ["update"],
		"before": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": contributor_role_id}},
		},
		"after": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": contributor_role_id}},
		},
	},
}]}

mock_update_resource_owner := {"resource_changes": [{
	"address": "azapi_update_resource.owner",
	"type": "azapi_update_resource",
	"change": {
		"actions": ["update"],
		"before": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": owner_role_id}},
		},
		"after": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": owner_role_id}},
		},
	},
}]}

# Non-sensitive built-in role.
mock_create_reader := {"resource_changes": [{
	"address": "azapi_resource.reader",
	"type": "azapi_resource",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"type": "Microsoft.Authorization/roleAssignments@2022-04-01",
			"body": {"properties": {"roleDefinitionId": reader_role_id}},
		},
	},
}]}

# azapi resource that is not a role assignment.
mock_create_storage_account := {"resource_changes": [{
	"address": "azapi_resource.storage",
	"type": "azapi_resource",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {
			"type": "Microsoft.Storage/storageAccounts@2023-01-01",
			"body": {"properties": {}},
		},
	},
}]}

# Owner via the azurerm provider is out of scope for this package.
mock_azurerm_owner := {"resource_changes": [{
	"address": "azurerm_role_assignment.owner",
	"type": "azurerm_role_assignment",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"role_definition_name": "Owner"},
	},
}]}

# =============================================================================
# Tests
# =============================================================================

test_create_owner_warns if {
	result := roles.warn with input as mock_create_owner
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
	contains(r.msg, "change")
	r.severity == "medium"
}

test_create_owner_string_body_warns if {
	result := roles.warn with input as mock_create_owner_string_body
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
}

test_update_contributor_warns if {
	result := roles.warn with input as mock_update_contributor
	count(result) == 1
	some r in result
	contains(r.msg, "Contributor")
	contains(r.msg, "change")
}

test_update_resource_owner_warns if {
	result := roles.warn with input as mock_update_resource_owner
	count(result) == 1
	some r in result
	contains(r.msg, "Owner")
}

test_create_reader_no_warn if {
	result := roles.warn with input as mock_create_reader
	count(result) == 0
}

test_storage_account_no_warn if {
	result := roles.warn with input as mock_create_storage_account
	count(result) == 0
}

test_azurerm_owner_out_of_scope if {
	result := roles.warn with input as mock_azurerm_owner
	count(result) == 0
}

test_warn_message_includes_address if {
	result := roles.warn with input as mock_create_owner
	some r in result
	contains(r.msg, "azapi_resource.owner")
}

test_warn_result_has_required_keys if {
	result := roles.warn with input as mock_create_owner
	some r in result
	r.msg
	r.severity
}
