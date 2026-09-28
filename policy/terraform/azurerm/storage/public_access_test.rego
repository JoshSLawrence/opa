package terraform.azurerm.storage_test

import rego.v1

import data.terraform.azurerm.storage

mock_create_storage_account_public_items := {"resource_changes": [{
	"address": "azurerm_storage_account.this",
	"type": "azurerm_storage_account",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"allow_nested_items_to_be_public": true},
	},
}]}

mock_update_storage_account_public_items := {"resource_changes": [{
	"address": "azurerm_storage_account.this",
	"type": "azurerm_storage_account",
	"change": {
		"actions": ["update"],
		"before": {"allow_nested_items_to_be_public": true},
		"after": {"allow_nested_items_to_be_public": true},
	},
}]}

mock_create_storage_account_public_network := {"resource_changes": [{
	"address": "azurerm_storage_account.this",
	"type": "azurerm_storage_account",
	"change": {
		"actions": ["create"],
		"before": null,
		"after": {"public_network_access": "Enabled"},
	},
}]}

mock_update_storage_account_public_network := {"resource_changes": [{
	"address": "azurerm_storage_account.this",
	"type": "azurerm_storage_account",
	"change": {
		"actions": ["update"],
		"before": {"public_network_access": "Disabled"},
		"after": {"public_network_access": "Enabled"},
	},
}]}

test_deny_storage_account_public_items_create if {
	result := storage.deny with input as mock_create_storage_account_public_items
	count(result) == 1
	some r in result
	contains(r.msg, "azurerm_storage_account.this")
	contains(r.msg, "allows nested items to be public")
	r.severity == "high"
}

test_deny_storage_account_public_items_update if {
	result := storage.deny with input as mock_update_storage_account_public_items
	count(result) == 1
	some r in result
	contains(r.msg, "azurerm_storage_account.this")
	contains(r.msg, "allows nested items to be public")
	r.severity == "high"
}

test_deny_storage_account_public_network_create if {
	result := storage.deny with input as mock_create_storage_account_public_network
	count(result) == 1
	some r in result
	contains(r.msg, "azurerm_storage_account.this")
	contains(r.msg, "public network access enabled")
	r.severity == "high"
}

test_deny_storage_account_public_network_update if {
	result := storage.deny with input as mock_update_storage_account_public_network
	count(result) == 1
	some r in result
	contains(r.msg, "azurerm_storage_account.this")
	contains(r.msg, "public network access enabled")
	r.severity == "high"
}
