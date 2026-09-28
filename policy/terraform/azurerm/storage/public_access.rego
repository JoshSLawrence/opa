package terraform.azurerm.storage

import rego.v1

deny contains result if {
	some resource in input.resource_changes
	resource.type == "azurerm_storage_account"
	some action in resource.change.actions
	action in ["create", "update"]
	resource.change.after.allow_nested_items_to_be_public == true
	result := {
		"msg": sprintf("Storage account %s allows nested items to be public", [
			resource.address,
		]),
		"severity": "high",
	}
}

deny contains result if {
	some resource in input.resource_changes
	resource.type == "azurerm_storage_account"
	some action in resource.change.actions
	action in ["create", "update"]
	resource.change.after.public_network_access == "Enabled"
	result := {
		"msg": sprintf("Storage account %s has public network access enabled", [
			resource.address,
		]),
		"severity": "high",
	}
}
