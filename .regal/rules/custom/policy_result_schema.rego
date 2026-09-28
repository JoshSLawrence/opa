# METADATA
# description: |
#   Ensures deny and warn rules in terraform.* packages return structured
#   objects with required "msg" and "severity" keys.
# related_resources:
#   - description: Policy output rules
#     ref: policy/terraform/README.md
# schemas:
#   - input: schema.regal.ast
package custom.regal.rules.policy.policy_result_schema

import rego.v1

import data.regal.result

# Only check files in terraform.* packages
_is_terraform_package if {
	some i
	input.package.path[i].value == "terraform"
}

# Rule names that require structured output
_policy_rule_names := {"deny", "warn"}

# Required keys in the result object
_required_keys := {"msg", "severity"}

# Find deny/warn rules that don't have proper result schema
report contains violation if {
	_is_terraform_package

	some rule in input.rules
	_is_policy_rule(rule)

	not _has_valid_result_assignment(rule)

	violation := result.fail(rego.metadata.chain(), result.location(rule.head))
}

# Check if rule is a deny or warn rule
_is_policy_rule(rule) if {
	rule.head.ref[0].value in _policy_rule_names
	rule.head.key # Must be a "contains" rule (has a key)
}

# Check if rule body has a valid result assignment with required keys
_has_valid_result_assignment(rule) if {
	key_var := rule.head.key.value

	some expr in rule.body
	_is_assignment(expr)
	expr.terms[1].value == key_var
	expr.terms[2].type == "object"

	obj_keys := {k.value | some pair in expr.terms[2].value; k := pair[0]}

	# Check all required keys are present (subset check via intersection)
	_required_keys & obj_keys == _required_keys
}

# Check if expression is an assignment
_is_assignment(expr) if {
	expr.terms[0].type == "ref"
	expr.terms[0].value[0].value == "assign"
}
