# Terraform Policies

OPA policies for validating Terraform/OpenTofu plans.

> **Note:** Package names use `terraform.*` to follow community conventions.
> We use OpenTofu, which produces an identical plan JSON format.

## Structure

Policies are namespaced **by provider** first, then subdivided by concern as
needed:

```text
terraform/
├── azapi/                      # package terraform.azapi.*
│   └── roles/                  # package terraform.azapi.roles
│       └── role_assignments.rego
├── azuread/                    # package terraform.azuread.*
│   └── roles/                  # package terraform.azuread.roles
│       └── directory_roles.rego
└── azurerm/                    # package terraform.azurerm.*
    ├── roles/                  # package terraform.azurerm.roles
    │   └── protected_roles.rego
    └── storage/                # package terraform.azurerm.storage
        └── public_access.rego
```

## Provider Namespacing

The top-level package segment is the **provider name**. Each Azure-related
provider gets its own namespace rather than folding everything into one
"Azure" package:

| Provider | Resource Prefix | Namespace |
|----------|-----------------|-----------|
| `azurerm` | `azurerm_*` | `terraform.azurerm.*` |
| `azuread` | `azuread_*` | `terraform.azuread.*` |
| `azapi` | `azapi_resource`, `azapi_update_resource` | `terraform.azapi.*` |

The same logical concern may therefore span packages. Roles, for example, are
enforced separately per provider because each expresses them differently — the
`roles` subpackage under each provider handles that provider's flavor:

- `azurerm_role_assignment` → `terraform.azurerm.roles`
- `azuread_directory_role` / `_assignment` / `_eligibility_schedule_request` →
  `terraform.azuread.roles`
- `azapi_resource` (type `Microsoft.Authorization/roleAssignments@*`) →
  `terraform.azapi.roles`

Keep the sensitive-role lists in these packages in sync when adding a role to
one of them.

## Policy Output Rules

All policies in the `terraform.*` package must output to these rules:

| Rule | Type | Pipeline Behavior |
|------|------|-------------------|
| `deny` | `set[object]` | Blocks PR, fails pipeline |
| `warn` | `set[object]` | Logs warning, PR proceeds |
| `require_review` | `set[object]` | Adds required reviewers |

These are conventions interpreted by the CI pipeline, not Rego keywords.

### Output Schema

All `deny` and `warn` rules must return structured objects with `msg` and
`severity` keys:

```rego
deny contains result if {
    ...
    result := {
        "msg": "Human-readable explanation",
        "severity": "critical",
    }
}

warn contains result if {
    ...
    result := {
        "msg": "Advisory message",
        "severity": "medium",
    }
}

# require_review returns objects with message and reviewers
require_review contains result if {
    ...
    result := {
        "message": "Human-readable explanation",
        "reviewers": ["team-or-user"],
    }
}
```

### Severity Levels

| Severity | Use Case |
|----------|----------|
| `critical` | Security vulnerabilities, data exposure, compliance violations |
| `high` | Significant risk, requires immediate attention |
| `medium` | Moderate risk, should be addressed |
| `low` | Minor issues, best practice recommendations |

## Usage

Generate a plan and convert to JSON:

```bash
tofu plan -out=tfplan.bin
tofu show -json tfplan.bin > tfplan.json
```

Evaluate policies against the plan:

```bash
opa eval -d ./policy -i tfplan.json "data.terraform.azurerm.roles.warn"
```

<!-- markdownlint-disable MD013 -->

| Flag | Description |
|------|-------------|
| `-d ./policy` | Load all Rego policies from the policy directory |
| `-i tfplan.json` | Use the OpenTofu plan JSON as input |
| `"data.terraform.azurerm.roles.warn"` | Query the `warn` rules in the `terraform.azurerm.roles` package |

<!-- markdownlint-enable MD013 -->

If any `deny` rules match, the output contains the violation messages.
An empty result means no violations.

## Shared Helpers

If you find yourself duplicating logic across multiple policies, consider
extracting it into a shared helper library under `policy/lib/`. Use the
following structure:

```text
policy/
├── lib/
│   └── terraform/
│       └── <helper_name>/
│           ├── <helper_name>.rego       # package lib.terraform.<helper_name>
│           └── <helper_name>_test.rego
└── terraform/
    └── ...
```

Import helpers with `import data.lib.terraform.<helper_name>`.

> **Note:** Prefer plain Rego over abstractions. Only create helpers when
> there's clear, repeated boilerplate across multiple policies.
