# Agent Instructions

OPA Rego policy repository for validating Terraform/OpenTofu plans. Rule,
severity, and output-schema conventions are documented in
[policy/terraform/README.md](policy/terraform/README.md); authoring and testing
workflow is in [CONTRIBUTING.md](CONTRIBUTING.md). Read both before changing
policies.

## Conventions

- Rego v1 only: `import rego.v1`, `contains`, `if`, `some x in collection`
- Package names match directory paths with `policy/` stripped
  (`policy/terraform/azurerm/roles/foo.rego` → `package terraform.azurerm.roles`)
- `deny`/`warn` rules return objects with `msg` and `severity` keys (enforced by
  the custom Regal rule in `.regal/rules/custom/`); `require_review` returns
  `message` and `reviewers`
- Use `tofu`, not `terraform`, in CLI examples
- Never commit real tenant data (tenant, subscription, or principal IDs, or
  resource names) in policies or tests; use placeholder GUIDs such as
  `00000000-0000-0000-0000-000000000000`

## Setup

```bash
mise trust && mise install && pre-commit install
```

## Commands

```bash
opa test ./policy -v                    # Run all tests
opa fmt -w .                            # Auto-format
opa check --strict policy/              # Syntax check
regal lint --format compact policy/     # Lint
.github/scripts/validate-policies.sh    # Everything CI runs
```

## Directory Structure

```text
.github/
├── dependabot.yml
├── scripts/                          # CI scripts (runnable locally)
│   ├── common.sh
│   └── validate-policies.sh
└── workflows/
    └── validate.yaml                 # PR/push validation
.regal/                               # Regal lint config + custom rules
policy/
└── terraform/                        # Terraform plan policies (by provider)
    ├── azapi/
    │   └── roles/                    # package terraform.azapi.roles
    │       ├── role_assignments.rego
    │       └── role_assignments_test.rego
    ├── azuread/
    │   └── roles/                    # package terraform.azuread.roles
    │       ├── directory_roles.rego
    │       └── directory_roles_test.rego
    └── azurerm/
        ├── roles/                    # package terraform.azurerm.roles
        │   ├── protected_roles.rego
        │   └── protected_roles_test.rego
        └── storage/                  # package terraform.azurerm.storage
            ├── public_access.rego
            └── public_access_test.rego
```

Policies are namespaced **by provider** (`azapi`, `azuread`, `azurerm`), then
subdivided by concern (e.g. `roles`, `storage`). Test files are `*_test.rego`
alongside policies; shared helpers go in `policy/lib/<package>/` only if
needed.

## Pre-commit Hooks and CI

Hooks run `opa fmt`, `opa check --strict`, `regal lint`, `opa test`, and
`shellcheck`. The GitHub Actions workflow runs the same Rego checks via
`.github/scripts/validate-policies.sh`. Fix formatting with `opa fmt -w .`
before committing.
