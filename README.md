# OPA Policies

Policy-as-code using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
and its policy language [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
(pronounced "ray-go").

## What Is This?

This repository contains **policies**—rules that validate input and return
results. Policies are evaluated by OPA, a general-purpose policy engine. Each
package defines its own output rules and conventions (e.g., `deny`, `allow`,
`require_review`)—see the package README for specifics.

You don't need to know Rego to **use** these policies. You just need to:

1. **Provide input** — structured data (JSON) representing what you want to
   validate (e.g., a Terraform plan)
2. **Query a package** — ask OPA to evaluate rules against your input
3. **Handle the output** — act on the results (block a PR, add reviewers, log
   warnings)

```text
┌─────────┐      ┌─────────────┐      ┌─────────┐
│  Input  │ ──── │  Policies   │ ──── │ Output  │
│ (JSON)  │      │   (Rego)    │      │ (JSON)  │
└─────────┘      └─────────────┘      └─────────┘
```

## Packages

Policies are organized into **packages** based on what they validate. Each
top-level package defines its own input format, output rules, and conventions.

> **Note:** You may see us refer to top-level packages like `terraform` as
> "namespaces" informally. This is just shorthand—Rego's official term is
> "package".

| Package | Description | Docs |
|---------|-------------|------|
| `terraform` | Terraform/OpenTofu plan validation | [policy/terraform/](policy/terraform/) |

When querying policies, you reference the package in the query path:

```bash
# Query the terraform.azurerm.roles package
opa eval -d ./policy -i input.json "data.terraform.azurerm.roles.warn"
#                                        ───────────────────────────────
#                                        package path             .rule
```

The result is JSON you can parse and handle as needed:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": ["Violation message 1", "Violation message 2"],
          "text": "data.terraform.azurerm.roles.warn"
        }
      ]
    }
  ]
}
```

> **Note:** Input format, output rules, and result structure vary by package.
> Always review the package README for specifics.

## Repository Structure

```text
policy/
├── lib/                            # Shared helpers
│   ├── common/                     # Helpers shared across all packages
│   └── <package>/                  # Package-specific helpers
└── <package>/                      # Top-level packages
    └── README.md                   # Package-specific docs (start here)
```

## Getting Started

1. **Find your package** — check the table above for what you're validating
2. **Read the package README** — each package documents its input format,
   output rules, and usage examples
3. **Call OPA** — pass your input and handle the results

## Quick Example

```bash
# Generate input (example: OpenTofu plan)
tofu plan -out=tfplan.bin
tofu show -json tfplan.bin > tfplan.json

# Evaluate policies
opa eval -d ./policy -i tfplan.json "data.terraform.azurerm.roles.warn"

# Handle the results (implement your own logic)
result=$(opa eval -d ./policy -i tfplan.json --format json \
  "data.terraform.azurerm.roles.warn")

handle_policy_result "$result"
# ^ your function: parse violations, block deployments, send alerts,
#   add PR reviewers, post to Slack, update dashboards, etc.
```

Since OPA outputs structured JSON, any language can consume policy results—bash,
Python, Go, JavaScript, etc.—to drive decisions in your code or automation.

## Contributing

Want to write or modify policies? See [CONTRIBUTING.md](CONTRIBUTING.md).
