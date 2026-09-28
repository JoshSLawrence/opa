# Contributing

## Prerequisites

- [mise](https://mise.jdx.dev/getting-started.html)

> **Note:** Windows users should use
> [WSL](https://learn.microsoft.com/en-us/windows/wsl/install).
> [VS Code supports WSL](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-vscode).

## Editor Setup

Install [Regal](https://docs.styra.com/regal) for real-time linting and
language support:

- **VS Code**: Install the
  [OPA extension](https://marketplace.visualstudio.com/items?itemName=tsandall.opa)
  (v0.13.3+) which includes Regal support
- **Other editors**: See
  [Regal editor support](https://www.openpolicyagent.org/projects/regal/editor-support)

The repo includes `.regal/config.yaml` which configures linting rules, including
package naming to match our directory structure.

## Getting Started

Trust the mise config (required on first clone), then install all tools and hooks:

```bash
mise trust
mise install
pre-commit install
```

## Writing Policies

All policies use Rego v1. Include `import rego.v1` at the top of each file.

> **Note:** Many community examples use legacy Rego syntax. If adapting external
> policies, update them to v1 conventions (`import rego.v1`, `contains`,
> `if`, `some x in collection` instead of `[_]`).

Package declarations match the directory path (with `policy/` stripped):

```text
policy/
└── terraform/
    └── azurerm/
        └── roles/
            └── protected_roles.rego    → package terraform.azurerm.roles
```

## Policy Output Rules

Each package defines its own output conventions (e.g., `deny`, `warn`,
`require_review`). Before contributing to a package, review its README for the
expected output rules and schema.

Package READMEs are located at `policy/<package>/README.md`.

## Shared Helpers

If you find yourself duplicating logic across multiple policies, consider
extracting it into a shared helper under `policy/lib/`. See
`policy/terraform/README.md` for the recommended structure.

> **Note:** Prefer plain Rego over abstractions. Only create helpers when
> there's clear, repeated boilerplate.

## Testing

All policies must include unit tests in `*_test.rego` files alongside the
policy file.

```text
policy/terraform/azurerm/roles/
├── protected_roles.rego
└── protected_roles_test.rego
```

> **Note:** If you ran `pre-commit install` during setup, hooks run
> `opa test ./policy` and `regal lint` automatically on every commit. Regal
> enforces the output schema for `deny`/`warn` rules. Use these commands to run
> tests manually.

```bash
# Run all tests
opa test ./policy -v

# Run tests for a specific package (by directory)
opa test ./policy/terraform/ -v              # All terraform policies
opa test ./policy/terraform/azurerm/ -v      # azurerm provider only
```

## Formatting

Pre-commit hooks validate formatting automatically. To fix files manually:

```bash
opa fmt -w .
```

> **Tip:** Enable format on save in your editor to avoid thinking about
> formatting entirely. The OPA extension for VS Code supports this.

## Workflow

1. Add policies under the appropriate package directory
2. Include corresponding `*_test.rego` files
3. Iterate — run tests on your package for faster feedback during development
4. Commit — pre-commit hooks run formatting, linting, and **all tests**
5. Open a pull request — the `Validate` GitHub Actions workflow re-runs the same
   checks

## Continuous Integration

`.github/workflows/validate.yaml` runs
`.github/scripts/validate-policies.sh` on every pull request and push to
`main`. The script works locally too, so you can reproduce a CI failure with:

```bash
.github/scripts/validate-policies.sh
```
