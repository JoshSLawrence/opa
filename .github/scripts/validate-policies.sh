#!/usr/bin/env bash
set -euo pipefail

# Validate OPA policies: formatting, syntax, linting, and tests.
# Mirrors pre-commit hooks for CI consistency.

# Source common functions
# shellcheck source=.github/scripts/common.sh
source "$(dirname "$0")/common.sh"

log_info "Checking formatting with opa fmt"
if ! opa fmt --diff --fail policy/; then
    log_error "Formatting check failed. Run 'opa fmt -w .' locally to fix."
    exit 1
fi

log_info "Checking syntax with opa check --strict"
opa check --strict policy/

log_info "Linting with regal"
regal lint --format compact policy/

log_info "Running tests with opa test"
opa test ./policy -v

log_info "All validations passed"
