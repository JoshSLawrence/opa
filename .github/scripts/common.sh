#!/usr/bin/env bash
# Common functions library for OPA policy pipeline scripts.
# Source this file in other scripts: source "$(dirname "$0")/common.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect if running in GitHub Actions (GITHUB_ACTIONS is set to "true")
is_github_actions() {
    [[ "${GITHUB_ACTIONS:-}" == "true" ]]
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Workflow commands go to stdout; GitHub surfaces them as annotations on the
# run summary and PR.
log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
    if is_github_actions; then
        echo "::warning::$1"
    fi
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    if is_github_actions; then
        echo "::error::$1"
    fi
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1" >&2
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Require a tool to be installed, exit if not found
require_tool() {
    local cmd="$1"
    local name="${2:-$cmd}"
    if ! command_exists "$cmd"; then
        log_error "$name is not installed. Please install $name to proceed."
        exit 1
    fi
}
