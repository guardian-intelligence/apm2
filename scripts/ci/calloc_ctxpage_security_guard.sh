#!/usr/bin/env bash
# Security regression harness for calloc + ctxpage.
# - Fails closed if expected security tests are missing.
# - Executes targeted security-prefixed tests in each crate.
# - Runs test safety lint over touched crates and this harness script.

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

if ! command -v rg >/dev/null 2>&1; then
    log_error "ripgrep (rg) is required."
    exit 2
fi

run_security_tests_for_crate() {
    local crate="$1"
    local list_output
    list_output="$(cargo test -p "${crate}" -- --list 2>&1)"
    if ! printf '%s\n' "${list_output}" | rg -q 'security_'; then
        log_error "no security_ tests discovered for crate '${crate}' (fail-closed)"
        exit 2
    fi

    log_info "running security tests for ${crate}"
    cargo test -p "${crate}" security_
}

run_security_tests_for_crate "ctxpage"
run_security_tests_for_crate "calloc"

log_info "running test safety guard over calloc/ctxpage surfaces"
./scripts/ci/test_safety_guard.sh crates/calloc crates/ctxpage scripts/ci/calloc_ctxpage_security_guard.sh

log_info "calloc + ctxpage security harness completed successfully"
