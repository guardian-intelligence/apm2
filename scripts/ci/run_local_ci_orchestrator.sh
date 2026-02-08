#!/usr/bin/env bash
# Local CI orchestrator: single GitHub job, local parallel checks, detailed logs.
# Designed for self-hosted execution where GitHub is status projection only.

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_info() { echo -e "${GREEN}INFO:${NC} $*"; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*"; }
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

LOG_ROOT="${REPO_ROOT}/target/ci/orchestrator_logs"
RUN_STAMP="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${LOG_ROOT}/${RUN_STAMP}"
mkdir -p "${LOG_DIR}"

declare -a CHECK_ORDER=()
declare -A CHECK_LOG=()
declare -A CHECK_CMD=()
declare -A CHECK_STATUS=()
OVERALL_FAILED=0

record_check_start() {
    local id="$1"
    local cmd="$2"
    CHECK_ORDER+=("${id}")
    CHECK_LOG["${id}"]="${LOG_DIR}/${id}.log"
    CHECK_CMD["${id}"]="${cmd}"
}

record_check_end() {
    local id="$1"
    local rc="$2"
    if [[ "${rc}" -eq 0 ]]; then
        CHECK_STATUS["${id}"]="PASS"
        log_info "END   [${id}] PASS"
    else
        CHECK_STATUS["${id}"]="FAIL(${rc})"
        OVERALL_FAILED=1
        log_error "END   [${id}] FAIL (${rc})"
    fi
}

run_serial_check() {
    local id="$1"
    local cmd="$2"
    local logfile="${LOG_DIR}/${id}.log"

    record_check_start "${id}" "${cmd}"
    log_info "START [${id}] ${cmd}"

    set +e
    (
        set -euo pipefail
        cd "${REPO_ROOT}"
        bash -lc "${cmd}"
    ) > >(tee "${logfile}") 2>&1
    local rc=$?
    set -e

    record_check_end "${id}" "${rc}"
}

run_parallel_group() {
    local group_name="$1"
    shift
    local -a entries=("$@")
    local -a ids=()
    local -a pids=()

    log_info "=== Parallel Group: ${group_name} ==="

    local entry id cmd logfile
    for entry in "${entries[@]}"; do
        id="${entry%%::*}"
        cmd="${entry#*::}"
        logfile="${LOG_DIR}/${id}.log"

        record_check_start "${id}" "${cmd}"
        log_info "START [${id}] ${cmd}"

        (
            set -euo pipefail
            cd "${REPO_ROOT}"
            bash -lc "${cmd}"
        ) > >(tee "${logfile}") 2>&1 &

        ids+=("${id}")
        pids+=("$!")
    done

    local i rc
    for i in "${!ids[@]}"; do
        set +e
        wait "${pids[$i]}"
        rc=$?
        set -e
        record_check_end "${ids[$i]}" "${rc}"
    done
}

print_summary() {
    echo
    log_info "=== CI Summary ==="
    echo "Logs: ${LOG_DIR}"
    local id status
    for id in "${CHECK_ORDER[@]}"; do
        status="${CHECK_STATUS[${id}]:-UNKNOWN}"
        printf '  %-28s %-10s %s\n' "${id}" "${status}" "${CHECK_LOG[${id}]}"
    done
}

print_failure_tails() {
    local id status
    for id in "${CHECK_ORDER[@]}"; do
        status="${CHECK_STATUS[${id}]:-UNKNOWN}"
        if [[ "${status}" == FAIL* ]]; then
            echo
            log_warn "=== Failure Tail: ${id} ==="
            tail -n 120 "${CHECK_LOG[${id}]}" || true
        fi
    done
}

log_info "=== Local CI Orchestrator ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Log dir: ${LOG_DIR}"

# Bootstrap dependencies once for the whole CI run.
run_serial_check "bootstrap" "
sudo apt-get update
sudo apt-get install -y protobuf-compiler ripgrep jq
if ! command -v cargo-nextest >/dev/null 2>&1; then cargo install cargo-nextest --locked; fi
if ! command -v cargo-deny >/dev/null 2>&1; then cargo install cargo-deny --locked; fi
if ! command -v cargo-audit >/dev/null 2>&1; then cargo install cargo-audit --locked; fi
rustup toolchain install 1.85 --profile minimal --no-self-update
"

# Fast static and guardrail checks in parallel.
run_parallel_group "static-guardrails" \
    "test_safety_guard::./scripts/ci/test_safety_guard.sh" \
    "legacy_ipc_guard::./scripts/ci/legacy_ipc_guard.sh" \
    "evidence_refs_lint::./scripts/ci/evidence_refs_lint.sh" \
    "test_refs_lint::./scripts/ci/test_refs_lint.sh" \
    "proto_enum_drift::./scripts/ci/proto_enum_drift.sh" \
    "review_artifact_lint::./scripts/ci/review_artifact_lint.sh" \
    "status_write_cmd_lint::./scripts/lint/no_direct_status_write_commands.sh"

# Compile-heavy checks are run serially to avoid memory spikes and keep logs clear.
run_serial_check "rustfmt" "cargo fmt --all --check"
run_serial_check "clippy" "cargo clippy --workspace --all-targets --all-features -- -D warnings"
run_serial_check "workspace_integrity_guard" "./scripts/ci/workspace_integrity_guard.sh --snapshot-file target/ci/workspace_integrity.snapshot.tsv -- ./scripts/ci/run_bounded_tests.sh --timeout-seconds 600 --kill-after-seconds 20 -- cargo nextest run --workspace --all-features --config-file .config/nextest.toml --profile ci"
run_serial_check "bounded_doctests" "./scripts/ci/run_bounded_tests.sh --timeout-seconds 600 --kill-after-seconds 20 -- cargo test --doc --workspace --all-features"
run_serial_check "test_vectors" "cargo test --package apm2-core --features test_vectors canonicalization"
run_serial_check "msrv_check" "cargo +1.85 check --workspace --all-features"
run_serial_check "cargo_deny" "cargo deny check all"
run_serial_check "cargo_audit" "cargo audit --ignore RUSTSEC-2023-0089"
run_serial_check "guardrail_fixtures" "./scripts/ci/test_guardrail_fixtures.sh"

print_summary

if [[ "${OVERALL_FAILED}" -ne 0 ]]; then
    print_failure_tails
    log_error "Local CI orchestrator failed."
    exit 1
fi

log_info "Local CI orchestrator passed."
exit 0
