#!/usr/bin/env bash
# Local CI orchestrator: single-suite execution with per-run target isolation.
# The entire script is intended to be wrapped once by run_bounded_tests.sh.

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

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_error "Required command not found: ${cmd}"
        exit 1
    fi
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${REPO_ROOT}"

RUN_ID="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
LOG_ROOT="${REPO_ROOT}/target/ci/orchestrator_logs"
LOG_DIR="${LOG_ROOT}/${RUN_ID}-$(date -u +%Y%m%dT%H%M%SZ)"
BUILD_TARGET_DIR="${APM2_CI_TARGET_DIR:-target/ci/target-build-${RUN_ID}}"
BUILD_LOG="${LOG_DIR}/build_all_targets.log"

mkdir -p "${LOG_DIR}"

log_info "=== Local CI Orchestrator ==="
log_info "Repo root: ${REPO_ROOT}"
log_info "Run ID: ${RUN_ID}"
log_info "Log dir: ${LOG_DIR}"
log_info "Per-run target dir: ${BUILD_TARGET_DIR}"

require_cmd cargo
require_cmd rustc
require_cmd protoc

if [[ "${APM2_CI_DRY_RUN:-0}" == "1" ]]; then
    log_warn "APM2_CI_DRY_RUN=1 set; skipping cargo build."
    exit 0
fi

log_info "START [build_all_targets] cargo build --workspace --all-features --all-targets --locked"
set +e
(
    set -euo pipefail
    cd "${REPO_ROOT}"
    CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" \
        cargo build --workspace --all-features --all-targets --locked
) > >(tee "${BUILD_LOG}") 2>&1
status=$?
set -e

if [[ ${status} -ne 0 ]]; then
    log_error "END   [build_all_targets] FAIL (${status})"
    log_warn "=== Failure Tail: build_all_targets ==="
    tail -n 160 "${BUILD_LOG}" || true
    log_error "Local CI orchestrator failed."
    exit "${status}"
fi

log_info "END   [build_all_targets] PASS"
log_info "Log file: ${BUILD_LOG}"
log_info "Local CI orchestrator passed."
exit 0
