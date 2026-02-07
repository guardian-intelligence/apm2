#!/usr/bin/env bash
# CI drift guard: validate review artifact integrity (TCK-00409)
#
# Checks that:
# 1. Review prompt files do not contain deprecated direct status-write commands
#    that bypass the approved review gate path
# 2. Review metadata templates require exact PR number and head SHA binding
#
# Exit codes:
#   0 - All review artifacts are compliant
#   1 - Violations found
#   2 - Script error
#
# Usage:
#   ./scripts/ci/review_artifact_lint.sh

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

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

check_dependencies() {
    if ! command -v rg &>/dev/null; then
        log_error "ripgrep (rg) is required but not installed."
        exit 2
    fi
}

VIOLATIONS=0

REPO_ROOT="$(git rev-parse --show-toplevel)"
REVIEW_DIR="${REPO_ROOT}/documents/reviews"
REVIEW_GATE_DIR="${REPO_ROOT}/.github/review-gate"

if [[ ! -d "$REVIEW_DIR" ]]; then
    log_error "Review directory not found: ${REVIEW_DIR} (are you inside the repository?)"
    exit 2
fi

log_info "=== Review Artifact Integrity Lint (TCK-00409) ==="
echo

check_dependencies

# Check 1: Review prompts must not contain deprecated direct status-write commands.
# The approved path is through the review gate (gh pr comment + cargo xtask).
# Direct gh api calls to set statuses bypass the gate.
log_info "Checking for deprecated direct status-write patterns in review scripts..."

# Patterns that indicate direct status-write commands.
# We search broadly, then filter out approved uses that bind to $reviewed_sha.
STATUS_WRITE_PATTERNS=(
    'gh api.*(statuses.*--method POST|--method POST.*statuses)'
    'gh api.*statuses.*state=.success'
    'gh api.*(check-runs.*--method POST|--method POST.*check-runs)'
    'gh pr review.*--approve'
)

for pattern in "${STATUS_WRITE_PATTERNS[@]}"; do
    # Search only in review prompt/script files, not in this lint script itself.
    # Do NOT suppress rg errors — the script must fail-closed on regex failure.
    rg_exit=0
    matches=$(rg -l "$pattern" "$REVIEW_DIR" 2>&1) || rg_exit=$?
    if [[ $rg_exit -eq 2 ]]; then
        log_error "ripgrep failed on pattern: $pattern"
        exit 2
    fi
    if [[ $rg_exit -eq 1 ]]; then
        # exit code 1 means no matches — continue to next pattern
        continue
    fi
    if [[ -n "$matches" ]]; then
        for match_file in $matches; do
            # Get all matching lines; fail-closed on rg error
            rg_exit=0
            violating_lines=$(rg -n "$pattern" "$match_file" 2>&1) || rg_exit=$?
            if [[ $rg_exit -eq 2 ]]; then
                log_error "ripgrep failed on pattern: $pattern in $match_file"
                exit 2
            fi
            if [[ $rg_exit -eq 1 ]]; then
                continue
            fi
            if [[ -n "$violating_lines" ]]; then
                # Allow the approved pattern: posting status with $reviewed_sha
                safe=$(echo "$violating_lines" | grep -c '\$reviewed_sha\|"$reviewed_sha"' || true)
                total=$(echo "$violating_lines" | wc -l)
                if [[ $safe -lt $total ]]; then
                    log_error "Deprecated status-write bypassing review gate in: $match_file"
                    echo "$violating_lines" | grep -v '\$reviewed_sha' | while read -r line; do
                        log_error "  $line"
                    done
                    VIOLATIONS=1
                fi
            fi
        done
    fi
done

# Check 2: Review prompt metadata templates must require head_sha and pr_number binding.
# Both CODE_QUALITY_PROMPT.md and SECURITY_REVIEW_PROMPT.md must contain
# metadata block constraints that enforce SHA pinning.
log_info "Checking review prompt metadata SHA-pinning constraints..."

REVIEW_PROMPTS=(
    "${REVIEW_DIR}/CODE_QUALITY_PROMPT.md"
    "${REVIEW_DIR}/SECURITY_REVIEW_PROMPT.md"
)

for prompt_file in "${REVIEW_PROMPTS[@]}"; do
    if [[ ! -f "$prompt_file" ]]; then
        log_warn "Review prompt not found: ${prompt_file}"
        continue
    fi

    # Verify the metadata template contains head_sha field AND exact-binding constraint
    if ! grep -q '"head_sha"' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing head_sha metadata field"
        VIOLATIONS=1
    fi
    if ! grep -q 'head_sha.*MUST.*equal\|head_sha.*MUST.*reviewed_sha\|head_sha.*equal.*reviewed_sha' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing exact-binding constraint for head_sha (must require equality to reviewed_sha)"
        VIOLATIONS=1
    fi

    # Verify the metadata template contains pr_number field AND exact-binding constraint
    if ! grep -q '"pr_number"' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing pr_number metadata field"
        VIOLATIONS=1
    fi
    if ! grep -q 'pr_number.*MUST.*equal\|pr_number.*MUST.*match\|pr_number.*exact' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} missing exact-binding constraint for pr_number (must require exact match)"
        VIOLATIONS=1
    fi

    # Verify reviewed_sha is assigned from headRefOid
    if ! grep -q 'reviewed_sha.*headRefOid\|Set reviewed_sha = headRefOid' "$prompt_file" 2>/dev/null; then
        log_error "Review prompt ${prompt_file} does not bind reviewed_sha to headRefOid"
        VIOLATIONS=1
    fi

    log_info "  ${prompt_file}: metadata constraints present"
done

# Check 3: trusted-reviewers.json must exist and be valid JSON
log_info "Checking trusted-reviewers.json integrity..."
TRUSTED_REVIEWERS="${REVIEW_GATE_DIR}/trusted-reviewers.json"
if [[ ! -f "$TRUSTED_REVIEWERS" ]]; then
    log_error "Missing trusted-reviewers.json at ${TRUSTED_REVIEWERS}"
    VIOLATIONS=1
else
    if ! python3 -c "import json; json.load(open('${TRUSTED_REVIEWERS}'))" 2>/dev/null; then
        log_error "Invalid JSON in ${TRUSTED_REVIEWERS}"
        VIOLATIONS=1
    else
        log_info "  ${TRUSTED_REVIEWERS}: valid JSON"
    fi
fi

echo
if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Review artifact integrity violations found ==="
    exit 1
else
    log_info "=== PASSED: All review artifacts are compliant ==="
    exit 0
fi
