#!/usr/bin/env bash
# CI drift guard: validate evidence/requirement cross-references (TCK-00409)
#
# Checks that:
# 1. Every requirement_id in evidence artifacts resolves to an existing REQ-*.yaml
# 2. Every evidence_id in requirement files resolves to an existing EVID-*.yaml
#    (requirements with status PROPOSED are allowed forward references)
#
# Known pre-existing broken references are listed in the KNOWN_ISSUES array
# and produce warnings instead of errors. Remove entries as they are fixed.
#
# Exit codes:
#   0 - All references resolve (or are permitted forward/known references)
#   1 - New broken references found
#   2 - Script error
#
# Usage:
#   ./scripts/ci/evidence_refs_lint.sh

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

VIOLATIONS=0
WARNINGS=0
REPO_ROOT="$(git rev-parse --show-toplevel)"
RFC_DIR="${REPO_ROOT}/documents/rfcs"

if [[ ! -d "$RFC_DIR" ]]; then
    log_error "RFC directory not found: ${RFC_DIR} (are you inside the repository?)"
    exit 2
fi

# Known pre-existing broken references (file:ref_id pairs).
# These produce warnings instead of hard failures.
# Remove entries from this list as each reference is fixed.
declare -A KNOWN_ISSUES
KNOWN_ISSUES["RFC-0020/EVID-0101:REQ-0101"]=1

log_info "=== Evidence/Requirement Reference Lint (TCK-00409) ==="
echo

# Collect all existing requirement IDs across all RFCs
declare -A REQ_INDEX
while IFS= read -r req_file; do
    rfc=$(echo "$req_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    basename_no_ext=$(basename "$req_file" .yaml)
    REQ_INDEX["${rfc}/${basename_no_ext}"]=1
done < <(find "$RFC_DIR" -path '*/requirements/REQ-*.yaml' 2>/dev/null || true)

# Collect all existing evidence IDs across all RFCs
declare -A EVID_INDEX
while IFS= read -r evid_file; do
    rfc=$(echo "$evid_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    basename_no_ext=$(basename "$evid_file" .yaml)
    basename_no_ext="${basename_no_ext%.md}"
    EVID_INDEX["${rfc}/${basename_no_ext}"]=1
done < <(find "$RFC_DIR" -path '*/evidence_artifacts/EVID-*' 2>/dev/null || true)

# Check 1: Every requirement_id in evidence artifacts resolves to a REQ file
log_info "Checking requirement_ids in evidence artifacts..."
while IFS= read -r evid_file; do
    rfc=$(echo "$evid_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')
    evid_basename=$(basename "$evid_file" .yaml)

    # Extract all requirement_ids from the full file (not truncated by line count)
    all_req_ids=$(sed -n '/requirement_ids:/,/^[^[:space:]-]/p' "$evid_file" 2>/dev/null | \
        grep -oP 'REQ-[A-Z]*[0-9]+' | sort -u || true)

    for req_id in $all_req_ids; do
        if [[ -z "${REQ_INDEX["${rfc}/${req_id}"]:-}" ]]; then
            known_key="${rfc}/${evid_basename}:${req_id}"
            if [[ -n "${KNOWN_ISSUES["${known_key}"]:-}" ]]; then
                log_warn "Known issue: ${evid_file} references ${req_id} (pre-existing, tracked)"
                WARNINGS=$((WARNINGS + 1))
            else
                log_error "Broken reference: ${evid_file} references ${req_id} but no ${RFC_DIR}/${rfc}/requirements/${req_id}.yaml exists"
                VIOLATIONS=1
            fi
        fi
    done
done < <(find "$RFC_DIR" -path '*/evidence_artifacts/EVID-*.yaml' 2>/dev/null || true)

# Check 2: Every evidence_id in requirement files resolves to an EVID file
# Requirements with status PROPOSED are allowed forward references.
log_info "Checking evidence_ids in requirement files..."
while IFS= read -r req_file; do
    rfc=$(echo "$req_file" | sed -n 's|.*documents/rfcs/\([^/]*\)/.*|\1|p')

    req_status=$(grep -oP '^\s*status:\s*"?\K[A-Z_]+' "$req_file" 2>/dev/null || echo "UNKNOWN")

    # Extract all evidence_ids from the full file (not truncated by line count)
    evid_ids=$(sed -n '/evidence_ids:/,/^[^[:space:]-]/p' "$req_file" 2>/dev/null | \
        grep -oP 'EVID-[A-Z]*[0-9]+' | sort -u || true)

    for evid_id in $evid_ids; do
        if [[ -z "${EVID_INDEX["${rfc}/${evid_id}"]:-}" ]]; then
            if [[ "$req_status" == "PROPOSED" ]]; then
                WARNINGS=$((WARNINGS + 1))
            else
                log_error "Broken reference: ${req_file} (status=${req_status}) references ${evid_id} but no ${RFC_DIR}/${rfc}/evidence_artifacts/${evid_id}.yaml exists"
                VIOLATIONS=1
            fi
        fi
    done
done < <(find "$RFC_DIR" -path '*/requirements/REQ-*.yaml' 2>/dev/null || true)

echo
if [[ $WARNINGS -gt 0 ]]; then
    log_warn "${WARNINGS} forward/known reference(s) skipped (allowed)"
fi

if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Broken evidence/requirement references detected ==="
    exit 1
else
    log_info "=== PASSED: All evidence/requirement references resolve ==="
    exit 0
fi
