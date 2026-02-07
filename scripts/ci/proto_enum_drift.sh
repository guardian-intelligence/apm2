#!/usr/bin/env bash
# CI drift guard: detect protocol enum drift between .proto and Rust source (TCK-00409)
#
# Checks that enum variants defined in .proto files match those in the
# generated Rust code. This catches cases where a proto enum is updated
# but the generated code is not regenerated, or vice versa.
#
# The canonical source of truth is the .proto file; this script verifies
# the generated Rust file (apm2.daemon.v1.rs) is in sync.
#
# Exit codes:
#   0 - No enum drift detected
#   1 - Enum drift detected
#   2 - Script error
#
# Usage:
#   ./scripts/ci/proto_enum_drift.sh

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

PROTO_FILE="proto/apm2d_runtime_v1.proto"
GENERATED_RS="crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs"

log_info "=== Proto Enum Drift Detection (TCK-00409) ==="
echo

if [[ ! -f "$PROTO_FILE" ]]; then
    log_error "Proto file not found: $PROTO_FILE"
    exit 2
fi

if [[ ! -f "$GENERATED_RS" ]]; then
    log_error "Generated Rust file not found: $GENERATED_RS"
    exit 2
fi

# Extract enum names and variant counts from .proto file
extract_proto_enums() {
    local file="$1"
    local current_enum=""
    local variant_count=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*enum[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\{ ]]; then
            current_enum="${BASH_REMATCH[1]}"
            variant_count=0
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*\} ]]; then
            echo "${current_enum}=${variant_count}"
            current_enum=""
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*[A-Z_]+[[:space:]]*=[[:space:]]*[0-9]+ ]]; then
            variant_count=$((variant_count + 1))
        fi
    done < "$file"
}

# Count variants in a Rust enum block from the generated file.
# prost generates: pub enum Name { Variant = 0, ... }
# We look for lines matching "Identifier = N," inside the enum braces.
count_rs_enum_variants() {
    local file="$1"
    local target_enum="$2"
    local count=0
    local in_enum=0
    local brace_depth=0

    while IFS= read -r line; do
        if [[ $in_enum -eq 0 ]] && [[ "$line" =~ ^pub\ enum\ ${target_enum}[[:space:]] ]]; then
            in_enum=1
            if [[ "$line" == *"{"* ]]; then
                brace_depth=1
            fi
            continue
        fi
        if [[ $in_enum -eq 1 ]]; then
            # Track brace depth
            if [[ "$line" == *"{"* ]]; then
                brace_depth=$((brace_depth + 1))
            fi
            if [[ "$line" == *"}"* ]]; then
                brace_depth=$((brace_depth - 1))
                if [[ $brace_depth -le 0 ]]; then
                    break
                fi
            fi
            # Match prost-generated variant: "    VariantName = N,"
            if [[ "$line" =~ ^[[:space:]]+[A-Z][A-Za-z0-9]*[[:space:]]*=[[:space:]]*[0-9]+, ]]; then
                count=$((count + 1))
            fi
        fi
    done < "$file"
    echo "$count"
}

log_info "Comparing enum variant counts..."

proto_enums=$(extract_proto_enums "$PROTO_FILE")

for entry in $proto_enums; do
    enum_name="${entry%%=*}"
    proto_count="${entry##*=}"

    rs_count=$(count_rs_enum_variants "$GENERATED_RS" "$enum_name")

    if [[ $rs_count -eq 0 ]]; then
        log_warn "Enum ${enum_name} not found in generated Rust code (may use different naming)"
        continue
    fi

    if [[ $proto_count -ne $rs_count ]]; then
        log_error "Enum drift: ${enum_name} has ${proto_count} variants in proto but ${rs_count} in generated Rust"
        log_error "  Proto: ${PROTO_FILE}"
        log_error "  Rust:  ${GENERATED_RS}"
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
    else
        log_info "  ${enum_name}: ${proto_count} variants (OK)"
    fi
done

echo
if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Proto/Rust enum drift detected ==="
    log_error "Run 'cargo build -p apm2-daemon' to regenerate proto code."
    exit 1
else
    log_info "=== PASSED: No proto/Rust enum drift detected ==="
    exit 0
fi
