#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUT_BASE="${REPO_ROOT}/target/calloc_ctxpage_stress"
SYNTHETIC_FILES=2000
SYNTHETIC_BYTES=1024
MAX_PAGES=3
PAGE_BUDGETS_CSV="98304,131072,196608"
SKIP_BUILD=0

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --out-base <dir>          Output base directory (default: target/calloc_ctxpage_stress)
  --synthetic-files <n>     Synthetic fixture file count (default: 2000)
  --synthetic-bytes <n>     Target bytes per synthetic file payload (default: 1024)
  --max-pages <n>           Max pagination resume steps per scenario (default: 3)
  --page-budgets <csv>      Comma-separated page budgets in bytes (default: 98304,131072,196608)
  --skip-build              Skip release build for calloc and ctxpage
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-base)
            OUT_BASE="$2"
            shift 2
            ;;
        --synthetic-files)
            SYNTHETIC_FILES="$2"
            shift 2
            ;;
        --synthetic-bytes)
            SYNTHETIC_BYTES="$2"
            shift 2
            ;;
        --max-pages)
            MAX_PAGES="$2"
            shift 2
            ;;
        --page-budgets)
            PAGE_BUDGETS_CSV="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if ! [[ "$SYNTHETIC_FILES" =~ ^[0-9]+$ ]] || ! [[ "$SYNTHETIC_BYTES" =~ ^[0-9]+$ ]] || ! [[ "$MAX_PAGES" =~ ^[0-9]+$ ]]; then
    echo "Invalid numeric argument"
    exit 1
fi

IFS=',' read -r -a PAGE_BUDGETS <<< "$PAGE_BUDGETS_CSV"
if [[ ${#PAGE_BUDGETS[@]} -eq 0 ]]; then
    echo "--page-budgets must provide at least one value"
    exit 1
fi

for budget in "${PAGE_BUDGETS[@]}"; do
    if ! [[ "$budget" =~ ^[0-9]+$ ]]; then
        echo "Invalid budget value: $budget"
        exit 1
    fi
done

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="${OUT_BASE}/run-${TIMESTAMP}"
mkdir -p "$RUN_DIR"

RESULTS_TSV="${RUN_DIR}/results.tsv"
printf 'scenario\tstatus\telapsed_ms\tlog\n' > "$RESULTS_TSV"

FAILURES=0

log() {
    printf '[%s] %s\n' "$(date -u +"%H:%M:%S")" "$*"
}

record_result() {
    local scenario="$1"
    local status="$2"
    local elapsed_ms="$3"
    local log_path="$4"

    printf '%s\t%s\t%s\t%s\n' "$scenario" "$status" "$elapsed_ms" "$log_path" >> "$RESULTS_TSV"

    if [[ "$status" -eq 0 ]]; then
        log "PASS ${scenario} (${elapsed_ms}ms)"
    else
        log "FAIL ${scenario} (${elapsed_ms}ms)"
        FAILURES=$((FAILURES + 1))
    fi
}

run_timed_shell() {
    local scenario="$1"
    local command="$2"
    local log_path="${RUN_DIR}/${scenario}.log"
    local start_ns end_ns elapsed_ms status

    start_ns="$(date +%s%N)"
    set +e
    bash -o pipefail -c "$command" > "$log_path" 2>&1
    status=$?
    set -e
    end_ns="$(date +%s%N)"
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    record_result "$scenario" "$status" "$elapsed_ms" "$log_path"
    return "$status"
}

extract_json_string() {
    local file="$1"
    local key="$2"

    local match
    match="$(rg -o "\"${key}\"\\s*:\\s*\"[^\"]*\"" "$file" | head -n 1 || true)"
    if [[ -z "$match" ]]; then
        printf ''
        return 0
    fi

    printf '%s' "$match" | sed -E "s/.*\"${key}\"\\s*:\\s*\"([^\"]*)\".*/\\1/"
}

extract_json_raw() {
    local file="$1"
    local key="$2"

    local match
    match="$(rg -o "\"${key}\"\\s*:\\s*(\"[^\"]*\"|null|[0-9]+)" "$file" | head -n 1 || true)"
    if [[ -z "$match" ]]; then
        printf ''
        return 0
    fi

    printf '%s' "$match" | sed -E "s/.*\"${key}\"\\s*:\\s*(\"[^\"]*\"|null|[0-9]+).*/\\1/"
}

unwrap_json_string_or_empty() {
    local raw="$1"
    if [[ -z "$raw" || "$raw" == "null" ]]; then
        printf ''
        return 0
    fi

    local unwrapped="$raw"
    unwrapped="${unwrapped#\"}"
    unwrapped="${unwrapped%\"}"
    printf '%s' "$unwrapped"
}

create_synthetic_fixture() {
    local root="$1"
    mkdir -p "${root}/src"

    local index module dir file payload token
    for ((index = 0; index < SYNTHETIC_FILES; index++)); do
        module="$(printf 'module_%03d' "$((index % 64))")"
        dir="${root}/src/${module}"
        mkdir -p "$dir"
        file="$(printf '%s/file_%05d.rs' "$dir" "$index")"

        payload=""
        token="$(printf 'ctx-%02d-' "$((index % 31))")"
        while ((${#payload} < SYNTHETIC_BYTES)); do
            payload+="$token"
        done
        payload="${payload:0:${SYNTHETIC_BYTES}}"

        printf "// synthetic fixture file %d\npub fn f_%d() -> &'static str { \"%s\" }\n" \
            "$index" "$index" "$payload" > "$file"
    done

    local budget_bytes
    budget_bytes=$(( SYNTHETIC_FILES * (SYNTHETIC_BYTES + 256) + 1048576 ))
    local max_file_bytes
    max_file_bytes=$(( SYNTHETIC_BYTES + 8192 ))

    cat > "${root}/.calloc.toml" <<MANIFEST
[project]
namespace = "synthetic-stress"

[index]
roots = ["src"]
exclude = []
max_file_bytes = ${max_file_bytes}

[budget]
max_bytes = ${budget_bytes}
max_tokens = 1000000

[[include]]
glob = "src/**/*.rs"
priority = 100
anchor = true
MANIFEST
}

build_theory_manifest() {
    local manifest_path="$1"

    cat > "$manifest_path" <<'MANIFEST'
[project]
namespace = "theory-context"

[index]
roots = ["documents/theory", "documents"]
exclude = ["target/**", ".git/**", "**/*.png", "**/*.svg", "**/*.lock"]
max_file_bytes = 2097152

[budget]
max_bytes = 12582912
max_tokens = 1200000

[[include]]
glob = "documents/theory/AGENTS.md"
priority = 500
anchor = true

[[include]]
glob = "documents/theory/**/*.json"
priority = 450
anchor = true

[[include]]
glob = "documents/theory/**/*.md"
priority = 350
anchor = false

[[include]]
glob = "documents/AGENTS.md"
priority = 400
anchor = true

[[include]]
glob = "documents/reviews/CI_EXPECTATIONS.md"
priority = 300
anchor = true

[[exclude]]
glob = "documents/**/archive/**"
MANIFEST
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "Building release binaries (calloc, ctxpage)"
    run_timed_shell "build_release" "cd $(printf '%q' "$REPO_ROOT") && cargo build --release -p calloc -p ctxpage"
fi

CALLOC_BIN="${REPO_ROOT}/target/release/calloc"
CTXPAGE_BIN="${REPO_ROOT}/target/release/ctxpage"

if [[ ! -x "$CALLOC_BIN" || ! -x "$CTXPAGE_BIN" ]]; then
    echo "Release binaries not found. Run without --skip-build or build manually."
    exit 1
fi

log "Running synthetic scale scenario"
SYNTHETIC_ROOT="${RUN_DIR}/synthetic_repo"
create_synthetic_fixture "$SYNTHETIC_ROOT"

run_timed_shell \
    "synthetic_pack" \
    "cd $(printf '%q' "$SYNTHETIC_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe .calloc.toml --emit pack-json --output $(printf '%q' "${RUN_DIR}/synthetic.pack.json")"

run_timed_shell \
    "synthetic_blocks_dump" \
    "cd $(printf '%q' "$SYNTHETIC_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe .calloc.toml --emit blocks-jsonl > $(printf '%q' "${RUN_DIR}/synthetic.blocks.jsonl")"

PRIMARY_BUDGET="${PAGE_BUDGETS[0]}"

run_timed_shell \
    "synthetic_pipeline_inline_page" \
    "cd $(printf '%q' "$SYNTHETIC_ROOT") && $(printf '%q' "$CALLOC_BIN") stream --recipe .calloc.toml --page-max-bytes ${PRIMARY_BUDGET} > $(printf '%q' "${RUN_DIR}/synthetic.page.1.json")"

for budget in "${PAGE_BUDGETS[@]}"; do
    run_timed_shell \
        "synthetic_inspect_${budget}" \
        "$(printf '%q' "$CTXPAGE_BIN") inspect --max-bytes ${budget} < $(printf '%q' "${RUN_DIR}/synthetic.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/synthetic.inspect.${budget}.json")"
done

synthetic_cursor_raw="$(extract_json_raw "${RUN_DIR}/synthetic.page.1.json" "cursor_out")"
synthetic_cursor="$(unwrap_json_string_or_empty "$synthetic_cursor_raw")"

if [[ -n "$synthetic_cursor" ]]; then
    run_timed_shell \
        "synthetic_cursor_verify" \
        "$(printf '%q' "$CTXPAGE_BIN") cursor verify --max-bytes ${PRIMARY_BUDGET} --cursor $(printf '%q' "$synthetic_cursor") < $(printf '%q' "${RUN_DIR}/synthetic.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/synthetic.cursor.verify.json")"

    current_cursor="$synthetic_cursor"
    for ((page = 2; page <= MAX_PAGES; page++)); do
        run_timed_shell \
            "synthetic_page_${page}" \
            "$(printf '%q' "$CTXPAGE_BIN") page --max-bytes ${PRIMARY_BUDGET} --cursor $(printf '%q' "$current_cursor") < $(printf '%q' "${RUN_DIR}/synthetic.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/synthetic.page.${page}.json")"

        next_cursor_raw="$(extract_json_raw "${RUN_DIR}/synthetic.page.${page}.json" "cursor_out")"
        next_cursor="$(unwrap_json_string_or_empty "$next_cursor_raw")"
        if [[ -z "$next_cursor" ]]; then
            break
        fi
        current_cursor="$next_cursor"
    done
fi

log "Running documents/theory integration scenario"
THEORY_MANIFEST="${RUN_DIR}/theory.calloc.toml"
build_theory_manifest "$THEORY_MANIFEST"

run_timed_shell \
    "theory_pack_a" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe $(printf '%q' "$THEORY_MANIFEST") --emit pack-json --output $(printf '%q' "${RUN_DIR}/theory.pack.a.json")"

run_timed_shell \
    "theory_pack_b" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe $(printf '%q' "$THEORY_MANIFEST") --emit pack-json --output $(printf '%q' "${RUN_DIR}/theory.pack.b.json")"

theory_digest_a="$(extract_json_string "${RUN_DIR}/theory.pack.a.json" "pack_digest")"
theory_digest_b="$(extract_json_string "${RUN_DIR}/theory.pack.b.json" "pack_digest")"
if [[ -n "$theory_digest_a" && "$theory_digest_a" == "$theory_digest_b" ]]; then
    record_result "theory_pack_digest_stable" 0 0 "${RUN_DIR}/theory.pack.a.json"
else
    record_result "theory_pack_digest_stable" 1 0 "${RUN_DIR}/theory.pack.a.json"
fi

run_timed_shell \
    "theory_stream_page" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") stream --recipe $(printf '%q' "$THEORY_MANIFEST") --page-max-bytes ${PRIMARY_BUDGET} > $(printf '%q' "${RUN_DIR}/theory.page.inline.json")"

run_timed_shell \
    "theory_blocks_dump" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe $(printf '%q' "$THEORY_MANIFEST") --emit blocks-jsonl > $(printf '%q' "${RUN_DIR}/theory.blocks.jsonl")"

run_timed_shell \
    "theory_blocks_dump_repeat" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") pack --recipe $(printf '%q' "$THEORY_MANIFEST") --emit blocks-jsonl > $(printf '%q' "${RUN_DIR}/theory.blocks.repeat.jsonl")"

theory_sha_a="$(sha256sum "${RUN_DIR}/theory.blocks.jsonl" | awk '{print $1}')"
theory_sha_b="$(sha256sum "${RUN_DIR}/theory.blocks.repeat.jsonl" | awk '{print $1}')"
if [[ -n "$theory_sha_a" && "$theory_sha_a" == "$theory_sha_b" ]]; then
    record_result "theory_blocks_sha_stable" 0 0 "${RUN_DIR}/theory.blocks.jsonl"
else
    record_result "theory_blocks_sha_stable" 1 0 "${RUN_DIR}/theory.blocks.jsonl"
fi

run_timed_shell \
    "theory_pipeline_inline_page" \
    "cd $(printf '%q' "$REPO_ROOT") && $(printf '%q' "$CALLOC_BIN") stream --recipe $(printf '%q' "$THEORY_MANIFEST") --page-max-bytes ${PRIMARY_BUDGET} > $(printf '%q' "${RUN_DIR}/theory.page.1.json")"

for budget in "${PAGE_BUDGETS[@]}"; do
    run_timed_shell \
        "theory_inspect_${budget}" \
        "$(printf '%q' "$CTXPAGE_BIN") inspect --max-bytes ${budget} < $(printf '%q' "${RUN_DIR}/theory.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/theory.inspect.${budget}.json")"
done

theory_cursor_raw="$(extract_json_raw "${RUN_DIR}/theory.page.1.json" "cursor_out")"
theory_cursor="$(unwrap_json_string_or_empty "$theory_cursor_raw")"

if [[ -n "$theory_cursor" ]]; then
    run_timed_shell \
        "theory_cursor_verify" \
        "$(printf '%q' "$CTXPAGE_BIN") cursor verify --max-bytes ${PRIMARY_BUDGET} --cursor $(printf '%q' "$theory_cursor") < $(printf '%q' "${RUN_DIR}/theory.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/theory.cursor.verify.json")"

    current_cursor="$theory_cursor"
    for ((page = 2; page <= MAX_PAGES; page++)); do
        run_timed_shell \
            "theory_page_${page}" \
            "$(printf '%q' "$CTXPAGE_BIN") page --max-bytes ${PRIMARY_BUDGET} --cursor $(printf '%q' "$current_cursor") < $(printf '%q' "${RUN_DIR}/theory.blocks.jsonl") > $(printf '%q' "${RUN_DIR}/theory.page.${page}.json")"

        next_cursor_raw="$(extract_json_raw "${RUN_DIR}/theory.page.${page}.json" "cursor_out")"
        next_cursor="$(unwrap_json_string_or_empty "$next_cursor_raw")"
        if [[ -z "$next_cursor" ]]; then
            break
        fi
        current_cursor="$next_cursor"
    done
fi

SUMMARY_MD="${RUN_DIR}/summary.md"
{
    echo "# calloc + ctxpage stress summary"
    echo
    echo "- run_timestamp_utc: ${TIMESTAMP}"
    echo "- synthetic_files: ${SYNTHETIC_FILES}"
    echo "- synthetic_bytes: ${SYNTHETIC_BYTES}"
    echo "- max_pages: ${MAX_PAGES}"
    echo "- page_budgets: ${PAGE_BUDGETS_CSV}"
    echo
    echo "| scenario | status | elapsed_ms | log |"
    echo "| --- | --- | ---: | --- |"
    tail -n +2 "$RESULTS_TSV" | while IFS=$'\t' read -r scenario status elapsed_ms log_path; do
        if [[ "$status" -eq 0 ]]; then
            status_text="PASS"
        else
            status_text="FAIL"
        fi
        printf '| `%s` | %s | %s | `%s` |\n' "$scenario" "$status_text" "$elapsed_ms" "$log_path"
    done
    echo
    echo "## Determinism checks"
    echo
    echo "- theory_pack_digest_a: ${theory_digest_a:-<missing>}"
    echo "- theory_pack_digest_b: ${theory_digest_b:-<missing>}"
    echo "- theory_blocks_sha_a: ${theory_sha_a:-<missing>}"
    echo "- theory_blocks_sha_b: ${theory_sha_b:-<missing>}"
} > "$SUMMARY_MD"

log "Stress run artifacts: ${RUN_DIR}"
log "Summary: ${SUMMARY_MD}"

if [[ "$FAILURES" -ne 0 ]]; then
    log "Completed with ${FAILURES} failing scenarios"
    exit 1
fi

log "All scenarios passed"
