//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apm2_core::crypto::Signer;
use apm2_core::economics::queue_admission::HtfEvaluationWindow;
use apm2_core::fac::broker::BrokerState;
use apm2_core::fac::broker_health::{BrokerHealthChecker, WorkerHealthPolicy};
use apm2_core::fac::{
    ChannelBoundaryTrace, DenialReasonCode, FacBroker, FacJobOutcome, FacJobReceiptV1,
    FacJobReceiptV1Builder, FacJobSpecV1, FacJobSpecV1Builder, FacPolicyV1, JobSource,
    LaneProfileV1, MAX_JOB_RECEIPT_SIZE, MAX_JOB_SPEC_SIZE, MAX_POLICY_SIZE,
    QueueAdmissionTrace as JobQueueAdmissionTrace, compute_policy_hash, compute_test_env,
    deserialize_job_receipt, deserialize_policy, parse_policy_hash, persist_content_addressed_receipt,
    persist_policy,
};
use apm2_daemon::telemetry::is_cgroup_v2_available;
use blake3;
use chrono::{SecondsFormat, Utc};

use super::evidence::{EvidenceGateOptions, run_evidence_gates};
use super::gate_attestation::build_nextest_command;
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::timeout_policy::{
    MAX_MANUAL_TIMEOUT_SECONDS, TEST_TIMEOUT_SLA_MESSAGE, max_memory_bytes, parse_memory_limit,
    resolve_bounded_test_timeout,
};
use super::types::apm2_home_dir;
use crate::exit_codes::codes as exit_codes;

const HTF_TEST_HEARTBEAT_SECONDS: u64 = 10;
const QUEUE_DIR: &str = "queue";
const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const DENIED_DIR: &str = "denied";
const QUARANTINED_DIR: &str = "quarantined";
const CONSUME_RECEIPTS_DIR: &str = "authority_consumed";
const FAC_RECEIPTS_DIR: &str = "receipts";
const FAC_ROOT_DIR: &str = "private/fac";
const FAC_SIGNING_KEY_FILE: &str = "signing_key";
const FAC_BROKER_STATE_FILE: &str = "broker_state.json";
const RECEIPT_POLL_INTERVAL_SECS: u64 = 1;
const DEFAULT_BOUNDARY_ID: &str = "local";
const DEFAULT_AUTHORITY_CLOCK: &str = "local";

/// Run all evidence gates locally with optional bounded test execution.
///
/// 1. Requires clean working tree for full mode (`--quick` bypasses this)
/// 2. Resolves HEAD SHA
/// 3. Runs merge-conflict gate first (always recomputed)
/// 4. Runs evidence gates (with bounded test runner if available)
/// 5. Writes attested gate cache receipts for full runs
/// 6. Prints summary table
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    json_output: bool,
    direct: bool,
    wait_timeout: u64,
) -> u8 {
    match run_gates_inner(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        cpu_quota,
        direct,
        wait_timeout,
    ) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Gates");
                println!("  SHA:     {}", summary.sha);
                println!(
                    "  Verdict: {}",
                    if summary.passed { "PASS" } else { "FAIL" }
                );
                println!("  Bounded: {}", summary.bounded);
                println!(
                    "  Mode:    {}",
                    if summary.quick { "quick" } else { "full" }
                );
                println!("  Timeout: {}s", summary.effective_timeout_seconds);
                println!("  Cache:   {}", summary.cache_status);
                println!();
                println!("  {:<25} {:<6} {:>8}", "Gate", "Status", "Duration");
                println!("  {}", "-".repeat(43));
                for gate in &summary.gates {
                    println!(
                        "  {:<25} {:<6} {:>7}s",
                        gate.name, gate.status, gate.duration_secs
                    );
                }
                println!();
                if summary.quick {
                    println!("  Cache: not written in quick mode");
                } else {
                    println!(
                        "  Cache: ~/.apm2/private/fac/gate_cache_v2/{}/",
                        &summary.sha
                    );
                }
            }
            if summary.passed {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_gates_failed",
                    "message": err,
                });
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
                );
            } else if err.contains("no worker processed job within") {
                eprintln!("{err}");
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[derive(Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct GatesSummary {
    sha: String,
    passed: bool,
    bounded: bool,
    quick: bool,
    requested_timeout_seconds: u64,
    effective_timeout_seconds: u64,
    cache_status: String,
    gates: Vec<GateResult>,
}

#[derive(Debug, serde::Serialize)]
struct GateResult {
    name: String,
    status: String,
    duration_secs: u64,
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_gates_inner(
    _force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    direct: bool,
    wait_timeout: u64,
) -> Result<GatesSummary, String> {
    validate_timeout_seconds(timeout_seconds)?;
    let memory_max_bytes = parse_memory_limit(memory_max)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {memory_max} exceeds FAC test memory cap of {max_bytes}",
            max_bytes = max_memory_bytes()
        ));
    }

    let workspace_root =
        std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;
    let timeout_decision = resolve_bounded_test_timeout(&workspace_root, timeout_seconds);

    // 1. Require clean working tree for full gates only.
    ensure_clean_working_tree(&workspace_root, quick)?;

    // 2. Resolve HEAD SHA.
    let sha_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace_root)
        .output()
        .map_err(|e| format!("failed to run git rev-parse HEAD: {e}"))?;
    if !sha_output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let sha = String::from_utf8_lossy(&sha_output.stdout)
        .trim()
        .to_string();
    if sha.len() < 7 {
        return Err(format!("unexpected short SHA: {sha}"));
    }

    if direct {
        run_gates_direct(
            quick,
            timeout_seconds,
            timeout_decision.effective_seconds,
            &sha,
            memory_max,
            pids_max,
            cpu_quota,
            memory_max_bytes,
            &workspace_root,
        )
    } else {
        run_gates_queue(
            quick,
            timeout_seconds,
            timeout_decision.effective_seconds,
            wait_timeout,
            &sha,
            memory_max_bytes,
            pids_max,
            cpu_quota,
            &workspace_root,
        )
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_gates_direct(
    quick: bool,
    timeout_seconds: u64,
    effective_timeout_seconds: u64,
    sha: &str,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    _memory_max_bytes: u64,
    workspace_root: &Path,
) -> Result<GatesSummary, String> {
    // 2. Merge-conflict gate always runs first and is never cache-reused.
    let merge_gate = evaluate_merge_conflict_gate(workspace_root, sha)?;
    if merge_gate.status == "FAIL" {
        return run_gates_direct_finalize(
            sha,
            false,
            false,
            quick,
            timeout_seconds,
            effective_timeout_seconds,
            vec![merge_gate],
        );
    }

    // 3. Build test command override for test execution.
    let bounded_script = workspace_root.join("scripts/ci/run_bounded_tests.sh");
    let cgroup_available = is_cgroup_v2_available();
    let bounded = bounded_script.is_file() && cgroup_available;
    let default_nextest_command = build_nextest_command();
    let test_command_environment = compute_nextest_test_environment()?;

    let test_command = if quick {
        None
    } else if bounded {
        Some(build_bounded_test_command(
            &bounded_script,
            effective_timeout_seconds,
            memory_max,
            pids_max,
            cpu_quota,
            &default_nextest_command,
        ))
    } else {
        Some(default_nextest_command)
    };

    let opts = EvidenceGateOptions {
        test_command,
        test_command_environment,
        skip_test_gate: quick,
        skip_merge_conflict_gate: true,
    };

    // 4. Run evidence gates.
    let started = Instant::now();
    let (passed, gate_results) = run_evidence_gates(workspace_root, sha, None, Some(&opts))?;
    let total_secs = started.elapsed().as_secs();

    // 5. Skip gate cache in unsafe direct mode.

    let mut gates = vec![merge_gate];
    let mut evidence_gates: Vec<GateResult> = gate_results
        .iter()
        .map(|r| GateResult {
            name: r.gate_name.clone(),
            status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
            duration_secs: r.duration_secs,
        })
        .collect();
    gates.append(&mut evidence_gates);
    if quick {
        // Keep test visible in summary even when skipped for inner-loop runs.
        let insert_index = gates
            .iter()
            .position(|gate| gate.name == "workspace_integrity")
            .unwrap_or(gates.len());
        gates.insert(
            insert_index,
            GateResult {
                name: "test".to_string(),
                status: "SKIP".to_string(),
                duration_secs: 0,
            },
        );
    }

    eprintln!(
        "fac gates (mode={}): completed in {total_secs}s — {}",
        if quick { "quick" } else { "full" },
        if passed { "PASS" } else { "FAIL" }
    );

    run_gates_direct_finalize(
        sha,
        passed,
        bounded,
        quick,
        timeout_seconds,
        effective_timeout_seconds,
        gates,
    )
}

fn run_gates_direct_finalize(
    sha: &str,
    passed: bool,
    bounded: bool,
    quick: bool,
    timeout_seconds: u64,
    effective_timeout_seconds: u64,
    gates: Vec<GateResult>,
) -> Result<GatesSummary, String> {
    let cache_status = if quick {
        "disabled (quick mode)".to_string()
    } else {
        "disabled (unsafe direct)".to_string()
    };

    emit_direct_fac_receipt(sha, passed, quick, timeout_seconds, &gates)?;

    Ok(GatesSummary {
        sha: sha.to_string(),
        passed,
        bounded,
        quick,
        requested_timeout_seconds: timeout_seconds,
        effective_timeout_seconds,
        cache_status,
        gates,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_gates_queue(
    quick: bool,
    timeout_seconds: u64,
    effective_timeout_seconds: u64,
    wait_timeout: u64,
    sha: &str,
    memory_max_bytes: u64,
    pids_max: u64,
    cpu_quota: &str,
    workspace_root: &Path,
) -> Result<GatesSummary, String> {
    validate_wait_timeout(wait_timeout)?;

    let _ = (pids_max, cpu_quota);

    let spec = build_gates_job_spec(
        workspace_root,
        sha,
        quick,
        effective_timeout_seconds,
        memory_max_bytes,
    )?;

    let apm2_home = apm2_home_dir().map_err(|e| format!("failed to resolve APM2 home: {e}"))?;
    let queue_root = apm2_home.join(QUEUE_DIR);
    let fac_root = apm2_home.join(FAC_ROOT_DIR);
    ensure_queue_root_dirs(&queue_root)?;
    let mut broker = load_or_init_broker(&fac_root)?;
    bootstrap_broker_for_issuance(&fac_root, &mut broker)?;

    let mut spec = spec;
    let job_spec_digest = parse_policy_hash(&spec.job_spec_digest).ok_or_else(|| {
        format!(
            "invalid job spec digest generated by builder: {}",
            spec.job_spec_digest
        )
    })?;
    let token = broker
        .issue_channel_context_token(
            &job_spec_digest,
            &spec.actuation.lease_id,
            &spec.actuation.request_id,
        )
        .map_err(|e| format!("failed to issue channel context token: {e}"))?;
    spec.actuation.channel_context_token = Some(token);

    let pending_path = write_pending_job_spec(&queue_root, &spec)?;
    save_broker_state(&broker, &fac_root)?;

    let receipt = match wait_for_matching_receipt(
        &fac_root.join(FAC_RECEIPTS_DIR),
        &spec.job_id,
        wait_timeout,
    ) {
        Ok(receipt) => receipt,
        Err(err) => {
            if let Err(remove_err) = fs::remove_file(&pending_path) {
                eprintln!(
                    "fac gates: warning: could not remove pending job spec {} after timeout: {}",
                    pending_path.display(),
                    remove_err
                );
            }
            return Err(err);
        },
    };

    if let Err(err) = fs::remove_file(&pending_path) {
        eprintln!(
            "fac gates: warning: could not remove pending job spec {}: {}",
            pending_path.display(),
            err
        );
    }

    let passed = matches!(receipt.outcome, FacJobOutcome::Completed);
    Ok(GatesSummary {
        sha: sha.to_string(),
        passed,
        bounded: false,
        quick,
        requested_timeout_seconds: timeout_seconds,
        effective_timeout_seconds,
        cache_status: "queued on worker".to_string(),
        gates: vec![GateResult {
            name: "worker".to_string(),
            status: if passed {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            duration_secs: 0,
        }],
    })
}

fn validate_wait_timeout(wait_timeout: u64) -> Result<(), String> {
    if wait_timeout == 0 {
        return Err("--wait-timeout must be greater than zero.".to_string());
    }
    Ok(())
}

fn build_gates_job_spec(
    workspace_root: &Path,
    head_sha: &str,
    quick: bool,
    effective_timeout_seconds: u64,
    memory_max_bytes: u64,
) -> Result<FacJobSpecV1, String> {
    let now = current_timestamp_epoch_secs();
    let job_id = format!("fac-gates-{}-{now}", short_hash_or_fallback(head_sha));
    let enqueue_time = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    let repo_id = workspace_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace")
        .to_string();

    let source = JobSource {
        kind: "mirror_commit".to_string(),
        repo_id,
        head_sha: head_sha.to_string(),
        patch: None,
    };

    let mut builder = FacJobSpecV1Builder::new(
        job_id,
        "gates",
        "bulk",
        enqueue_time,
        format!("lease-{now}"),
        source,
    )
    .priority(25)
        .memory_max_bytes(memory_max_bytes)
    .test_timeout_seconds(effective_timeout_seconds)
    .require_nextest(!quick);

    // In quick mode there is no heavyweight test requirement and no
    // test timeout.
    if quick {
        builder = builder.require_nextest(false).test_timeout_seconds(0);
    }

    builder
        .build()
        .map_err(|e| format!("cannot build gates job spec: {e}"))
}

fn short_hash_or_fallback(full_sha: &str) -> String {
    full_sha.chars().take(12).collect::<String>()
}

fn ensure_queue_root_dirs(queue_root: &Path) -> Result<(), String> {
    for dir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(dir);
        if !path.exists() {
            fs::create_dir_all(&path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

fn load_or_init_broker(fac_root: &Path) -> Result<FacBroker, String> {
    let signer = load_or_generate_persistent_signer(fac_root)?;
    let mut default_state = BrokerState::default();
    let state_path = fac_root.join(FAC_BROKER_STATE_FILE);
    if state_path.exists() {
        if let Some(state) = load_broker_state(&state_path) {
            default_state = state;
        }
    }
    FacBroker::from_signer_and_state(signer, default_state)
        .map_err(|e| format!("cannot construct broker from signing key and state: {e}"))
}

fn load_broker_state(state_path: &Path) -> Option<BrokerState> {
    let bytes = read_bounded(state_path, 1_048_576).ok()?;
    FacBroker::deserialize_state(&bytes).ok()
}

fn bootstrap_broker_for_issuance(fac_root: &Path, broker: &mut FacBroker) -> Result<(), String> {
    let mut checker = BrokerHealthChecker::new();
    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);
    let eval_window = broker
        .build_evaluation_window(
            DEFAULT_BOUNDARY_ID,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .unwrap_or_else(|_| default_eval_window());
    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            DEFAULT_BOUNDARY_ID,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .map_err(|e| format!("cannot issue startup time authority envelope: {e}"))?;
    let _ = broker.check_health(Some(&startup_envelope), &eval_window, &[], &mut checker);

    if let Err(e) =
        broker.evaluate_admission_health_gate(&checker, &eval_window, WorkerHealthPolicy::default())
    {
        return Err(format!("admission health gate failed: {e}"));
    }

    let (_policy_hash, policy_digest) =
        load_or_create_policy(fac_root).map_err(|e| format!("cannot load fac policy: {e}"))?;

    broker
        .admit_policy_digest(policy_digest)
        .map_err(|e| format!("cannot admit policy digest: {e}"))?;

    Ok(())
}

fn save_broker_state(broker: &FacBroker, fac_root: &Path) -> Result<(), String> {
    let state_path = fac_root.join(FAC_BROKER_STATE_FILE);
    let bytes = broker
        .serialize_state()
        .map_err(|e| format!("cannot serialize broker state: {e}"))?;
    fs::write(&state_path, bytes).map_err(|e| format!("cannot write broker state: {e}"))
}

fn load_or_generate_persistent_signer(fac_root: &Path) -> Result<Signer, String> {
    let key_path = fac_root.join(FAC_SIGNING_KEY_FILE);
    if key_path.exists() {
        let bytes =
            read_bounded(&key_path, 64).map_err(|e| format!("cannot read signing key: {e}"))?;
        Signer::from_bytes(&bytes).map_err(|e| format!("invalid signing key: {e}"))
    } else {
        let signer = Signer::generate();
        let key_bytes = signer.secret_key_bytes();
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create signing key directory: {e}"))?;
        }
        fs::write(&key_path, key_bytes.as_ref())
            .map_err(|e| format!("cannot write signing key: {e}"))?;
        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("cannot set signing key permissions: {e}"))?;
        }
        Ok(signer)
    }
}

fn load_or_create_policy(fac_root: &Path) -> Result<(String, [u8; 32]), String> {
    let policy_dir = fac_root.join("policy");
    let policy_path = policy_dir.join("fac_policy.v1.json");

    let policy = if policy_path.exists() {
        let bytes = read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|e| format!("cannot load fac policy: {e}"))?
    } else {
        let default_policy = FacPolicyV1::default_policy();
        persist_policy(fac_root, &default_policy)
            .map_err(|e| format!("cannot persist default fac policy: {e}"))?;
        default_policy
    };

    let policy_hash =
        compute_policy_hash(&policy).map_err(|e| format!("cannot compute policy hash: {e}"))?;
    let policy_digest =
        parse_policy_hash(&policy_hash).ok_or_else(|| "invalid policy hash".to_string())?;

    Ok((policy_hash, policy_digest))
}

fn write_pending_job_spec(queue_root: &Path, spec: &FacJobSpecV1) -> Result<PathBuf, String> {
    let job_spec_json =
        serde_json::to_vec_pretty(spec).map_err(|e| format!("cannot serialize job spec: {e}"))?;
    if job_spec_json.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "job spec exceeds worker limit: {} > {}",
            job_spec_json.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }

    let pending_dir = queue_root.join(PENDING_DIR);
    fs::create_dir_all(&pending_dir)
        .map_err(|e| format!("cannot create pending directory: {e}"))?;

    let file_name = format!("{}.json", spec.job_id);
    let target = pending_dir.join(file_name);
    let temp = pending_dir.join(format!(".pending-{}.tmp", spec.job_id));
    fs::write(&temp, job_spec_json)
        .map_err(|e| format!("cannot write pending job spec temp file: {e}"))?;
    fs::rename(&temp, &target)
        .map_err(|e| format!("cannot move pending job spec to {}: {e}", target.display()))?;

    Ok(target)
}

fn wait_for_matching_receipt(
    receipts_dir: &Path,
    job_id: &str,
    wait_timeout: u64,
) -> Result<FacJobReceiptV1, String> {
    let start = Instant::now();
    let timeout = Duration::from_secs(wait_timeout);

    loop {
        if let Ok(entries) = fs::read_dir(receipts_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let bytes = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Err(format!(
                            "failed to read FAC receipt {}: {e}",
                            path.display()
                        ));
                    },
                };
                if bytes.len() > MAX_JOB_RECEIPT_SIZE {
                    continue;
                }
                let Ok(receipt) = deserialize_job_receipt(&bytes) else {
                    continue;
                };
                if receipt.job_id == job_id {
                    return Ok(receipt);
                }
            }
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "error: no worker processed job within {wait_timeout}s\nhint: ensure worker is running: apm2 fac services ensure\nhint: or use --direct to run gates locally (unsafe)"
            ));
        }

        let elapsed = start.elapsed();
        let remaining = timeout.saturating_sub(elapsed).as_secs();
        if remaining > 0 {
            let sleep_secs = remaining.min(RECEIPT_POLL_INTERVAL_SECS);
            sleep(Duration::from_secs(sleep_secs));
        }
    }
}

fn emit_direct_fac_receipt(
    sha: &str,
    passed: bool,
    quick: bool,
    timeout_seconds: u64,
    gates: &[GateResult],
) -> Result<(), String> {
    let apm2_home = apm2_home_dir().map_err(|e| format!("failed to resolve APM2 home: {e}"))?;
    let fac_root = apm2_home.join(FAC_ROOT_DIR);

    let mut reason = if passed {
        "all gates passed (direct mode)".to_string()
    } else {
        format!("one or more gates failed; quick={quick}, timeout={timeout_seconds}s")
    };
    if !gates.is_empty() {
        let details = gates
            .iter()
            .map(|g| format!("{}={}", g.name, g.status))
            .collect::<Vec<_>>()
            .join(", ");
        reason = format!("{reason} [{details}]");
    }

    let outcome = if passed {
        FacJobOutcome::Completed
    } else {
        FacJobOutcome::Denied
    };

    let boundary_trace = ChannelBoundaryTrace {
        passed,
        defect_count: 0,
        defect_classes: Vec::new(),
    };

    let queue_trace = JobQueueAdmissionTrace {
        verdict: if passed { "allow" } else { "deny" }.to_string(),
        queue_lane: "local".to_string(),
        defect_reason: if passed {
            None
        } else {
            Some("direct-mode-without-admission".to_string())
        },
    };

    let spec_digest = format!("b3-256:{}", blake3::hash(sha.as_bytes()).to_hex());
    let mut receipt = FacJobReceiptV1Builder::new(
        format!("local-{}-{sha}", current_timestamp_epoch_secs()),
        format!("sha-{sha}"),
        spec_digest,
    )
    .unsafe_direct(true)
    .outcome(outcome)
    .reason(&reason)
    .rfc0028_channel_boundary(boundary_trace)
    .eio29_queue_admission(queue_trace)
    .timestamp_secs(current_timestamp_epoch_secs())
    ;
    if !passed {
        receipt = receipt.denial_reason(DenialReasonCode::ValidationFailed);
    }

    let receipt = receipt
        .try_build()
        .map_err(|e| format!("cannot build direct receipt: {e}"))?;

    persist_content_addressed_receipt(&fac_root.join(FAC_RECEIPTS_DIR), &receipt)
        .map_err(|e| format!("cannot persist direct receipt: {e}"))?;

    Ok(())
}

fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if metadata.len() > max_size as u64 {
        return Err(format!(
            "file {} exceeds max {} bytes",
            path.display(),
            max_size
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let read_limit = metadata.len() as usize;
    let mut limited_reader = file.take((max_size.saturating_add(1)) as u64);
    let mut bytes = Vec::with_capacity(read_limit);
    limited_reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > max_size {
        return Err(format!(
            "file {} exceeds max {} bytes",
            path.display(),
            max_size
        ));
    }

    Ok(bytes)
}

fn current_timestamp_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_eval_window() -> HtfEvaluationWindow {
    HtfEvaluationWindow {
        boundary_id: DEFAULT_BOUNDARY_ID.to_string(),
        authority_clock: DEFAULT_AUTHORITY_CLOCK.to_string(),
        tick_start: 0,
        tick_end: 0,
    }
}

fn validate_timeout_seconds(timeout_seconds: u64) -> Result<(), String> {
    if timeout_seconds == 0 {
        return Err(format!(
            "--timeout-seconds must be greater than zero (max {MAX_MANUAL_TIMEOUT_SECONDS}). {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    if timeout_seconds > MAX_MANUAL_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout-seconds cannot exceed {MAX_MANUAL_TIMEOUT_SECONDS}. {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    Ok(())
}

fn evaluate_merge_conflict_gate(workspace_root: &Path, sha: &str) -> Result<GateResult, String> {
    let started = Instant::now();
    let report = check_merge_conflicts_against_main(workspace_root, sha)?;
    let duration = started.elapsed().as_secs();
    let passed = !report.has_conflicts();
    if !passed {
        eprintln!("{}", render_merge_conflict_summary(&report));
    }
    Ok(GateResult {
        name: "merge_conflict_main".to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        duration_secs: duration,
    })
}

/// Build the bounded test runner command, mirroring the old `fac check`
/// pattern.
fn build_bounded_test_command(
    bounded_script: &Path,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    nextest_command: &[String],
) -> Vec<String> {
    let mut command = vec![
        bounded_script.display().to_string(),
        "--timeout-seconds".to_string(),
        timeout_seconds.to_string(),
        "--kill-after-seconds".to_string(),
        "20".to_string(),
        "--heartbeat-seconds".to_string(),
        HTF_TEST_HEARTBEAT_SECONDS.to_string(),
        "--memory-max".to_string(),
        memory_max.to_string(),
        "--pids-max".to_string(),
        pids_max.to_string(),
        "--cpu-quota".to_string(),
        cpu_quota.to_string(),
        "--".to_string(),
    ];
    command.extend(nextest_command.iter().cloned());
    command
}

fn compute_nextest_test_environment() -> Result<Vec<(String, String)>, String> {
    let profile = LaneProfileV1::new("lane-00", "b3-256:fac-gates", "boundary-00")
        .map_err(|err| format!("failed to construct FAC gate lane profile: {err}"))?;
    Ok(compute_test_env(&profile))
}

fn ensure_clean_working_tree(workspace_root: &Path, quick: bool) -> Result<(), String> {
    if quick {
        return Ok(());
    }

    let diff_status = Command::new("git")
        .args(["diff", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    if !diff_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has unstaged changes. ALL changes must be committed before \
             running full gates — build artifacts are SHA-attested and reused as a source of truth. \
             Run `git add -A && git commit` first, or use `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    let cached_status = Command::new("git")
        .args(["diff", "--cached", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff --cached: {e}"))?;
    if !cached_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has staged but uncommitted changes. ALL changes must be \
             committed before running full gates — build artifacts are SHA-attested and reused \
             as a source of truth. Run `git commit` first, or use `apm2 fac gates --quick` for \
             inner-loop development."
                .to_string(),
        );
    }

    let untracked = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files --others --exclude-standard: {e}"))?;
    if !untracked.status.success() {
        return Err("failed to evaluate untracked files for clean-tree check".to_string());
    }
    if !String::from_utf8_lossy(&untracked.stdout).trim().is_empty() {
        return Err(
            "DIRTY TREE: working tree has untracked files. ALL files must be committed (or \
             .gitignored) before running full gates — build artifacts are SHA-attested and \
             reused as a source of truth. Run `git add -A && git commit` first, or use \
             `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    #[test]
    fn ensure_clean_working_tree_skips_checks_in_quick_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let result = ensure_clean_working_tree(temp_dir.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_clean_working_tree_rejects_unstaged_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("sample.txt"), "v1\n").expect("write file");
        run_git(repo, &["add", "sample.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("sample.txt"), "v2\n").expect("modify file");

        let err = ensure_clean_working_tree(repo, false).expect_err("dirty tree should fail");
        assert!(err.contains("working tree has unstaged changes"));
    }

    #[test]
    fn ensure_clean_working_tree_rejects_untracked_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("tracked.txt"), "v1\n").expect("write tracked file");
        run_git(repo, &["add", "tracked.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("untracked.txt"), "new\n").expect("write untracked file");

        let err = ensure_clean_working_tree(repo, false).expect_err("untracked tree should fail");
        assert!(err.contains("working tree has untracked files"));
    }

    #[test]
    fn bounded_test_command_uses_nextest() {
        let command = build_bounded_test_command(
            Path::new("/tmp/run_bounded_tests.sh"),
            120,
            "24G",
            1536,
            "200%",
            &build_nextest_command(),
        );
        let joined = command.join(" ");
        assert!(joined.contains("cargo nextest run --workspace"));
        assert!(!joined.contains("cargo test --workspace"));
    }

    #[test]
    fn test_wait_for_matching_receipt_returns_timeout_error() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let error = wait_for_matching_receipt(temp_dir.path(), "no-such-job", 1)
            .expect_err("receipt poll should timeout when missing");

        assert!(error.contains("error: no worker processed job within 1s"));
        assert!(error.contains("ensure worker is running: apm2 fac services ensure"));
    }

    #[test]
    fn test_wait_for_matching_receipt_finds_matching_job() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let dir = temp_dir.path();

        let receipt = FacJobReceiptV1Builder::new(
            "receipt-001",
            "job-001",
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .outcome(FacJobOutcome::Completed)
        .reason("completed")
        .timestamp_secs(1_700_000_000)
        .rfc0028_channel_boundary(ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
        })
        .eio29_queue_admission(JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "bulk".to_string(),
            defect_reason: None,
        })
        .try_build()
        .expect("build sample receipt");

        let receipt_path = dir.join("sample.json");
        let bytes = serde_json::to_vec_pretty(&receipt).expect("serialize receipt");
        fs::write(&receipt_path, bytes).expect("write sample receipt");

        let found = wait_for_matching_receipt(dir, "job-001", 5).expect("find matching receipt");
        assert_eq!(found.receipt_id, "receipt-001");
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
