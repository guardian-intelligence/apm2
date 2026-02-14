#![allow(clippy::disallowed_methods)]

use std::fs::OpenOptions;
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::fac::GcReceiptV1;
use crate::fac::lane::{LaneManager, LaneState};
use crate::fac::safe_rmtree::{SafeRmtreeError, SafeRmtreeOutcome, safe_rmtree_v1};

pub const GATE_CACHE_TTL_SECS: u64 = 2_592_000;
pub const QUARANTINE_RETENTION_SECS: u64 = 2_592_000;
const FAC_CARGO_HOME_DIR: &str = "cargo_home";
const FAC_LEGACY_EVIDENCE_DIR: &str = "evidence";
/// Maximum recursion depth for directory-size estimation.
const MAX_TRAVERSAL_DEPTH: usize = 64;
/// Maximum number of directory entries processed during size estimation.
const MAX_DIR_ENTRIES: usize = 100_000;

#[derive(Debug, Clone)]
pub struct GcPlan {
    pub targets: Vec<GcTarget>,
}

#[derive(Debug, Clone)]
pub struct GcTarget {
    pub path: PathBuf,
    pub allowed_parent: PathBuf,
    pub kind: crate::fac::gc_receipt::GcActionKind,
    pub estimated_bytes: u64,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum GcPlanError {
    Io(String),
    Precondition(String),
}

/// Create a garbage-collection plan from all known FAC artifacts.
///
/// # Errors
///
/// Returns `GcPlanError::Io` when workspace inspection fails.
pub fn plan_gc(fac_root: &Path, lane_manager: &LaneManager) -> Result<GcPlan, GcPlanError> {
    let mut targets = Vec::new();
    let statuses = lane_manager
        .all_lane_statuses()
        .map_err(|error| GcPlanError::Io(error.to_string()))?;

    for status in statuses {
        if status.state != LaneState::Idle {
            continue;
        }
        let lane_dir = lane_manager.lane_dir(&status.lane_id);
        let target_dir = lane_dir.join("target");
        let log_dir = lane_dir.join("logs");

        if target_dir.exists() {
            targets.push(GcTarget {
                path: target_dir.clone(),
                allowed_parent: lane_dir.clone(),
                kind: crate::fac::gc_receipt::GcActionKind::LaneTarget,
                estimated_bytes: estimate_dir_size(&target_dir),
            });
        }
        if log_dir.exists() {
            targets.push(GcTarget {
                path: log_dir.clone(),
                allowed_parent: lane_dir.clone(),
                kind: crate::fac::gc_receipt::GcActionKind::LaneLog,
                estimated_bytes: estimate_dir_size(&log_dir),
            });
        }
    }

    let gate_cache_root = fac_root.join("gate_cache_v2");
    if let Ok(entries) = std::fs::read_dir(&gate_cache_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, GATE_CACHE_TTL_SECS) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: gate_cache_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::GateCache,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }

    let queue_root = infer_queue_root(fac_root);
    let cargo_home_root = fac_root.join(FAC_CARGO_HOME_DIR);
    let legacy_evidence_root = fac_root.join(FAC_LEGACY_EVIDENCE_DIR);

    if cargo_home_root.exists() {
        targets.push(GcTarget {
            path: cargo_home_root.clone(),
            allowed_parent: fac_root.to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::CargoCache,
            estimated_bytes: estimate_dir_size(&cargo_home_root),
        });
    }

    if legacy_evidence_root.exists() {
        targets.push(GcTarget {
            path: legacy_evidence_root.clone(),
            allowed_parent: fac_root.to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::LaneLog,
            estimated_bytes: estimate_dir_size(&legacy_evidence_root),
        });
    }

    let quarantine_root = queue_root.join("quarantined");
    if let Ok(entries) = std::fs::read_dir(&quarantine_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, QUARANTINE_RETENTION_SECS) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: quarantine_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }

    targets.sort_by(|a, b| b.estimated_bytes.cmp(&a.estimated_bytes));
    Ok(GcPlan { targets })
}

/// Execute a garbage-collection plan and produce a best-effort receipt.
///
/// # Errors
///
/// This function records all per-target failures into `errors` and does not
/// abort early.
#[must_use]
pub fn execute_gc(plan: &GcPlan) -> GcReceiptV1 {
    #[allow(clippy::disallowed_methods)]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut actions = Vec::new();
    let mut errors = Vec::new();

    for target in &plan.targets {
        match is_lane_path_locked(target) {
            Ok(true) => {
                errors.push(crate::fac::gc_receipt::GcError {
                    target_path: target.path.display().to_string(),
                    reason: "lane is not idle".to_string(),
                });
                continue;
            },
            Ok(false) => (),
            Err(error) => {
                eprintln!(
                    "WARNING: lock check failed for {}: {error}, skipping",
                    target.path.display()
                );
                errors.push(crate::fac::gc_receipt::GcError {
                    target_path: target.path.display().to_string(),
                    reason: format!("lock check failed: {error}"),
                });
                continue;
            },
        }

        match safe_rmtree_v1(&target.path, &target.allowed_parent) {
            Ok(outcome) => {
                let (files_deleted, dirs_deleted) = match outcome {
                    SafeRmtreeOutcome::Deleted {
                        files_deleted,
                        dirs_deleted,
                    } => (files_deleted, dirs_deleted),
                    SafeRmtreeOutcome::AlreadyAbsent => (0, 0),
                };
                actions.push(crate::fac::gc_receipt::GcAction {
                    target_path: target.path.display().to_string(),
                    action_kind: target.kind.clone(),
                    bytes_freed: target.estimated_bytes,
                    files_deleted,
                    dirs_deleted,
                });
            },
            Err(error) => {
                errors.push(crate::fac::gc_receipt::GcError {
                    target_path: target.path.display().to_string(),
                    reason: safe_rmtree_error_to_string(error),
                });
            },
        }
    }

    GcReceiptV1 {
        schema: crate::fac::gc_receipt::GC_RECEIPT_SCHEMA.to_string(),
        receipt_id: String::new(),
        timestamp_secs: now,
        before_free_bytes: 0,
        after_free_bytes: 0,
        min_free_threshold: 0,
        actions,
        errors,
        content_hash: String::new(),
    }
}

fn safe_rmtree_error_to_string(error: SafeRmtreeError) -> String {
    match error {
        SafeRmtreeError::OutsideAllowedParent {
            root,
            allowed_parent,
        } => format!(
            "outside_allowed_parent:{}:{}",
            root.display(),
            allowed_parent.display()
        ),
        SafeRmtreeError::Io { context, source } => format!("io:{context}:{source}"),
        SafeRmtreeError::SymlinkDetected { path } => {
            format!("symlink_detected:{}", path.display())
        },
        SafeRmtreeError::CrossesFilesystemBoundary {
            root_dev,
            parent_dev,
        } => format!("crosses_filesystem_boundary:{root_dev}:{parent_dev}"),
        SafeRmtreeError::UnexpectedFileType { path, file_type } => {
            format!("unexpected_file_type:{}:{file_type}", path.display())
        },
        SafeRmtreeError::NotAbsolute { path } => format!("path_not_absolute:{}", path.display()),
        SafeRmtreeError::PermissionDenied { reason } => format!("permission_denied:{reason}"),
        SafeRmtreeError::TocTouRace { reason } => format!("toctou_race:{reason}"),
        SafeRmtreeError::DepthExceeded { path, max } => {
            format!("depth_exceeded:{}:{max}", path.display())
        },
        SafeRmtreeError::TooManyEntries { path, max } => {
            format!("too_many_entries:{}:{max}", path.display())
        },
        SafeRmtreeError::DotSegment { path } => format!("dot_segment:{}", path.display()),
    }
}

fn estimate_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = Vec::from([(path.to_path_buf(), 0usize)]);
    let mut entries_count = 0usize;

    while let Some(current) = stack.pop() {
        let (current, depth) = current;
        if depth >= MAX_TRAVERSAL_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            entries_count += 1;
            if entries_count >= MAX_DIR_ENTRIES {
                return total;
            }
            let entry_path = entry.path();
            let Ok(metadata) = entry_path.symlink_metadata() else {
                continue;
            };
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            } else if metadata.is_dir() {
                stack.push((entry_path, depth + 1));
            }
        }
    }
    total
}

fn is_stale_by_mtime(path: &Path, ttl_seconds: u64) -> bool {
    if ttl_seconds == 0 {
        return false;
    }
    let Ok(metadata) = path.symlink_metadata() else {
        return false;
    };
    let Ok(mtime) = metadata.modified().and_then(|m| {
        m.duration_since(UNIX_EPOCH)
            .map_err(|_| std::io::ErrorKind::InvalidData.into())
    }) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    now.checked_sub(Duration::from_secs(ttl_seconds))
        .is_some_and(|cutoff| mtime < cutoff)
}

fn infer_queue_root(fac_root: &Path) -> PathBuf {
    fac_root.parent().and_then(Path::parent).map_or_else(
        || fac_root.join("queue"),
        |apm2_home| apm2_home.join("queue"),
    )
}

fn is_lane_path_locked(target: &GcTarget) -> Result<bool, std::io::Error> {
    let lane_root = match target.path.file_name().and_then(|name| name.to_str()) {
        Some("target" | "logs") => target.path.parent(),
        _ => None,
    };
    let Some(lane_root) = lane_root else {
        return Ok(false);
    };
    if !lane_root.exists() {
        return Ok(false);
    }
    let fac_root = lane_root.parent().and_then(Path::parent).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cannot locate FAC root")
    })?;
    let locks_dir = fac_root.join("locks").join("lanes");
    let lane_name = lane_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid lane path")
        })?;
    let lock_path = locks_dir.join(format!("{lane_name}.lock"));
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    match flock_exclusive_nonblocking(&lock_file) {
        Ok(true) => {
            #[cfg(unix)]
            {
                let fd = lock_file.as_raw_fd();
                #[allow(unsafe_code)]
                let rc = unsafe { libc::flock(fd, libc::LOCK_UN) };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(false)
        },
        Ok(false) => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn flock_exclusive_nonblocking(file: &std::fs::File) -> io::Result<bool> {
    let fd = file.as_raw_fd();
    // SAFETY: flock is a standard POSIX call. fd is a valid file descriptor
    // owned by `file`. LOCK_EX | LOCK_NB is non-blocking exclusive lock.
    #[allow(unsafe_code)]
    let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(err)
}

#[cfg(not(unix))]
fn flock_exclusive_nonblocking(_: &std::fs::File) -> io::Result<bool> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::fac::lane::{LaneLeaseV1, LaneManager, LaneState};

    #[test]
    fn test_gc_plan_skips_running_lanes() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("dir setup");

        let lane_id = "lane-00";
        let lane_dir = lane_manager.lane_dir(lane_id);
        let _lane_lock = lane_manager
            .try_lock(lane_id)
            .expect("lock")
            .expect("acquired");
        let lease = LaneLeaseV1::new(
            lane_id,
            "job-001",
            1234,
            LaneState::Running,
            "2026-01-01T00:00:00Z",
            "fp-lane",
            "fp-toolchain",
        )
        .expect("lease");
        lease.persist(&lane_dir).expect("persist lease");

        let plan = plan_gc(&fac_root, &lane_manager).expect("plan");
        assert!(
            !plan
                .targets
                .iter()
                .any(|target| target.path.to_string_lossy().contains(lane_id)),
            "running lanes must be skipped"
        );
    }

    #[test]
    fn test_gc_uses_safe_rmtree() {
        let temp = tempdir().expect("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(temp.path(), perms).expect("set restrictive permissions");
        }

        let facade = GcTarget {
            path: temp.path().join("x"),
            allowed_parent: temp.path().to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::CargoCache,
            estimated_bytes: 10,
        };
        let plan = GcPlan {
            targets: vec![facade],
        };
        std::fs::create_dir_all(temp.path().join("x")).expect("dir");
        let r = execute_gc(&plan);
        assert!(r.actions.len() == 1 || r.errors.len() == 1);
        assert_eq!(r.errors.len(), 0);
        assert!(!temp.path().join("x").exists());
    }
}
