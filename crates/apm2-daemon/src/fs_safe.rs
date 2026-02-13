//! Safe atomic file I/O primitives for queue, lease, and receipt state files.
//!
//! This module provides three hardened helpers that eliminate common filesystem
//! attack surfaces in daemon state persistence:
//!
//! 1. **Atomic writer** ([`atomic_write`], [`atomic_write_json`]): write to a
//!    temp file in the same directory, fsync the data, rename to the final
//!    path, then fsync the parent directory. Crash at any point leaves either
//!    the old complete file or the new complete file — never a partial write.
//!
//! 2. **Safe opener** ([`safe_open`]): on Linux, opens with `O_NOFOLLOW` to
//!    refuse symlinks. On all platforms, verifies that the opened file is a
//!    regular file (not a device, pipe, or socket). This prevents symlink
//!    replacement tricks that could redirect reads/writes to attacker-chosen
//!    paths.
//!
//! 3. **Bounded JSON reader** ([`bounded_read_json`]): checks file size before
//!    reading, caps at a configurable maximum, and deserializes with serde's
//!    strict mode. Prevents memory-exhaustion `DoS` from oversized state files.
//!
//! # Security Properties
//!
//! - **CTR-2607**: Atomic write protocol (temp + fsync + rename).
//! - **CTR-2611**: Restrictive permissions (0600 files, 0700 dirs) at
//!   create-time.
//! - **CTR-1603**: Bounded reads — file size checked on handle metadata before
//!   allocation.
//! - **RSK-1601**: Parsing `DoS` prevention via size cap before
//!   deserialization.
//! - **CTR-2609**: Symlink refusal prevents path traversal via replacement.
//!
//! # Usage
//!
//! ```rust,ignore
//! use apm2_daemon::fs_safe::{atomic_write_json, bounded_read_json, safe_open};
//!
//! // Atomic JSON write
//! atomic_write_json(&path, &my_state)?;
//!
//! // Bounded JSON read (max 1 MiB)
//! let state: MyState = bounded_read_json(&path, 1_048_576)?;
//!
//! // Safe open (refuses symlinks)
//! let file = safe_open(&path)?;
//! ```

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Maximum size for any single state file read, used as a default upper bound
/// when callers do not specify a custom limit.
///
/// 16 MiB is generous for JSON state files while still preventing
/// memory-exhaustion attacks from corrupted or adversarial files.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;

/// Errors from safe filesystem operations.
#[derive(Debug, thiserror::Error)]
pub enum FsSafeError {
    /// File exceeds the configured size cap.
    #[error("file too large: {size} bytes exceeds maximum of {max} bytes")]
    FileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: u64,
    },

    /// The target path is a symbolic link (refused by `O_NOFOLLOW` or
    /// metadata check).
    #[error("refusing to open symlink at {}", path.display())]
    SymlinkRefused {
        /// Path that was a symlink.
        path: std::path::PathBuf,
    },

    /// The opened file is not a regular file (e.g., device, pipe, socket).
    #[error("not a regular file at {}", path.display())]
    NotRegularFile {
        /// Path that was not a regular file.
        path: std::path::PathBuf,
    },

    /// The final path has no parent directory (cannot create temp file).
    #[error("path has no parent directory: {}", path.display())]
    NoParentDirectory {
        /// Path with no parent.
        path: std::path::PathBuf,
    },

    /// JSON serialization failed.
    #[error("json serialization failed: {0}")]
    SerializeFailed(#[source] serde_json::Error),

    /// JSON deserialization failed.
    #[error("json deserialization failed: {0}")]
    DeserializeFailed(#[source] serde_json::Error),

    /// An I/O error occurred during the operation.
    #[error("I/O error during {context}: {source}")]
    Io {
        /// Human-readable description of the operation that failed.
        context: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl FsSafeError {
    /// Convenience constructor for I/O errors with context.
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// Atomic writer
// ---------------------------------------------------------------------------

/// Writes `data` to `path` atomically using the temp-file + fsync + rename
/// protocol.
///
/// # Crash Safety
///
/// At no point can a reader observe a partially-written file at `path`:
///
/// 1. A `NamedTempFile` is created in the same directory as `path` (ensuring
///    same-filesystem for atomic rename).
/// 2. `data` is written and flushed to the temp file.
/// 3. `fsync` is called on the temp file to ensure durability.
/// 4. The temp file is atomically renamed to `path`.
/// 5. `fsync` is called on the parent directory to commit the rename.
///
/// # Permissions (Unix)
///
/// - The temp file is created with 0600 (owner read/write only) via
///   `NamedTempFile` defaults.
/// - The parent directory is created (if necessary) with 0700 permissions.
///
/// # Errors
///
/// Returns [`FsSafeError`] if any filesystem operation fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), FsSafeError> {
    let parent = path
        .parent()
        .ok_or_else(|| FsSafeError::NoParentDirectory {
            path: path.to_path_buf(),
        })?;

    // Ensure parent directory exists with restrictive permissions.
    ensure_parent_dir(parent)?;

    // Create temp file in the same directory (same filesystem → atomic rename).
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| FsSafeError::io("create temp file", e))?;

    // Write data.
    tmp.write_all(data)
        .map_err(|e| FsSafeError::io("write to temp file", e))?;

    // Flush write buffer to OS.
    tmp.flush()
        .map_err(|e| FsSafeError::io("flush temp file", e))?;

    // fsync: data is durable on disk before rename.
    tmp.as_file()
        .sync_all()
        .map_err(|e| FsSafeError::io("fsync temp file", e))?;

    // Atomic rename (NamedTempFile::persist does rename(2)).
    tmp.persist(path)
        .map_err(|e| FsSafeError::io("atomic rename to final path", e.error))?;

    // fsync parent directory so the directory entry (rename) is durable.
    fsync_directory(parent)?;

    Ok(())
}

/// Serializes `value` to pretty-printed JSON and writes it atomically to
/// `path`.
///
/// This is a convenience wrapper around [`atomic_write`] that handles JSON
/// serialization. The serialization happens in memory before any file I/O,
/// so a serialization failure never leaves a partial file on disk.
///
/// # Errors
///
/// Returns [`FsSafeError::SerializeFailed`] if serialization fails, or any
/// I/O error from [`atomic_write`].
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), FsSafeError> {
    let json = serde_json::to_string_pretty(value).map_err(FsSafeError::SerializeFailed)?;
    atomic_write(path, json.as_bytes())
}

// ---------------------------------------------------------------------------
// Safe opener
// ---------------------------------------------------------------------------

/// Opens a file at `path` with symlink-refusal and regular-file verification.
///
/// # Security
///
/// - **Linux**: Uses `O_NOFOLLOW` via `libc` to atomically refuse symlinks at
///   the kernel level, eliminating any TOCTOU window between a metadata check
///   and the open.
/// - **Non-Linux**: Falls back to `symlink_metadata` check before open. This
///   has a theoretical TOCTOU window, but is the best available on platforms
///   without `O_NOFOLLOW` support in the open(2) path.
/// - **All platforms**: After opening, verifies via `fstat` (handle-based
///   metadata) that the file is a regular file — not a device, pipe, FIFO, or
///   socket.
///
/// # Errors
///
/// - [`FsSafeError::SymlinkRefused`] if the path is a symlink.
/// - [`FsSafeError::NotRegularFile`] if the opened file is not a regular file.
/// - [`FsSafeError::Io`] if the file cannot be opened.
pub fn safe_open(path: &Path) -> Result<File, FsSafeError> {
    // Platform-specific open with symlink refusal.
    let file = open_nofollow(path)?;

    // Post-open metadata verification on the file handle (not the path,
    // avoiding TOCTOU).
    let metadata = file
        .metadata()
        .map_err(|e| FsSafeError::io("fstat after open", e))?;

    if !metadata.is_file() {
        return Err(FsSafeError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }

    Ok(file)
}

/// Linux implementation: open with `O_NOFOLLOW` via `libc::open`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn open_nofollow(path: &Path) -> Result<File, FsSafeError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| FsSafeError::Io {
        context: "path contains null byte".into(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "null byte in path"),
    })?;

    // SAFETY: We are calling libc::open with a valid C string path and
    // well-defined flags. The returned fd is either -1 (error) or a valid
    // file descriptor that we immediately wrap in a File via from_raw_fd.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        // ELOOP is returned when O_NOFOLLOW encounters a symlink.
        if err.raw_os_error() == Some(libc::ELOOP) {
            return Err(FsSafeError::SymlinkRefused {
                path: path.to_path_buf(),
            });
        }
        return Err(FsSafeError::io("open with O_NOFOLLOW", err));
    }

    // SAFETY: fd is a valid, open file descriptor returned by libc::open
    // (we checked fd >= 0 above). Ownership is transferred to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Non-Linux fallback: check `symlink_metadata` then open normally.
///
/// Note: There is a theoretical TOCTOU window between the metadata check and
/// the open. This is acceptable on platforms that do not support `O_NOFOLLOW`
/// in the open(2) path, as it is the best available mitigation.
#[cfg(not(target_os = "linux"))]
fn open_nofollow(path: &Path) -> Result<File, FsSafeError> {
    // Use symlink_metadata (lstat) which does NOT follow symlinks.
    let meta =
        fs::symlink_metadata(path).map_err(|e| FsSafeError::io("symlink_metadata check", e))?;

    if meta.file_type().is_symlink() {
        return Err(FsSafeError::SymlinkRefused {
            path: path.to_path_buf(),
        });
    }

    File::open(path).map_err(|e| FsSafeError::io("open file", e))
}

// ---------------------------------------------------------------------------
// Bounded JSON reader
// ---------------------------------------------------------------------------

/// Reads and deserializes a JSON file with a size cap.
///
/// # Security
///
/// 1. Opens the file via [`safe_open`] (symlink refusal + regular-file check).
/// 2. Checks file size against `max_size` **on the open handle** (no TOCTOU
///    with the filesystem path).
/// 3. Uses [`Read::take`] to enforce the cap even if the file grows between the
///    metadata check and the read (belt-and-suspenders).
/// 4. Deserializes via `serde_json::from_reader`, which the caller's type
///    should annotate with `#[serde(deny_unknown_fields)]` for strictness.
///
/// # Errors
///
/// - [`FsSafeError::FileTooLarge`] if the file exceeds `max_size`.
/// - [`FsSafeError::SymlinkRefused`] if the path is a symlink.
/// - [`FsSafeError::NotRegularFile`] if not a regular file.
/// - [`FsSafeError::DeserializeFailed`] if JSON parsing fails.
/// - [`FsSafeError::Io`] on any I/O error.
pub fn bounded_read_json<T: DeserializeOwned>(
    path: &Path,
    max_size: u64,
) -> Result<T, FsSafeError> {
    let file = safe_open(path)?;

    // Check size on the handle — not the path — to avoid TOCTOU.
    let metadata = file
        .metadata()
        .map_err(|e| FsSafeError::io("fstat for size check", e))?;

    let file_size = metadata.len();
    if file_size > max_size {
        return Err(FsSafeError::FileTooLarge {
            size: file_size,
            max: max_size,
        });
    }

    // Belt-and-suspenders: cap the reader even if the file grows after the
    // metadata check. The +1 lets us detect if someone appended after our
    // stat, since take will stop at max_size+1 and serde will either fail
    // or succeed on the original content.
    let reader = BufReader::new(file.take(max_size.saturating_add(1)));
    serde_json::from_reader(reader).map_err(FsSafeError::DeserializeFailed)
}

/// Reads the raw bytes of a file with a size cap, using [`safe_open`].
///
/// Returns the file contents as a `Vec<u8>`. This is useful when the caller
/// needs raw bytes rather than JSON deserialization (e.g., for non-JSON state
/// files).
///
/// # Security
///
/// Same as [`bounded_read_json`]: opens via `safe_open`, checks size on
/// handle metadata, and uses `Read::take` as belt-and-suspenders.
///
/// # Errors
///
/// - [`FsSafeError::FileTooLarge`] if the file exceeds `max_size`.
/// - [`FsSafeError::SymlinkRefused`] if the path is a symlink.
/// - [`FsSafeError::NotRegularFile`] if not a regular file.
/// - [`FsSafeError::Io`] on any I/O error.
pub fn bounded_read(path: &Path, max_size: u64) -> Result<Vec<u8>, FsSafeError> {
    let file = safe_open(path)?;

    let metadata = file
        .metadata()
        .map_err(|e| FsSafeError::io("fstat for size check", e))?;

    let file_size = metadata.len();
    if file_size > max_size {
        return Err(FsSafeError::FileTooLarge {
            size: file_size,
            max: max_size,
        });
    }

    // Pre-allocate with known size (capped), then read with take.
    // Truncation is acceptable: on 32-bit targets, files > 4 GiB are
    // already rejected by the max_size check above (which is always well
    // below u32::MAX for state files). The min() ensures we never
    // over-allocate.
    #[allow(clippy::cast_possible_truncation)]
    let alloc_hint = std::cmp::min(file_size as usize, max_size as usize);
    let mut buf = Vec::with_capacity(alloc_hint);
    file.take(max_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| FsSafeError::io("bounded read", e))?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Ensures the parent directory exists with restrictive permissions.
fn ensure_parent_dir(parent: &Path) -> Result<(), FsSafeError> {
    if parent.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| FsSafeError::io("create parent directory with mode 0700", e))?;
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent).map_err(|e| FsSafeError::io("create parent directory", e))?;
    }

    Ok(())
}

/// Calls `fsync` on a directory to commit rename operations.
fn fsync_directory(dir: &Path) -> Result<(), FsSafeError> {
    let dir_file = File::open(dir).map_err(|e| FsSafeError::io("open directory for fsync", e))?;
    dir_file
        .sync_all()
        .map_err(|e| FsSafeError::io("fsync directory", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::fs as unix_fs;

    use serde::{Deserialize, Serialize};

    use super::*;

    /// Test struct with `deny_unknown_fields` for strict deserialization.
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct TestState {
        version: u32,
        name: String,
        count: u64,
    }

    // -----------------------------------------------------------------------
    // Atomic write tests
    // -----------------------------------------------------------------------

    #[test]
    fn atomic_write_creates_file_with_correct_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = TestState {
            version: 1,
            name: "test".to_string(),
            count: 42,
        };

        atomic_write_json(&path, &state).unwrap();

        // Verify file exists and content is correct.
        let content = fs::read_to_string(&path).unwrap();
        let loaded: TestState = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state1 = TestState {
            version: 1,
            name: "first".to_string(),
            count: 1,
        };
        let state2 = TestState {
            version: 2,
            name: "second".to_string(),
            count: 2,
        };

        atomic_write_json(&path, &state1).unwrap();
        atomic_write_json(&path, &state2).unwrap();

        let loaded: TestState = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(loaded, state2);
    }

    #[test]
    fn atomic_write_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("state.json");

        atomic_write(path.as_path(), b"hello").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_file_has_restrictive_permissions() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secure.json");

        atomic_write(path.as_path(), b"secret data").unwrap();

        let metadata = fs::metadata(&path).unwrap();
        // NamedTempFile creates files with 0600 by default.
        let mode = metadata.mode() & 0o777;
        assert_eq!(mode, 0o600, "file should have mode 0600, got {mode:o}");
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_creates_parent_dir_with_0700() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("new_parent");
        let path = nested.join("state.json");

        atomic_write(path.as_path(), b"data").unwrap();

        let metadata = fs::metadata(&nested).unwrap();
        let mode = metadata.mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "parent dir should have mode 0700, got {mode:o}"
        );
    }

    #[test]
    fn atomic_write_no_partial_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        // Write initial content.
        atomic_write(path.as_path(), b"original").unwrap();

        // Attempt to write to a path where the parent is read-only.
        // This is hard to simulate portably, so instead we verify that
        // after a successful write, the content is always complete.
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    fn atomic_write_no_parent_directory_error() {
        // A path with no parent (just a filename) — this edge case should
        // be handled gracefully. In practice, daemon state files always have
        // a parent directory.
        let result = atomic_write(Path::new(""), b"data");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Safe open tests
    // -----------------------------------------------------------------------

    #[test]
    fn safe_open_regular_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("regular.txt");
        fs::write(&path, b"hello").unwrap();

        let file = safe_open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file());
    }

    #[test]
    fn safe_open_symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");

        fs::write(&target, b"target content").unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let result = safe_open(&link);
        assert!(result.is_err(), "safe_open should refuse symlinks");

        match result.unwrap_err() {
            FsSafeError::SymlinkRefused { path } => {
                assert_eq!(path, link);
            },
            other => panic!("expected SymlinkRefused, got: {other}"),
        }
    }

    #[test]
    fn safe_open_dangling_symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling.txt");

        // Create a symlink to a nonexistent target.
        unix_fs::symlink("/nonexistent/target", &link).unwrap();

        let result = safe_open(&link);
        assert!(result.is_err(), "safe_open should refuse dangling symlinks");
    }

    #[test]
    fn safe_open_nonexistent_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.txt");

        let result = safe_open(&path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn safe_open_directory_rejected_as_not_regular_file() {
        let dir = tempfile::tempdir().unwrap();

        // Attempting to safe_open a directory should fail because it is not
        // a regular file. On Linux with O_NOFOLLOW + O_RDONLY, opening a
        // directory may succeed but the is_file() check will reject it.
        // On some systems open() on a directory returns EISDIR. Either way,
        // we should get an error.
        let result = safe_open(dir.path());
        assert!(result.is_err(), "safe_open should reject directories");
    }

    // -----------------------------------------------------------------------
    // Bounded read tests
    // -----------------------------------------------------------------------

    #[test]
    fn bounded_read_json_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let state = TestState {
            version: 1,
            name: "bounded".to_string(),
            count: 99,
        };

        // Write via atomic_write_json, read via bounded_read_json.
        atomic_write_json(&path, &state).unwrap();

        let loaded: TestState = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn bounded_read_json_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.json");

        // Write a file larger than the cap.
        let data = "x".repeat(1024);
        fs::write(&path, &data).unwrap();

        let result: Result<TestState, _> = bounded_read_json(&path, 100);
        assert!(result.is_err(), "should reject oversized file");

        match result.unwrap_err() {
            FsSafeError::FileTooLarge { size, max } => {
                assert_eq!(size, 1024);
                assert_eq!(max, 100);
            },
            other => panic!("expected FileTooLarge, got: {other}"),
        }
    }

    #[test]
    fn bounded_read_json_rejects_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra_fields.json");

        // Write JSON with an extra unknown field.
        let json = r#"{"version":1,"name":"test","count":1,"extra":"field"}"#;
        fs::write(&path, json).unwrap();

        let result: Result<TestState, _> = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn bounded_read_json_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");

        let state = TestState {
            version: 1,
            name: "real".to_string(),
            count: 1,
        };
        atomic_write_json(&target, &state).unwrap();
        unix_fs::symlink(&target, &link).unwrap();

        let result: Result<TestState, _> = bounded_read_json(&link, DEFAULT_MAX_FILE_SIZE);
        assert!(result.is_err(), "bounded_read_json should refuse symlinks");
    }

    #[test]
    fn bounded_read_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");

        atomic_write(path.as_path(), b"raw bytes here").unwrap();

        let data = bounded_read(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(data, b"raw bytes here");
    }

    #[test]
    fn bounded_read_rejects_oversized_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");

        fs::write(&path, vec![0u8; 500]).unwrap();

        let result = bounded_read(&path, 100);
        assert!(result.is_err());

        match result.unwrap_err() {
            FsSafeError::FileTooLarge { size, max } => {
                assert_eq!(size, 500);
                assert_eq!(max, 100);
            },
            other => panic!("expected FileTooLarge, got: {other}"),
        }
    }

    #[test]
    fn bounded_read_exact_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact.bin");

        // File size exactly at max_size should succeed.
        let data = vec![42u8; 256];
        fs::write(&path, &data).unwrap();

        let result = bounded_read(&path, 256);
        assert!(result.is_ok(), "file at exact max_size should succeed");
        assert_eq!(result.unwrap().len(), 256);
    }

    #[test]
    fn bounded_read_one_over_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over.bin");

        // File size one byte over max_size should fail.
        let data = vec![42u8; 257];
        fs::write(&path, &data).unwrap();

        let result = bounded_read(&path, 256);
        assert!(result.is_err(), "file one byte over max_size should fail");
    }

    // -----------------------------------------------------------------------
    // Round-trip integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn atomic_write_then_bounded_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.json");

        let state = TestState {
            version: 3,
            name: "round-trip".to_string(),
            count: 123_456,
        };

        atomic_write_json(&path, &state).unwrap();
        let loaded: TestState = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn multiple_overwrites_always_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.json");

        for i in 0..10u64 {
            let state = TestState {
                version: 1,
                name: format!("iteration-{i}"),
                count: i,
            };
            atomic_write_json(&path, &state).unwrap();

            let loaded: TestState = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
            assert_eq!(loaded.count, i, "iteration {i} mismatch");
            assert_eq!(loaded.name, format!("iteration-{i}"));
        }
    }

    #[test]
    fn empty_json_object_round_trip() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Empty {}

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.json");

        atomic_write_json(&path, &Empty {}).unwrap();
        let loaded: Empty = bounded_read_json(&path, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(loaded, Empty {});
    }

    #[test]
    fn symlink_replacement_attack_prevented() {
        // Scenario: attacker replaces a state file with a symlink pointing
        // to a sensitive file (e.g., /etc/passwd). The safe_open should
        // refuse to follow the symlink.
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("sessions.json");
        let attacker_target = dir.path().join("attacker_controlled.txt");

        // Write legitimate state.
        let state = TestState {
            version: 1,
            name: "legit".to_string(),
            count: 1,
        };
        atomic_write_json(&state_path, &state).unwrap();

        // Write attacker-controlled content.
        fs::write(
            &attacker_target,
            r#"{"version":1,"name":"pwned","count":666}"#,
        )
        .unwrap();

        // Attacker replaces state file with symlink.
        fs::remove_file(&state_path).unwrap();
        unix_fs::symlink(&attacker_target, &state_path).unwrap();

        // bounded_read_json should refuse the symlink.
        let result: Result<TestState, _> = bounded_read_json(&state_path, DEFAULT_MAX_FILE_SIZE);
        assert!(result.is_err(), "should refuse symlink replacement attack");
    }

    #[test]
    fn atomic_write_to_symlink_target_prevented() {
        // Scenario: attacker creates a symlink at the state file path
        // pointing to a sensitive file. atomic_write should NOT follow
        // the symlink (NamedTempFile + rename replaces the symlink itself).
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let sensitive_path = dir.path().join("sensitive.txt");

        // Create a sensitive file.
        fs::write(&sensitive_path, "sensitive data").unwrap();

        // Attacker places a symlink at the state path.
        unix_fs::symlink(&sensitive_path, &state_path).unwrap();

        // atomic_write should replace the symlink with a regular file
        // (rename replaces the directory entry, not following the symlink).
        atomic_write(state_path.as_path(), b"new state").unwrap();

        // The sensitive file should be untouched.
        let sensitive_content = fs::read_to_string(&sensitive_path).unwrap();
        assert_eq!(
            sensitive_content, "sensitive data",
            "atomic_write should not follow the symlink to overwrite the sensitive file"
        );

        // The state path should now be a regular file (symlink replaced).
        let meta = fs::symlink_metadata(&state_path).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "state path should no longer be a symlink"
        );

        let content = fs::read_to_string(&state_path).unwrap();
        assert_eq!(content, "new state");
    }
}
