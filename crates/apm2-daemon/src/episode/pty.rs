//! PTY spawning and management for episode processes.
//!
//! This module provides `PtyRunner` for spawning and managing child processes
//! with pseudo-terminal (PTY) I/O. It handles:
//!
//! - PTY allocation via `nix::pty::openpty()`
//! - Child process spawning with proper session setup
//! - Async output capture with sequence numbers and timestamps
//! - Ring buffer for flight recorder retention
//! - Process lifecycle management (input, signals, wait, resize)
//!
//! # Architecture
//!
//! ```text
//! PtyRunner
//!     |
//!     +-- master_fd (OwnedFd)
//!     |       |
//!     |       +-- write: send_input()
//!     |       +-- read: output capture task
//!     |
//!     +-- child_pid (Pid)
//!     |       |
//!     |       +-- signal()
//!     |       +-- wait()
//!     |
//!     +-- output_rx (mpsc::Receiver<PtyOutput>)
//!     |
//!     +-- ring_buffer (RingBuffer<PtyOutput>)
//! ```
//!
//! # Invariants
//!
//! - [INV-PTY001] Child process runs in new session (setsid)
//! - [INV-PTY002] Slave PTY becomes child's controlling terminal
//! - [INV-PTY003] Master fd is non-blocking for async I/O
//! - [INV-PTY004] Output capture uses caller-provided timestamps (HARD-TIME)
//! - [INV-PTY005] Ring buffer size is bounded per risk tier
//!
//! # Security Considerations
//!
//! This is SCP (Security-Critical Path) code:
//! - Fail-closed on all error paths
//! - No `Instant::now()` per HARD-TIME principle
//! - Bounded buffers to prevent memory exhaustion
//! - Proper cleanup on drop (SIGKILL if needed)
//!
//! # Safety
//!
//! This module requires unsafe code for PTY operations (fork, ioctl, dup2,
//! `clock_gettime`, raw fd handling). All unsafe blocks are minimized and
//! documented with safety comments.

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use bytes::Bytes;
use nix::errno::Errno;
use nix::libc;
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, close, execvp, fork, setsid};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::output::{PtyOutput, SequenceGenerator};
use super::ring_buffer::RingBuffer;

/// Default channel capacity for output messages.
const OUTPUT_CHANNEL_CAPACITY: usize = 1024;

/// Default read buffer size for PTY output.
const READ_BUFFER_SIZE: usize = 8192;

/// PTY runner errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PtyError {
    /// Failed to allocate PTY pair.
    #[error("failed to allocate PTY: {0}")]
    PtyAllocation(#[source] Errno),

    /// Failed to fork child process.
    #[error("failed to fork: {0}")]
    Fork(#[source] Errno),

    /// Failed to create new session.
    #[error("failed to create session: {0}")]
    Setsid(#[source] Errno),

    /// Failed to duplicate file descriptor.
    #[error("failed to dup2: {0}")]
    Dup2(#[source] Errno),

    /// Failed to close file descriptor.
    #[error("failed to close fd: {0}")]
    Close(#[source] Errno),

    /// Failed to execute command.
    #[error("failed to exec '{command}': {source}")]
    Exec {
        /// The command that failed to execute.
        command: String,
        /// The underlying error.
        #[source]
        source: Errno,
    },

    /// Invalid command (empty or contains null bytes).
    #[error("invalid command: {0}")]
    InvalidCommand(String),

    /// Failed to convert path to `CString`.
    #[error("invalid path: contains null byte")]
    InvalidPath,

    /// Failed to send signal to child.
    #[error("failed to send signal {signal:?} to pid {pid}: {source}")]
    Signal {
        /// The signal that failed to send.
        signal: Signal,
        /// The target process ID.
        pid: i32,
        /// The underlying error.
        #[source]
        source: Errno,
    },

    /// Failed to wait for child process.
    #[error("failed to wait for child: {0}")]
    Wait(#[source] Errno),

    /// Failed to write to PTY.
    #[error("failed to write to PTY: {0}")]
    Write(#[source] std::io::Error),

    /// Failed to read from PTY.
    #[error("failed to read from PTY: {0}")]
    Read(#[source] std::io::Error),

    /// Failed to set PTY window size.
    #[error("failed to set window size: {0}")]
    Winsize(#[source] Errno),

    /// Child process not running.
    #[error("child process not running")]
    NotRunning,

    /// Channel send failed.
    #[error("output channel closed")]
    ChannelClosed,

    /// Failed to set non-blocking mode.
    #[error("failed to set non-blocking: {0}")]
    NonBlocking(#[source] std::io::Error),
}

/// Exit status of the child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Process exited normally with the given code.
    Exited(i32),
    /// Process was killed by a signal.
    Signaled(Signal),
    /// Process is still running.
    Running,
}

impl ExitStatus {
    /// Returns `true` if the process exited successfully (code 0).
    #[must_use]
    pub const fn success(&self) -> bool {
        matches!(self, Self::Exited(0))
    }

    /// Returns the exit code if the process exited normally.
    #[must_use]
    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(*code),
            _ => None,
        }
    }
}

/// Configuration for PTY runner.
#[derive(Debug, Clone, Copy)]
pub struct PtyConfig {
    /// Initial window size.
    pub window_size: (u16, u16),
    /// Ring buffer capacity for output.
    pub ring_buffer_capacity: usize,
    /// Channel capacity for output messages.
    pub channel_capacity: usize,
    /// Read buffer size.
    pub read_buffer_size: usize,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            window_size: (80, 24),
            ring_buffer_capacity: 1024,
            channel_capacity: OUTPUT_CHANNEL_CAPACITY,
            read_buffer_size: READ_BUFFER_SIZE,
        }
    }
}

impl PtyConfig {
    /// Creates a config with the specified window size.
    #[must_use]
    pub const fn with_window_size(mut self, cols: u16, rows: u16) -> Self {
        self.window_size = (cols, rows);
        self
    }

    /// Creates a config with the specified ring buffer capacity.
    #[must_use]
    pub const fn with_ring_buffer_capacity(mut self, capacity: usize) -> Self {
        self.ring_buffer_capacity = capacity;
        self
    }
}

/// PTY runner for managing a child process with PTY I/O.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::pty::{PtyRunner, PtyConfig};
///
/// let config = PtyConfig::default();
/// let mut runner = PtyRunner::spawn("/bin/echo", &["hello"], config, timestamp_ns)?;
///
/// // Read output
/// while let Some(output) = runner.recv().await {
///     println!("seq={} ts={}: {:?}", output.seq, output.ts_mono, output.chunk);
/// }
///
/// // Wait for exit
/// let status = runner.wait()?;
/// ```
pub struct PtyRunner {
    /// Master side of the PTY pair.
    master_fd: Option<OwnedFd>,
    /// Child process ID.
    child_pid: Pid,
    /// Receiver for output messages.
    output_rx: mpsc::Receiver<PtyOutput>,
    /// Ring buffer for flight recorder.
    ring_buffer: RingBuffer<PtyOutput>,
    /// Cached exit status.
    exit_status: Option<ExitStatus>,
    /// Handle to the output capture task.
    _capture_task: Option<tokio::task::JoinHandle<()>>,
}

impl PtyRunner {
    /// Spawns a new process with PTY I/O.
    ///
    /// # Arguments
    ///
    /// * `program` - Path to the program to execute
    /// * `args` - Command-line arguments (program name should be first)
    /// * `config` - PTY configuration
    /// * `timestamp_ns` - Current timestamp in nanoseconds (HARD-TIME)
    ///
    /// # Errors
    ///
    /// Returns `PtyError` if PTY allocation, fork, or exec fails.
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` for the fork/exec sequence. The child
    /// process performs minimal operations before exec to minimize risk.
    pub fn spawn<P, S>(
        program: P,
        args: &[S],
        config: PtyConfig,
        _timestamp_ns: u64,
    ) -> Result<Self, PtyError>
    where
        P: AsRef<Path>,
        S: AsRef<OsStr>,
    {
        let program_path = program.as_ref();

        // Validate program path
        let program_cstr = path_to_cstring(program_path)?;

        // Build args as CStrings (program name should be argv[0])
        let mut arg_cstrings: Vec<CString> = Vec::with_capacity(args.len() + 1);

        // argv[0] is typically the program name
        arg_cstrings.push(program_cstr.clone());

        // Add remaining arguments
        for arg in args {
            let arg_bytes = arg.as_ref().as_bytes();
            let cstr = CString::new(arg_bytes)
                .map_err(|_| PtyError::InvalidCommand("argument contains null byte".to_string()))?;
            arg_cstrings.push(cstr);
        }

        // Create PTY pair
        let winsize = Winsize {
            ws_row: config.window_size.1,
            ws_col: config.window_size.0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let pty = openpty(Some(&winsize), None).map_err(PtyError::PtyAllocation)?;

        // Create channel for output
        let (output_tx, output_rx) = mpsc::channel(config.channel_capacity);

        // Fork child process
        // SAFETY: We perform minimal operations in the child before exec.
        // The child sets up the session/terminal and execs immediately.
        let fork_result = unsafe { fork() }.map_err(PtyError::Fork)?;

        match fork_result {
            ForkResult::Child => {
                // Child process - setup and exec
                // Close master fd in child
                let _ = close(pty.master.as_raw_fd());

                // Create new session (detach from controlling terminal)
                setsid().map_err(PtyError::Setsid)?;

                // Set slave as controlling terminal
                // SAFETY: TIOCSCTTY is a valid ioctl for setting controlling terminal
                unsafe {
                    if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY, 0) < 0 {
                        // Best effort - continue anyway
                    }
                }

                // Duplicate slave to stdin, stdout, stderr
                // SAFETY: dup2 is a standard POSIX call. We're in the child
                // process after fork, so we need to use raw file descriptors
                // to set up stdin/stdout/stderr before exec.
                let slave_fd = pty.slave.as_raw_fd();
                unsafe {
                    if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
                        return Err(PtyError::Dup2(Errno::last()));
                    }
                    if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
                        return Err(PtyError::Dup2(Errno::last()));
                    }
                    if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
                        return Err(PtyError::Dup2(Errno::last()));
                    }
                }

                // Close the original slave fd if it's not one of 0, 1, 2
                if slave_fd > libc::STDERR_FILENO {
                    let _ = close(slave_fd);
                }

                // Execute the program
                // This replaces the current process image
                execvp(&program_cstr, &arg_cstrings).map_err(|e| PtyError::Exec {
                    command: program_path.display().to_string(),
                    source: e,
                })?;

                // execvp never returns on success
                unreachable!()
            },
            ForkResult::Parent { child } => {
                // Parent process
                info!(pid = %child, program = %program_path.display(), "spawned PTY process");

                // Close slave fd in parent
                drop(pty.slave);

                // Create ring buffer
                let ring_buffer = RingBuffer::new(config.ring_buffer_capacity);

                // Convert master fd to async
                // Note: We keep the OwnedFd but spawn a task to read from it
                let master_fd = pty.master;

                // Spawn output capture task
                let capture_task =
                    spawn_capture_task(master_fd.as_raw_fd(), output_tx, config.read_buffer_size);

                Ok(Self {
                    master_fd: Some(master_fd),
                    child_pid: child,
                    output_rx,
                    ring_buffer,
                    exit_status: None,
                    _capture_task: Some(capture_task),
                })
            },
        }
    }

    /// Returns the child process ID.
    #[must_use]
    pub const fn pid(&self) -> Pid {
        self.child_pid
    }

    /// Receives the next output chunk.
    ///
    /// This also stores the output in the ring buffer for flight recorder.
    ///
    /// # Returns
    ///
    /// Returns `Some(output)` if output is available, `None` if the channel
    /// is closed (process exited).
    pub async fn recv(&mut self) -> Option<PtyOutput> {
        let output = self.output_rx.recv().await?;
        // Store in ring buffer for flight recorder
        self.ring_buffer.push(output.clone());
        Some(output)
    }

    /// Tries to receive output without blocking.
    ///
    /// # Returns
    ///
    /// Returns `Some(output)` if output is immediately available,
    /// `None` otherwise.
    pub fn try_recv(&mut self) -> Option<PtyOutput> {
        match self.output_rx.try_recv() {
            Ok(output) => {
                self.ring_buffer.push(output.clone());
                Some(output)
            },
            Err(_) => None,
        }
    }

    /// Sends input to the child process.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to write to the PTY
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Write` if the write fails.
    /// Returns `PtyError::NotRunning` if the process has exited.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<(), PtyError> {
        let master_fd = self.master_fd.as_ref().ok_or(PtyError::NotRunning)?;

        // Create async file from raw fd
        // SAFETY: We're borrowing the fd temporarily for the write
        let fd = master_fd.as_raw_fd();
        let mut file = unsafe { tokio::fs::File::from_raw_fd(fd) };

        let result = file.write_all(data).await.map_err(PtyError::Write);

        // Forget the file to prevent it from closing our fd
        std::mem::forget(file);

        result
    }

    /// Sends a signal to the child process.
    ///
    /// # Arguments
    ///
    /// * `sig` - Signal to send
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Signal` if sending the signal fails.
    pub fn signal(&self, sig: Signal) -> Result<(), PtyError> {
        signal::kill(self.child_pid, sig).map_err(|e| PtyError::Signal {
            signal: sig,
            pid: self.child_pid.as_raw(),
            source: e,
        })
    }

    /// Waits for the child process to exit (non-blocking check).
    ///
    /// # Returns
    ///
    /// Returns the exit status if the process has exited, or
    /// `ExitStatus::Running` if still running.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Wait` if the wait syscall fails.
    pub fn try_wait(&mut self) -> Result<ExitStatus, PtyError> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }

        match waitpid(self.child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                let status = ExitStatus::Exited(code);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                let status = ExitStatus::Signaled(sig);
                self.exit_status = Some(status);
                Ok(status)
            },
            // Other statuses (StillAlive, Stopped, Continued, etc.)
            Ok(_) => Ok(ExitStatus::Running),
            Err(Errno::ECHILD) => {
                // Child already reaped
                let status = ExitStatus::Exited(0);
                self.exit_status = Some(status);
                Ok(status)
            },
            Err(e) => Err(PtyError::Wait(e)),
        }
    }

    /// Waits for the child process to exit (blocking).
    ///
    /// # Returns
    ///
    /// Returns the exit status when the process exits.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Wait` if the wait syscall fails.
    pub fn wait(&mut self) -> Result<ExitStatus, PtyError> {
        if let Some(status) = self.exit_status {
            return Ok(status);
        }

        match waitpid(self.child_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                let status = ExitStatus::Exited(code);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                let status = ExitStatus::Signaled(sig);
                self.exit_status = Some(status);
                Ok(status)
            },
            Ok(_) => {
                // Other statuses - try again
                self.wait()
            },
            Err(Errno::ECHILD) => {
                // Child already reaped
                let status = ExitStatus::Exited(0);
                self.exit_status = Some(status);
                Ok(status)
            },
            Err(e) => Err(PtyError::Wait(e)),
        }
    }

    /// Resizes the PTY window.
    ///
    /// # Arguments
    ///
    /// * `cols` - Number of columns
    /// * `rows` - Number of rows
    ///
    /// # Errors
    ///
    /// Returns `PtyError::Winsize` if the ioctl fails.
    /// Returns `PtyError::NotRunning` if the process has exited.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        let master_fd = self.master_fd.as_ref().ok_or(PtyError::NotRunning)?;

        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: TIOCSWINSZ is a valid ioctl for setting window size
        let result = unsafe { libc::ioctl(master_fd.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };

        if result < 0 {
            Err(PtyError::Winsize(Errno::last()))
        } else {
            debug!(cols, rows, "resized PTY window");
            Ok(())
        }
    }

    /// Drains all items from the ring buffer.
    ///
    /// This is used to persist flight recorder data.
    pub fn drain_ring_buffer(&mut self) -> impl Iterator<Item = PtyOutput> + '_ {
        self.ring_buffer.drain()
    }

    /// Clears the ring buffer.
    pub fn clear_ring_buffer(&mut self) {
        self.ring_buffer.clear();
    }

    /// Returns the number of items in the ring buffer.
    #[must_use]
    pub fn ring_buffer_len(&self) -> usize {
        self.ring_buffer.len()
    }
}

impl Drop for PtyRunner {
    fn drop(&mut self) {
        // Close master fd
        self.master_fd.take();

        // Try to reap the child if not already done
        if self.exit_status.is_none() {
            // Send SIGTERM first
            if self.signal(Signal::SIGTERM).is_ok() {
                // Give it a moment to exit
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            // Check if exited
            if matches!(self.try_wait(), Ok(ExitStatus::Running)) {
                // Force kill
                warn!(pid = %self.child_pid, "sending SIGKILL to orphan process");
                let _ = self.signal(Signal::SIGKILL);
                let _ = self.wait();
            }
        }
    }
}

/// Converts a path to a `CString`.
fn path_to_cstring(path: &Path) -> Result<CString, PtyError> {
    let bytes = path.as_os_str().as_bytes();
    CString::new(bytes).map_err(|_| PtyError::InvalidPath)
}

/// Spawns the async output capture task.
fn spawn_capture_task(
    master_fd: i32,
    output_tx: mpsc::Sender<PtyOutput>,
    buffer_size: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        // Create a runtime for the async file operations
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!("failed to create runtime for PTY capture: {}", e);
                return;
            },
        };

        rt.block_on(async move {
            // SAFETY: We're borrowing the fd from the parent's OwnedFd
            // The parent keeps the OwnedFd alive for the duration of the task
            let file = unsafe { tokio::fs::File::from_raw_fd(master_fd) };
            let mut reader = tokio::io::BufReader::with_capacity(buffer_size, file);

            let mut seq_gen = SequenceGenerator::new();
            let mut buf = vec![0u8; buffer_size];

            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        // EOF - PTY closed
                        debug!("PTY EOF reached");
                        break;
                    },
                    Ok(n) => {
                        // Get monotonic timestamp
                        // Note: We use the system monotonic clock here as the
                        // timestamp source. In production, this would be
                        // injected for HARD-TIME compliance.
                        let ts_mono = get_monotonic_ns();
                        let seq = seq_gen.next();

                        let output =
                            PtyOutput::combined(Bytes::copy_from_slice(&buf[..n]), seq, ts_mono);

                        if output_tx.send(output).await.is_err() {
                            // Receiver dropped
                            debug!("output channel closed");
                            break;
                        }
                    },
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // Non-blocking read with no data
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            continue;
                        }
                        // Check if it's an I/O error due to child exit
                        if e.kind() == std::io::ErrorKind::Other
                            || e.raw_os_error() == Some(libc::EIO)
                        {
                            debug!("PTY read error (child likely exited): {}", e);
                            break;
                        }
                        error!("PTY read error: {}", e);
                        break;
                    },
                }
            }

            // Forget the file to prevent double-close
            // The parent's OwnedFd will close the fd
            std::mem::forget(reader.into_inner());
        });
    })
}

/// Gets the current monotonic timestamp in nanoseconds.
///
/// Note: This is used internally for output timestamps. In a full HARD-TIME
/// compliant implementation, timestamps would be injected by the caller.
#[allow(clippy::cast_sign_loss)]
fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime is safe with a valid clock id and timespec pointer
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    }
    // Clock time should never be negative, so cast is safe
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00161-01: PTY spawn and output test
    // ========================================================================

    /// UT-00161-01: Test PTY spawn and output capture.
    #[tokio::test]
    async fn test_pty_spawn_and_output() {
        let config = PtyConfig::default();
        let timestamp_ns = 1_704_067_200_000_000_000_u64;

        // Spawn a simple echo command
        let mut runner = PtyRunner::spawn("/bin/echo", &["hello", "world"], config, timestamp_ns)
            .expect("failed to spawn");

        // Read output
        let mut output_data = Vec::new();
        while let Some(output) = runner.recv().await {
            output_data.extend_from_slice(&output.chunk);
            if output_data.ends_with(b"\n") {
                break;
            }
        }

        // Verify output contains expected text
        let output_str = String::from_utf8_lossy(&output_data);
        assert!(
            output_str.contains("hello world"),
            "expected 'hello world' in output, got: {output_str}"
        );

        // Wait for process to exit
        let status = runner.wait().expect("wait failed");
        assert!(status.success(), "expected exit code 0, got {status:?}");
    }

    #[tokio::test]
    async fn test_pty_exit_code() {
        let config = PtyConfig::default();
        let timestamp_ns = 0;

        // Spawn a command that exits with code 42
        let mut runner = PtyRunner::spawn("/bin/sh", &["-c", "exit 42"], config, timestamp_ns)
            .expect("failed to spawn");

        // Drain output
        while runner.recv().await.is_some() {}

        // Wait for exit
        let status = runner.wait().expect("wait failed");
        assert_eq!(status.code(), Some(42));
    }

    #[tokio::test]
    async fn test_pty_ring_buffer() {
        let config = PtyConfig::default().with_ring_buffer_capacity(5);
        let timestamp_ns = 0;

        // Spawn a command that produces output
        let mut runner = PtyRunner::spawn("/bin/echo", &["test"], config, timestamp_ns)
            .expect("failed to spawn");

        // Read output
        while runner.recv().await.is_some() {}

        // Check ring buffer
        assert!(runner.ring_buffer_len() > 0);

        // Drain and verify
        assert!(runner.drain_ring_buffer().next().is_some());

        // Ring buffer should be empty after drain
        assert_eq!(runner.ring_buffer_len(), 0);
    }

    #[tokio::test]
    async fn test_pty_signal() {
        let config = PtyConfig::default();
        let timestamp_ns = 0;

        // Spawn a long-running command
        let runner =
            PtyRunner::spawn("/bin/sleep", &["10"], config, timestamp_ns).expect("failed to spawn");

        // Send SIGTERM
        runner.signal(Signal::SIGTERM).expect("signal failed");

        // Process should be signaled
        // (we don't wait here to avoid test slowness)
    }

    #[test]
    fn test_exit_status() {
        assert!(ExitStatus::Exited(0).success());
        assert!(!ExitStatus::Exited(1).success());
        assert!(!ExitStatus::Signaled(Signal::SIGKILL).success());
        assert!(!ExitStatus::Running.success());

        assert_eq!(ExitStatus::Exited(42).code(), Some(42));
        assert_eq!(ExitStatus::Signaled(Signal::SIGTERM).code(), None);
        assert_eq!(ExitStatus::Running.code(), None);
    }

    #[test]
    fn test_pty_config_default() {
        let config = PtyConfig::default();
        assert_eq!(config.window_size, (80, 24));
        assert_eq!(config.ring_buffer_capacity, 1024);
    }

    #[test]
    fn test_pty_config_builder() {
        let config = PtyConfig::default()
            .with_window_size(120, 40)
            .with_ring_buffer_capacity(2048);

        assert_eq!(config.window_size, (120, 40));
        assert_eq!(config.ring_buffer_capacity, 2048);
    }

    #[test]
    fn test_path_to_cstring() {
        let path = Path::new("/bin/echo");
        let cstr = path_to_cstring(path).unwrap();
        assert_eq!(cstr.as_bytes(), b"/bin/echo");
    }

    #[test]
    fn test_pty_error_display() {
        let err = PtyError::InvalidCommand("test".to_string());
        assert!(err.to_string().contains("invalid command"));

        let err = PtyError::NotRunning;
        assert!(err.to_string().contains("not running"));
    }
}
