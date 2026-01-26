//! Rate limiting for the webhook handler.
//!
//! Implements a simple in-memory rate limiter using a sliding window algorithm.
//! Rate limiting is applied per source IP address to prevent abuse.
//!
//! # Configuration
//!
//! - `max_requests`: Maximum number of requests allowed in the window
//! - `window_secs`: Size of the sliding window in seconds
//!
//! # Thread Safety
//!
//! The rate limiter is thread-safe using `RwLock` for the internal state.
//! This is required because axum handlers may run concurrently.
//!
//! # Memory Management
//!
//! To prevent unbounded memory growth from attackers spoofing IP addresses,
//! the rate limiter calls `cleanup()` probabilistically on every Nth request
//! (default: every 100 requests). This removes entries for IPs that have no
//! recent requests within the time window.
//!
//! # Invariant
//!
//! - [INV-WH002] Rate limiter state is thread-safe.
//! - [INV-WH003] Cleanup is called periodically to bound memory usage.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::error::WebhookError;

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the window.
    pub max_requests: u32,

    /// Size of the sliding window in seconds.
    pub window_secs: u64,

    /// How often to run cleanup (every N requests).
    ///
    /// A lower value means more frequent cleanup but slightly higher overhead.
    /// A higher value means less frequent cleanup but more potential memory
    /// usage. Default: 100 requests.
    pub cleanup_interval: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Allow 60 requests per minute by default (reasonable for CI webhooks)
            max_requests: 60,
            window_secs: 60,
            // Run cleanup every 100 requests to bound memory growth
            cleanup_interval: 100,
        }
    }
}

/// An in-memory rate limiter using a sliding window algorithm.
///
/// The rate limiter tracks request timestamps per IP address and rejects
/// requests that exceed the configured limit within the time window.
///
/// To prevent unbounded memory growth (denial of service via IP spoofing), the
/// limiter calls `cleanup()` probabilistically based on `cleanup_interval`.
pub struct RateLimiter {
    config: RateLimitConfig,
    // Maps IP addresses to a list of request timestamps
    state: RwLock<HashMap<IpAddr, Vec<Instant>>>,
    // Counter for probabilistic cleanup (INV-WH003)
    request_count: AtomicU64,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: RwLock::new(HashMap::new()),
            request_count: AtomicU64::new(0),
        }
    }

    /// Checks if a request from the given IP should be allowed.
    ///
    /// If allowed, records the request and returns `Ok(())`.
    /// If rate limited, returns `Err(WebhookError::RateLimitExceeded)`.
    ///
    /// This method also calls `cleanup()` probabilistically (every N requests,
    /// configured by `cleanup_interval`) to prevent unbounded memory growth
    /// from IP address spoofing attacks (INV-WH003).
    ///
    /// # Arguments
    ///
    /// * `ip` - The source IP address of the request
    ///
    /// # Errors
    ///
    /// Returns `WebhookError::RateLimitExceeded` if the request would exceed
    /// the rate limit.
    pub fn check(&self, ip: IpAddr) -> Result<(), WebhookError> {
        let now = Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_secs);
        let cutoff = now.checked_sub(window_duration).unwrap_or(now);

        // Probabilistic cleanup to bound memory growth (INV-WH003)
        // We use fetch_add with Relaxed ordering because:
        // 1. We don't need synchronization with other memory operations
        // 2. The occasional missed or duplicate cleanup is acceptable
        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        if count > 0 && count % self.config.cleanup_interval == 0 {
            tracing::debug!(
                request_count = count,
                "running periodic rate limiter cleanup"
            );
            self.cleanup();
        }

        // First, try to read and check without write lock
        {
            let state = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(timestamps) = state.get(&ip) {
                let recent_count = timestamps.iter().filter(|&&t| t > cutoff).count();
                if recent_count >= self.config.max_requests as usize {
                    tracing::warn!(
                        ip = %ip,
                        requests = recent_count,
                        max = self.config.max_requests,
                        "rate limit exceeded"
                    );
                    return Err(WebhookError::RateLimitExceeded);
                }
            }
        }

        // If we get here, we need to record the request
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let timestamps = state.entry(ip).or_default();

        // Remove old timestamps outside the window
        timestamps.retain(|&t| t > cutoff);

        // Check again after cleanup (race condition protection)
        if timestamps.len() >= self.config.max_requests as usize {
            tracing::warn!(
                ip = %ip,
                requests = timestamps.len(),
                max = self.config.max_requests,
                "rate limit exceeded"
            );
            return Err(WebhookError::RateLimitExceeded);
        }

        // Record this request
        timestamps.push(now);

        Ok(())
    }

    /// Cleans up old entries from the rate limiter state.
    ///
    /// This should be called periodically to prevent memory growth.
    /// It removes all IP addresses that have no recent requests.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_secs);
        let cutoff = now.checked_sub(window_duration).unwrap_or(now);

        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Remove entries with no recent timestamps
        state.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }

    /// Returns the number of tracked IP addresses.
    ///
    /// Useful for monitoring and debugging.
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn another_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
    }

    #[test]
    fn test_allows_requests_within_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn test_rejects_when_limit_exceeded() {
        let config = RateLimitConfig {
            max_requests: 3,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Allow first 3 requests
        for _ in 0..3 {
            assert!(limiter.check(ip).is_ok());
        }

        // 4th request should be rejected
        let result = limiter.check(ip);
        assert!(matches!(result, Err(WebhookError::RateLimitExceeded)));
    }

    #[test]
    fn test_different_ips_tracked_separately() {
        let config = RateLimitConfig {
            max_requests: 2,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip1 = test_ip();
        let ip2 = another_ip();

        // IP1 uses 2 requests
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(matches!(
            limiter.check(ip1),
            Err(WebhookError::RateLimitExceeded)
        ));

        // IP2 should still have its own quota
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip2).is_ok());
        assert!(matches!(
            limiter.check(ip2),
            Err(WebhookError::RateLimitExceeded)
        ));
    }

    #[test]
    fn test_window_expiration() {
        let config = RateLimitConfig {
            max_requests: 2,
            // Use a very short window for testing
            window_secs: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Use up the quota
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(matches!(
            limiter.check(ip),
            Err(WebhookError::RateLimitExceeded)
        ));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let config = RateLimitConfig {
            max_requests: 10,
            window_secs: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Add entries for multiple IPs
        for i in 0..5 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
            limiter.check(ip).unwrap();
        }

        assert_eq!(limiter.tracked_ips(), 5);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Cleanup should remove all entries
        limiter.cleanup();
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 60);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.cleanup_interval, 100);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let config = RateLimitConfig {
            max_requests: 100,
            window_secs: 60,
            ..Default::default()
        };
        let limiter = Arc::new(RateLimiter::new(config));
        let ip = test_ip();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    for _ in 0..10 {
                        let _ = limiter.check(ip);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // After 100 requests (10 threads * 10 requests), we should be at limit
        // Next request should be rejected
        assert!(matches!(
            limiter.check(ip),
            Err(WebhookError::RateLimitExceeded)
        ));
    }

    /// Test that cleanup is called probabilistically to prevent memory
    /// exhaustion.
    ///
    /// This test verifies INV-WH003: cleanup is called periodically to bound
    /// memory usage. It simulates an attacker sending requests from many
    /// unique IP addresses and verifies that old entries are cleaned up
    /// after the window expires.
    #[test]
    fn test_probabilistic_cleanup_bounds_memory() {
        let config = RateLimitConfig {
            max_requests: 100,
            // Short window so entries expire quickly
            window_secs: 1,
            // Cleanup every 10 requests for faster testing
            cleanup_interval: 10,
        };
        let limiter = RateLimiter::new(config);

        // Simulate requests from 50 unique IPs (simulating IP spoofing attack)
        for i in 0..50 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            limiter.check(ip).unwrap();
        }

        // Should have 50 tracked IPs
        assert_eq!(limiter.tracked_ips(), 50);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Send more requests to trigger cleanup (at request 60, 70, etc.)
        // Since we're at request 50, the next cleanup will be at request 60
        for i in 50..65 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            limiter.check(ip).unwrap();
        }

        // After cleanup, old expired entries should be removed.
        // We added 15 new IPs (50..65), and cleanup should have removed
        // the 50 expired entries. We should have around 15 IPs tracked.
        let tracked = limiter.tracked_ips();
        assert!(
            tracked <= 20,
            "Expected cleanup to remove expired entries, but got {tracked} tracked IPs"
        );
    }

    /// Test that request counter increments correctly and triggers cleanup.
    #[test]
    fn test_request_counter_increments() {
        let config = RateLimitConfig {
            max_requests: 100,
            window_secs: 60,
            cleanup_interval: 5,
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Make 6 requests
        for _ in 0..6 {
            limiter.check(ip).unwrap();
        }

        // Verify counter has incremented (cleanup should have run at request 5)
        let count = limiter.request_count.load(Ordering::Relaxed);
        assert_eq!(count, 6);
    }
}
