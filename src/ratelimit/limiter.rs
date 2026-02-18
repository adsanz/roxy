//! Sliding window rate limiter with DashMap storage.
//!
//! Uses a sliding window algorithm for smooth rate limiting.
//! Thread-safe for concurrent access.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Rate limiter with sliding window algorithm.
pub struct RateLimiter {
    /// Storage for rate limit counters keyed by string
    windows: DashMap<String, SlidingWindow>,

    /// Interval for cleanup of expired entries
    cleanup_interval: Duration,

    /// Last cleanup time (milliseconds since start_time)
    last_cleanup: AtomicU64,

    /// Baseline instant for computing elapsed time
    start_time: Instant,
}

/// Sliding window counter for a single key.
#[derive(Debug)]
pub struct SlidingWindow {
    /// Request count in current window
    current_count: AtomicU64,

    /// Request count in previous window
    previous_count: AtomicU64,

    /// Start time of current window (millis since RateLimiter start_time)
    window_start: AtomicU64,

    /// Last access time (millis since RateLimiter start_time)
    last_access: AtomicU64,

    /// Window duration in milliseconds
    window_ms: u64,

    /// Maximum requests per window
    max_requests: u64,
}

/// Result of a rate limit check.
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Remaining requests in current window
        remaining: u64,
    },
    /// Request is rate limited
    Limited {
        /// Seconds until the limit resets
        retry_after_secs: u64,
    },
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            windows: DashMap::new(),
            cleanup_interval,
            last_cleanup: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Check if a request should be allowed for the given key.
    ///
    /// Uses a two-phase lookup to avoid allocating a `String` for existing entries:
    /// 1. `get_mut(&str)` — zero-alloc fast-path for keys already in the map
    /// 2. `entry(key.to_string())` — allocates only on first sight of a new key
    pub fn check(&self, key: &str, max_requests: u64, window_secs: u64) -> RateLimitResult {
        let now = Instant::now();
        let now_ms = now.duration_since(self.start_time).as_millis() as u64;

        // Scope the DashMap access so the shard lock is released before
        // maybe_cleanup(). retain() acquires write-locks on every shard;
        // calling it while we still hold one causes a same-thread deadlock
        // because parking_lot::RwLock is not reentrant.
        let result = {
            // Fast path: key already exists — zero alloc, just get_mut with &str
            if let Some(window) = self.windows.get_mut(key) {
                window.check_and_increment(now_ms)
            } else {
                // Slow path: first time seeing this key — allocate String for entry()
                let mut entry = self
                    .windows
                    .entry(key.to_string())
                    .or_insert_with(|| SlidingWindow::new(max_requests, window_secs * 1000, now_ms));
                entry.value_mut().check_and_increment(now_ms)
            }
        }; // shard lock dropped here

        // Periodic cleanup — safe now, no shard lock held
        self.maybe_cleanup(now_ms);

        result
    }

    /// Get the number of tracked keys (for monitoring/testing).
    #[cfg(test)]
    pub fn key_count(&self) -> usize {
        self.windows.len()
    }

    /// Remove expired entries.
    fn maybe_cleanup(&self, now_ms: u64) {
        let last = self.last_cleanup.load(Ordering::Relaxed);
        let cleanup_interval_ms = self.cleanup_interval.as_millis() as u64;

        if now_ms - last > cleanup_interval_ms
            && self
                .last_cleanup
                .compare_exchange(last, now_ms, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
        {
            self.cleanup(now_ms);
        }
    }

    /// Compute elapsed milliseconds since the rate limiter was created.
    pub fn elapsed_ms(&self) -> u64 {
        Instant::now().duration_since(self.start_time).as_millis() as u64
    }

    /// Force a cleanup of expired entries. Called from background task.
    pub fn force_cleanup(&self) {
        let now_ms = self.elapsed_ms();
        // Update last_cleanup so maybe_cleanup() in check() does not
        // redundantly run cleanup right after the background task.
        self.last_cleanup.store(now_ms, Ordering::Relaxed);
        self.cleanup(now_ms);
    }

    /// Remove entries that haven't been accessed in 2 windows.
    fn cleanup(&self, now_ms: u64) {
        self.windows.retain(|_, window| {
            let last_access = window.last_access.load(Ordering::Relaxed);
            // Keep if accessed within last 2 windows
            now_ms.saturating_sub(last_access) < window.window_ms * 2
        });
        // Release hash table capacity freed by retain().
        // Without this, DashMap retains its high-water capacity forever.
        self.windows.shrink_to_fit();
    }
}

impl SlidingWindow {
    /// Create a new sliding window.
    fn new(max_requests: u64, window_ms: u64, now_ms: u64) -> Self {
        Self {
            current_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            window_start: AtomicU64::new(now_ms),
            last_access: AtomicU64::new(now_ms),
            window_ms,
            max_requests,
        }
    }

    /// Check if request is allowed and increment counter if so.
    ///
    /// # Safety invariant
    ///
    /// This method MUST be called while the caller holds the DashMap shard
    /// write-lock (via `entry()` or `get_mut()`). The shard lock serializes
    /// concurrent access to the same key, making the non-atomic
    /// load→compare→fetch_add sequence safe. `Ordering::Relaxed` is sufficient
    /// because the `parking_lot::RwLock` underlying DashMap provides
    /// acquire/release barriers on lock/unlock.
    fn check_and_increment(&self, now_ms: u64) -> RateLimitResult {
        // Update last access time
        self.last_access.store(now_ms, Ordering::Relaxed);

        self.maybe_rotate(now_ms);

        let window_start = self.window_start.load(Ordering::Relaxed);
        let elapsed_in_window = now_ms.saturating_sub(window_start);
        let window_progress = (elapsed_in_window as f64) / (self.window_ms as f64);

        // Sliding window: weighted average of current and previous
        let current = self.current_count.load(Ordering::Relaxed);
        let previous = self.previous_count.load(Ordering::Relaxed);

        let weighted_count = current as f64 + (previous as f64 * (1.0 - window_progress));

        if weighted_count < self.max_requests as f64 {
            self.current_count.fetch_add(1, Ordering::Relaxed);
            let remaining = (self.max_requests as f64 - weighted_count - 1.0).max(0.0) as u64;
            RateLimitResult::Allowed { remaining }
        } else {
            // Calculate retry-after
            let retry_after_ms = self.window_ms - elapsed_in_window;
            let retry_after_secs = (retry_after_ms / 1000).max(1);
            RateLimitResult::Limited { retry_after_secs }
        }
    }

    /// Rotate window if needed.
    ///
    /// # Safety invariant
    ///
    /// Must be called under DashMap shard write-lock (see `check_and_increment`).
    /// The three stores to `previous_count`, `current_count`, and `window_start`
    /// are effectively atomic as a group because the shard lock prevents
    /// concurrent access to the same key.
    fn maybe_rotate(&self, now_ms: u64) {
        let window_start = self.window_start.load(Ordering::Relaxed);

        if now_ms >= window_start + self.window_ms {
            // Need to rotate
            let current = self.current_count.load(Ordering::Relaxed);

            // Check if we missed multiple windows
            let windows_passed = (now_ms - window_start) / self.window_ms;

            if windows_passed >= 2 {
                // Reset both counters
                self.previous_count.store(0, Ordering::Relaxed);
            } else {
                // Normal rotation
                self.previous_count.store(current, Ordering::Relaxed);
            }

            self.current_count.store(0, Ordering::Relaxed);
            self.window_start.store(
                window_start + (windows_passed * self.window_ms),
                Ordering::Relaxed,
            );
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_under_limit() {
        let limiter = RateLimiter::new(Duration::from_secs(60));

        for i in 0..5 {
            let result = limiter.check("test-key", 10, 1);
            assert!(
                matches!(result, RateLimitResult::Allowed { remaining } if remaining == 10 - i - 1),
                "Expected allowed with {} remaining, got {:?}",
                10 - i - 1,
                result
            );
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(Duration::from_secs(60));

        // Use up the limit
        for _ in 0..10 {
            limiter.check("test-key", 10, 1);
        }

        // Next request should be limited
        let result = limiter.check("test-key", 10, 1);
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_different_keys_independent() {
        let limiter = RateLimiter::new(Duration::from_secs(60));

        // Use up limit for key1
        for _ in 0..10 {
            limiter.check("key1", 10, 1);
        }

        // key2 should still be allowed
        let result = limiter.check("key2", 10, 1);
        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }
}
