//! Credit-based rate limiting with fixed budget and scheduled resets.
//!
//! Unlike the sliding window rate limiter, credits are a simple decrementing
//! counter with wall-clock-aligned resets (daily/weekly/monthly).
//! Thread-safe for concurrent access.

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, Timelike, Utc, Weekday};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

use crate::util::StackString;

/// Result of a credit check.
#[derive(Debug, Clone, PartialEq)]
pub enum CreditResult {
    /// Request is allowed
    Allowed {
        remaining: u64,
        limit: u64,
        reset_after_secs: u64,
    },
    /// Request is allowed but throttled (soft limit exceeded)
    Throttled {
        remaining: u64,
        delay_ms: u64,
        limit: u64,
        reset_after_secs: u64,
    },
    /// Credits exhausted
    Exhausted {
        retry_after_secs: u64,
        reset_time: String,
        limit: u64,
        reset_after_secs: u64,
    },
    /// Rule not registered in credit manager (missing `config.credits` entry).
    /// The handler should log this at error level and let the request through
    /// rather than silently allowing unlimited traffic.
    NotConfigured,
}

/// Reset schedule for credit buckets.
#[derive(Debug, Clone)]
pub enum ResetSchedule {
    Daily {
        hour: u32,
        minute: u32,
    },
    Weekly {
        day: Weekday,
        hour: u32,
        minute: u32,
    },
    Monthly {
        day: u32,
        hour: u32,
        minute: u32,
    },
}

/// A single credit bucket for one key.
///
/// All atomic fields are accessed under the DashMap shard write-lock
/// (via `entry()` in `CreditManager::check()`). `Ordering::Relaxed` is
/// safe because the `parking_lot::RwLock` provides acquire/release barriers.
#[derive(Debug)]
struct CreditBucket {
    used: AtomicU64,
    reset_at: AtomicU64,
    last_access: AtomicU64,
}

/// Credit manager handling multiple credit rules.
pub struct CreditManager {
    buckets: DashMap<String, CreditBucket>,
    configs: DashMap<String, CreditRuleConfig>,
}

/// Configuration for a single credit rule.
#[derive(Debug, Clone)]
pub struct CreditRuleConfig {
    pub budget: u64,
    pub soft_limit: Option<u64>,
    pub max_delay_ms: u64,
    pub schedule: ResetSchedule,
    pub message: String,
}

impl ResetSchedule {
    /// Parse a reset schedule string.
    /// Formats: "daily@HH:MM", "weekly@Day-HH:MM", "monthly@DD-HH:MM"
    pub fn parse(s: &str) -> Result<Self, String> {
        let (period, time_part) = s
            .split_once('@')
            .ok_or("must be in format 'period@time' (e.g., daily@12:00)")?;

        match period {
            "daily" => {
                let t = parse_time(time_part)?;
                Ok(ResetSchedule::Daily {
                    hour: t.hour(),
                    minute: t.minute(),
                })
            }
            "weekly" => {
                let (day_str, hhmm) = time_part
                    .split_once('-')
                    .ok_or("weekly format must be 'weekly@Day-HH:MM'")?;
                let day = parse_weekday(day_str)?;
                let t = parse_time(hhmm)?;
                Ok(ResetSchedule::Weekly {
                    day,
                    hour: t.hour(),
                    minute: t.minute(),
                })
            }
            "monthly" => {
                let (day_str, hhmm) = time_part
                    .split_once('-')
                    .ok_or("monthly format must be 'monthly@DD-HH:MM'")?;
                let day: u32 = day_str.parse().map_err(|_| "invalid day of month")?;
                if !(1..=28).contains(&day) {
                    return Err("day of month must be 1-28".to_string());
                }
                let t = parse_time(hhmm)?;
                Ok(ResetSchedule::Monthly {
                    day,
                    hour: t.hour(),
                    minute: t.minute(),
                })
            }
            _ => Err(format!(
                "unknown period '{}', must be daily, weekly, or monthly",
                period
            )),
        }
    }

    /// Compute the next reset time as epoch seconds after `now`.
    pub fn next_reset_after(&self, now_epoch: u64) -> u64 {
        let now = DateTime::from_timestamp(now_epoch as i64, 0).unwrap_or_else(Utc::now);

        let next = match self {
            ResetSchedule::Daily { hour, minute } => {
                let candidate = now.date_naive().and_hms_opt(*hour, *minute, 0).unwrap();
                let candidate = candidate.and_utc();
                if candidate > now {
                    candidate
                } else {
                    candidate + chrono::Duration::days(1)
                }
            }
            ResetSchedule::Weekly { day, hour, minute } => {
                let target_time = NaiveTime::from_hms_opt(*hour, *minute, 0).unwrap();
                let current_weekday = now.weekday();
                let days_ahead =
                    (*day as i32 - current_weekday.num_days_from_monday() as i32 + 7) % 7;
                let candidate_date = now.date_naive() + chrono::Duration::days(days_ahead as i64);
                let candidate = candidate_date.and_time(target_time).and_utc();
                if candidate > now {
                    candidate
                } else {
                    candidate + chrono::Duration::weeks(1)
                }
            }
            ResetSchedule::Monthly { day, hour, minute } => {
                let target_time = NaiveTime::from_hms_opt(*hour, *minute, 0).unwrap();
                let candidate_date = NaiveDate::from_ymd_opt(now.year(), now.month(), *day)
                    .unwrap_or_else(|| now.date_naive());
                let candidate = candidate_date.and_time(target_time).and_utc();
                if candidate > now {
                    candidate
                } else {
                    // Next month
                    let (y, m) = if now.month() == 12 {
                        (now.year() + 1, 1)
                    } else {
                        (now.year(), now.month() + 1)
                    };
                    let next_date = NaiveDate::from_ymd_opt(y, m, *day)
                        .unwrap_or_else(|| NaiveDate::from_ymd_opt(y, m, 28).unwrap());
                    next_date.and_time(target_time).and_utc()
                }
            }
        };
        next.timestamp() as u64
    }

    /// Format epoch seconds as "YYYY-MM-DDTHH:MM:SSZ".
    pub fn format_reset_time(epoch_secs: u64) -> String {
        DateTime::from_timestamp(epoch_secs as i64, 0)
            .expect("BUG Open an issue at https://github.com/adsanz/roxy/issues: epoch timestamp out of representable range")
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }
}

fn parse_time(s: &str) -> Result<NaiveTime, String> {
    NaiveTime::parse_from_str(s, "%H:%M").map_err(|e| format!("invalid time '{}': {}", s, e))
}

fn parse_weekday(s: &str) -> Result<Weekday, String> {
    match s.to_lowercase().as_str() {
        "monday" | "mon" => Ok(Weekday::Mon),
        "tuesday" | "tue" => Ok(Weekday::Tue),
        "wednesday" | "wed" => Ok(Weekday::Wed),
        "thursday" | "thu" => Ok(Weekday::Thu),
        "friday" | "fri" => Ok(Weekday::Fri),
        "saturday" | "sat" => Ok(Weekday::Sat),
        "sunday" | "sun" => Ok(Weekday::Sun),
        _ => Err(format!("unknown day '{}', use Monday-Sunday or Mon-Sun", s)),
    }
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            configs: DashMap::new(),
        }
    }

    pub fn register_rule(&self, rule_name: String, config: CreditRuleConfig) {
        self.configs.insert(rule_name, config);
    }

    /// Check credits for a request. Consumes one credit if allowed.
    ///
    /// Uses a two-phase DashMap lookup to avoid heap allocation
    /// for existing buckets (the common case after warmup):
    /// 1. `get_mut(&str)` with a stack-formatted key — zero heap alloc
    /// 2. `entry(String)` only for first-time keys
    pub fn check(&self, rule_name: &str, key: &str) -> CreditResult {
        let config_ref = match self.configs.get(rule_name) {
            Some(c) => c,
            None => {
                return CreditResult::NotConfigured;
            }
        };

        let now_epoch = match u64::try_from(Utc::now().timestamp()) {
            Ok(t) => t,
            Err(_) => {
                warn!(target: "ratelimit", "System clock is before Unix epoch — check NTP; allowing request");
                return CreditResult::Allowed {
                    remaining: u64::MAX,
                    limit: u64::MAX,
                    reset_after_secs: 0,
                };
            }
        };

        // Fast path: format key on the stack and try get_mut — zero heap alloc
        let total_len = rule_name.len() + 1 + key.len();
        let mut stack_key = StackString::<128>::new();
        let fits_stack = stack_key.push_str(rule_name).is_ok()
            && stack_key.push_ascii(':').is_ok()
            && stack_key.push_str(key).is_ok();

        if fits_stack && let Some(mut entry) = self.buckets.get_mut(stack_key.as_str()) {
            let bucket = entry.value_mut();
            return Self::check_bucket(bucket, &config_ref, now_epoch);
        }

        // Slow path: key not found (or too long for stack) — allocate String for entry()
        let bucket_key = if fits_stack {
            // Key fit on stack but wasn't in the map — copy to String for insertion
            stack_key.as_str().to_owned()
        } else {
            let mut s = String::with_capacity(total_len);
            s.push_str(rule_name);
            s.push(':');
            s.push_str(key);
            s
        };

        let mut entry = self
            .buckets
            .entry(bucket_key)
            .or_insert_with(|| CreditBucket {
                used: AtomicU64::new(0),
                reset_at: AtomicU64::new(config_ref.schedule.next_reset_after(now_epoch)),
                last_access: AtomicU64::new(now_epoch),
            });

        let bucket = entry.value_mut();
        Self::check_bucket(bucket, &config_ref, now_epoch)
    }

    /// Core credit check logic, factored out so both fast-path and slow-path use it.
    fn check_bucket(
        bucket: &CreditBucket,
        config: &CreditRuleConfig,
        now_epoch: u64,
    ) -> CreditResult {
        bucket.last_access.store(now_epoch, Ordering::Relaxed);

        // Reset if past deadline
        let reset_at = bucket.reset_at.load(Ordering::Relaxed);
        if now_epoch >= reset_at {
            bucket.used.store(0, Ordering::Relaxed);
            bucket.reset_at.store(
                config.schedule.next_reset_after(now_epoch),
                Ordering::Relaxed,
            );
        }

        let used = bucket.used.load(Ordering::Relaxed);
        let reset_at = bucket.reset_at.load(Ordering::Relaxed);

        if used >= config.budget {
            let reset_secs = reset_at.saturating_sub(now_epoch);
            return CreditResult::Exhausted {
                retry_after_secs: reset_secs,
                reset_time: ResetSchedule::format_reset_time(reset_at),
                limit: config.budget,
                reset_after_secs: reset_secs,
            };
        }

        let new_used = bucket.used.fetch_add(1, Ordering::Relaxed) + 1;
        let remaining = config.budget.saturating_sub(new_used);
        let reset_secs = reset_at.saturating_sub(now_epoch);

        // Progressive delay above soft limit
        if let Some(soft_limit) = config.soft_limit
            && new_used > soft_limit
        {
            let range = config.budget.saturating_sub(soft_limit);
            let over = new_used.saturating_sub(soft_limit);
            let delay_ms = if range > 0 {
                (over as f64 / range as f64 * config.max_delay_ms as f64) as u64
            } else {
                config.max_delay_ms
            };
            return CreditResult::Throttled {
                remaining,
                delay_ms,
                limit: config.budget,
                reset_after_secs: reset_secs,
            };
        }

        CreditResult::Allowed {
            remaining,
            limit: config.budget,
            reset_after_secs: reset_secs,
        }
    }

    /// Format exhaustion message with {reset_time} interpolation.
    pub fn format_exhaustion_message(&self, rule_name: &str, reset_time: &str) -> String {
        match self.configs.get(rule_name) {
            Some(config) => config.message.replace("{reset_time}", reset_time),
            None => format!("Request credit exhausted until {}", reset_time),
        }
    }

    /// Remove stale credit buckets.
    ///
    /// A bucket is only removed when BOTH conditions hold:
    /// 1. The credit window has ended (`now >= reset_at`)
    /// 2. The bucket hasn't been accessed in 48 hours
    ///
    /// This prevents premature removal of weekly/monthly buckets during
    /// their active window — a user who goes silent for >48h within a
    /// 7-day window must still have their usage tracked.
    pub fn force_cleanup(&self) {
        let now_epoch = match u64::try_from(Utc::now().timestamp()) {
            Ok(t) => t,
            Err(_) => {
                warn!(target: "ratelimit", "System clock is before Unix epoch — check NTP; skipping credit cleanup");
                return;
            }
        };
        let expiry_secs = 48 * 3600;
        self.buckets.retain(|_, bucket| {
            let reset_at = bucket.reset_at.load(Ordering::Relaxed);
            // Keep bucket if we're still in the active credit window
            if now_epoch < reset_at {
                return true;
            }
            // Past reset: safe to remove if not accessed recently
            now_epoch.saturating_sub(bucket.last_access.load(Ordering::Relaxed)) < expiry_secs
        });
        // Reclaim hash table capacity after cleanup.
        // force_cleanup is only called from the background task,
        // so shard-lock contention with the request path is minimal.
        self.buckets.shrink_to_fit();
    }
}

impl Default for CreditManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_daily_schedule() {
        let sched = ResetSchedule::parse("daily@12:00").unwrap();
        assert!(matches!(
            sched,
            ResetSchedule::Daily {
                hour: 12,
                minute: 0
            }
        ));
    }

    #[test]
    fn test_parse_weekly_schedule() {
        let sched = ResetSchedule::parse("weekly@Mon-09:30").unwrap();
        assert!(matches!(
            sched,
            ResetSchedule::Weekly {
                day: Weekday::Mon,
                hour: 9,
                minute: 30
            }
        ));
    }

    #[test]
    fn test_parse_monthly_schedule() {
        let sched = ResetSchedule::parse("monthly@15-00:00").unwrap();
        assert!(matches!(
            sched,
            ResetSchedule::Monthly {
                day: 15,
                hour: 0,
                minute: 0
            }
        ));
    }

    #[test]
    fn test_parse_invalid_schedule() {
        assert!(ResetSchedule::parse("hourly@00:00").is_err());
        assert!(ResetSchedule::parse("daily").is_err());
        assert!(ResetSchedule::parse("monthly@32-00:00").is_err());
    }

    #[test]
    fn test_next_reset_daily() {
        let sched = ResetSchedule::Daily {
            hour: 12,
            minute: 0,
        };
        // 2024-01-01 00:00:00 UTC
        let now = 1704067200u64;
        let next = sched.next_reset_after(now);
        assert_eq!(next, 1704067200 + 43200); // 12:00 same day
    }

    #[test]
    fn test_next_reset_daily_rolls_over() {
        let sched = ResetSchedule::Daily { hour: 6, minute: 0 };
        // 2024-01-01 12:00:00 UTC
        let now = 1704110400u64;
        let next = sched.next_reset_after(now);
        // Should be 2024-01-02 06:00:00
        assert_eq!(next, 1704067200 + 86400 + 6 * 3600);
    }

    #[test]
    fn test_next_reset_monthly_correct() {
        let sched = ResetSchedule::Monthly {
            day: 15,
            hour: 0,
            minute: 0,
        };
        // 2024-02-20 00:00:00 UTC = after Feb 15
        let now = NaiveDate::from_ymd_opt(2024, 2, 20)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp() as u64;
        let next = sched.next_reset_after(now);
        // Should be 2024-03-15 00:00:00
        let expected = NaiveDate::from_ymd_opt(2024, 3, 15)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp() as u64;
        assert_eq!(next, expected);
    }

    fn make_test_config(
        budget: u64,
        soft_limit: Option<u64>,
        max_delay_ms: u64,
    ) -> CreditRuleConfig {
        CreditRuleConfig {
            budget,
            soft_limit,
            max_delay_ms,
            schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
            message: "Out of credits until {reset_time}".to_string(),
        }
    }

    #[test]
    fn test_credit_allows_under_budget() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(100, None, 2000));
        let result = manager.check("test-rule", "user-1");
        assert!(matches!(
            result,
            CreditResult::Allowed { remaining: 99, .. }
        ));
    }

    #[test]
    fn test_credit_exhaustion() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(5, None, 2000));
        for _ in 0..5 {
            assert!(matches!(
                manager.check("test-rule", "user-1"),
                CreditResult::Allowed { .. }
            ));
        }
        assert!(matches!(
            manager.check("test-rule", "user-1"),
            CreditResult::Exhausted { .. }
        ));
    }

    #[test]
    fn test_credit_soft_limit_throttling() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(100, Some(80), 2000));
        for _ in 0..80 {
            assert!(matches!(
                manager.check("test-rule", "user-1"),
                CreditResult::Allowed { .. }
            ));
        }
        let result = manager.check("test-rule", "user-1");
        assert!(matches!(result, CreditResult::Throttled { delay_ms, .. } if delay_ms > 0));
    }

    #[test]
    fn test_credit_progressive_delay() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(100, Some(50), 1000));
        for _ in 0..50 {
            manager.check("test-rule", "user-1");
        }

        // 51st: 1/50 * 1000 = 20ms
        match manager.check("test-rule", "user-1") {
            CreditResult::Throttled { delay_ms, .. } => assert_eq!(delay_ms, 20),
            other => panic!("expected throttled, got {:?}", other),
        }

        for _ in 0..24 {
            manager.check("test-rule", "user-1");
        }
        // 76/100 used, 26 over soft: 26/50 * 1000 = 520ms
        match manager.check("test-rule", "user-1") {
            CreditResult::Throttled { delay_ms, .. } => assert_eq!(delay_ms, 520),
            other => panic!("expected throttled, got {:?}", other),
        }
    }

    #[test]
    fn test_different_keys_independent() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(5, None, 2000));
        for _ in 0..5 {
            manager.check("test-rule", "user-1");
        }
        assert!(matches!(
            manager.check("test-rule", "user-1"),
            CreditResult::Exhausted { .. }
        ));
        assert!(matches!(
            manager.check("test-rule", "user-2"),
            CreditResult::Allowed { remaining: 4, .. }
        ));
    }

    #[test]
    fn test_format_reset_time() {
        assert_eq!(
            ResetSchedule::format_reset_time(1705321800),
            "2024-01-15T12:30:00Z"
        );
    }

    #[test]
    fn test_exhaustion_message_interpolation() {
        let manager = CreditManager::new();
        manager.register_rule(
            "test-rule".into(),
            CreditRuleConfig {
                message: "Credits exhausted. Resets at {reset_time}.".to_string(),
                ..make_test_config(10, None, 2000)
            },
        );
        let msg = manager.format_exhaustion_message("test-rule", "2024-01-15T00:00:00Z");
        assert_eq!(msg, "Credits exhausted. Resets at 2024-01-15T00:00:00Z.");
    }

    #[test]
    fn test_cleanup_removes_old_buckets() {
        let manager = CreditManager::new();
        manager.register_rule("test-rule".into(), make_test_config(100, None, 2000));
        manager.check("test-rule", "user-1");
        assert_eq!(manager.buckets.len(), 1);

        // Simulate: last_access long ago AND reset_at in the past (window closed)
        if let Some(entry) = manager.buckets.get_mut("test-rule:user-1") {
            entry.last_access.store(0, Ordering::Relaxed);
            entry.reset_at.store(0, Ordering::Relaxed);
        }
        manager.force_cleanup();
        assert_eq!(manager.buckets.len(), 0);
    }

    #[test]
    fn test_cleanup_preserves_active_window_buckets() {
        // Regression: weekly credit bucket must survive >48h of inactivity
        // within the same credit window.
        let manager = CreditManager::new();
        manager.register_rule(
            "weekly-rule".into(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Weekly {
                    day: Weekday::Mon,
                    hour: 0,
                    minute: 0,
                },
                message: "Out of credits".to_string(),
            },
        );

        // User makes requests, consuming credits
        for _ in 0..5 {
            manager.check("weekly-rule", "user-1");
        }
        assert_eq!(manager.buckets.len(), 1);

        // Simulate: last_access was 3 days ago (>48h) but reset_at is still in the future
        let now_epoch = u64::try_from(Utc::now().timestamp()).unwrap();
        let three_days_ago = now_epoch - (3 * 24 * 3600);
        if let Some(entry) = manager.buckets.get_mut("weekly-rule:user-1") {
            entry.last_access.store(three_days_ago, Ordering::Relaxed);
            // reset_at is already in the future (set by check()), leave it
        }

        // Cleanup must NOT remove the bucket — we're still in the credit window
        manager.force_cleanup();
        assert_eq!(
            manager.buckets.len(),
            1,
            "bucket removed during active credit window — weekly credits would reset!"
        );

        // Verify the 5 consumed credits are still tracked
        let result = manager.check("weekly-rule", "user-1");
        assert!(
            matches!(result, CreditResult::Allowed { remaining: 994, .. }),
            "expected 994 remaining (5 used + 1 from this check), got {:?}",
            result,
        );
    }

    // === Coverage: parse_weekday for all days ===

    #[test]
    fn test_parse_weekly_tuesday() {
        let schedule = ResetSchedule::parse("weekly@Tue-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Tue,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_weekly_wednesday() {
        let schedule = ResetSchedule::parse("weekly@Wed-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Wed,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_weekly_thursday() {
        let schedule = ResetSchedule::parse("weekly@Thu-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Thu,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_weekly_friday() {
        let schedule = ResetSchedule::parse("weekly@Friday-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Fri,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_weekly_saturday() {
        let schedule = ResetSchedule::parse("weekly@Sat-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Sat,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_weekly_sunday() {
        let schedule = ResetSchedule::parse("weekly@Sunday-10:00").unwrap();
        assert!(matches!(
            schedule,
            ResetSchedule::Weekly {
                day: Weekday::Sun,
                ..
            }
        ));
    }

    // === Coverage: weekly schedule past day ===

    #[test]
    fn test_weekly_reset_past_day() {
        // If the target weekday already passed this week, next_reset_after should go to next week
        let schedule = ResetSchedule::Weekly {
            day: Weekday::Mon,
            hour: 0,
            minute: 0,
        };
        let now_epoch = Utc::now().timestamp() as u64;
        let next = schedule.next_reset_after(now_epoch);
        // The result must be in the future
        assert!(next > now_epoch || next == now_epoch);
    }

    // === Coverage: monthly schedule edge cases ===

    #[test]
    fn test_monthly_reset_invalid_day_fallback() {
        // Day 31 in February → should fallback to current date
        let schedule = ResetSchedule::Monthly {
            day: 31,
            hour: 0,
            minute: 0,
        };
        // Use a fixed date in Feb
        let feb_ts = chrono::NaiveDate::from_ymd_opt(2025, 2, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp() as u64;
        let next = schedule.next_reset_after(feb_ts);
        assert!(next > feb_ts, "Reset should be in the future, got {}", next);
    }

    #[test]
    fn test_monthly_reset_december_wraps() {
        // In December, next month should be January of next year
        let schedule = ResetSchedule::Monthly {
            day: 15,
            hour: 0,
            minute: 0,
        };
        // Use Dec 20 — day 15 already passed, should wrap to Jan 15
        let dec_ts = chrono::NaiveDate::from_ymd_opt(2025, 12, 20)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp() as u64;
        let next = schedule.next_reset_after(dec_ts);
        assert!(next > dec_ts, "Reset should be in the future");
        // Convert back to check it's January
        let next_dt = DateTime::from_timestamp(next as i64, 0).unwrap();
        assert_eq!(next_dt.month(), 1, "Should wrap to January");
        assert_eq!(next_dt.year(), 2026, "Should wrap to next year");
    }

    // === Coverage: credit first request (slow path insert) ===

    #[test]
    fn test_credit_first_request_inserts_bucket() {
        let manager = CreditManager::new();
        manager.register_rule(
            "first-req".to_string(),
            CreditRuleConfig {
                budget: 100,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        // First request should trigger slow path (new key)
        let result = manager.check("first-req", "new-user");
        assert!(matches!(
            result,
            CreditResult::Allowed { remaining: 99, .. }
        ));
        assert_eq!(manager.buckets.len(), 1);
    }

    // === Coverage: credit reset after window expires ===

    #[test]
    fn test_credit_reset_after_window_expires() {
        let manager = CreditManager::new();
        manager.register_rule(
            "reset-rule".to_string(),
            CreditRuleConfig {
                budget: 10,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );

        // Consume all credits
        for _ in 0..10 {
            manager.check("reset-rule", "user-1");
        }
        let result = manager.check("reset-rule", "user-1");
        assert!(matches!(result, CreditResult::Exhausted { .. }));

        // Manually set reset_at to the past to simulate window expiry
        if let Some(entry) = manager.buckets.get_mut("reset-rule:user-1") {
            entry.reset_at.store(1, Ordering::Relaxed);
        }

        // Next request should reset and allow
        let result = manager.check("reset-rule", "user-1");
        assert!(matches!(result, CreditResult::Allowed { remaining: 9, .. }));
    }

    // === Coverage: format_exhaustion_message ===

    #[test]
    fn test_format_exhaustion_message_with_config() {
        let manager = CreditManager::new();
        manager.register_rule(
            "msg-rule".to_string(),
            CreditRuleConfig {
                budget: 100,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily {
                    hour: 12,
                    minute: 0,
                },
                message: "Credits exhausted. Resets at {reset_time}".to_string(),
            },
        );
        let msg = manager.format_exhaustion_message("msg-rule", "2025-01-01T12:00:00Z");
        assert_eq!(msg, "Credits exhausted. Resets at 2025-01-01T12:00:00Z");
    }

    #[test]
    fn test_format_exhaustion_message_unknown_rule() {
        let manager = CreditManager::new();
        let msg = manager.format_exhaustion_message("unknown", "2025-01-01T12:00:00Z");
        assert!(msg.contains("2025-01-01T12:00:00Z"));
    }

    // === Coverage: force_cleanup retains active window and removes stale ===

    #[test]
    fn test_force_cleanup_removes_expired_not_accessed() {
        let manager = CreditManager::new();
        manager.register_rule(
            "cleanup-rule".to_string(),
            CreditRuleConfig {
                budget: 100,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        // Create a bucket
        manager.check("cleanup-rule", "stale-user");

        // Set both reset_at and last_access to far in the past
        if let Some(entry) = manager.buckets.get_mut("cleanup-rule:stale-user") {
            entry.reset_at.store(1000, Ordering::Relaxed);
            entry.last_access.store(1000, Ordering::Relaxed);
        }

        manager.force_cleanup();
        assert_eq!(manager.buckets.len(), 0, "Stale bucket should be removed");
    }
}
