//! Credit-based rate limiting with fixed budget and scheduled resets.
//!
//! Unlike the sliding window rate limiter, credits are a simple decrementing
//! counter with wall-clock-aligned resets (daily/weekly/monthly).
//! Thread-safe for concurrent access.

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, Timelike, Utc, Weekday};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Result of a credit check.
#[derive(Debug, Clone, PartialEq)]
pub enum CreditResult {
    /// Request is allowed
    Allowed { remaining: u64 },
    /// Request is allowed but throttled (soft limit exceeded)
    Throttled { remaining: u64, delay_ms: u64 },
    /// Credits exhausted
    Exhausted {
        retry_after_secs: u64,
        reset_time: String,
    },
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
            .unwrap_or_else(Utc::now)
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
    pub fn check(&self, rule_name: &str, key: &str) -> CreditResult {
        let config = match self.configs.get(rule_name) {
            Some(c) => c.clone(),
            None => {
                return CreditResult::Allowed {
                    remaining: u64::MAX,
                };
            }
        };

        let now_epoch = Utc::now().timestamp() as u64;
        let bucket_key = format!("{}:{}", rule_name, key);

        let mut entry = self
            .buckets
            .entry(bucket_key)
            .or_insert_with(|| CreditBucket {
                used: AtomicU64::new(0),
                reset_at: AtomicU64::new(config.schedule.next_reset_after(now_epoch)),
                last_access: AtomicU64::new(now_epoch),
            });

        let bucket = entry.value_mut();
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
            return CreditResult::Exhausted {
                retry_after_secs: reset_at.saturating_sub(now_epoch),
                reset_time: ResetSchedule::format_reset_time(reset_at),
            };
        }

        let new_used = bucket.used.fetch_add(1, Ordering::Relaxed) + 1;
        let remaining = config.budget.saturating_sub(new_used);

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
            };
        }

        CreditResult::Allowed { remaining }
    }

    /// Format exhaustion message with {reset_time} interpolation.
    pub fn format_exhaustion_message(&self, rule_name: &str, reset_time: &str) -> String {
        match self.configs.get(rule_name) {
            Some(config) => config.message.replace("{reset_time}", reset_time),
            None => format!("Request credit exhausted until {}", reset_time),
        }
    }

    /// Remove buckets not accessed in 48 hours.
    pub fn force_cleanup(&self) {
        let now_epoch = Utc::now().timestamp() as u64;
        let expiry_secs = 48 * 3600;
        self.buckets.retain(|_, bucket| {
            now_epoch.saturating_sub(bucket.last_access.load(Ordering::Relaxed)) < expiry_secs
        });
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
        assert!(matches!(result, CreditResult::Allowed { remaining: 99 }));
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
            CreditResult::Allowed { remaining: 4 }
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

        if let Some(entry) = manager.buckets.get_mut("test-rule:user-1") {
            entry.last_access.store(0, Ordering::Relaxed);
        }
        manager.force_cleanup();
        assert_eq!(manager.buckets.len(), 0);
    }
}
