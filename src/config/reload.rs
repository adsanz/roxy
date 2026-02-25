//! Periodic config file reload.
//!
//! Spawns a background task that checks the config file for changes at a
//! configurable interval. On change, parses the new config, rebuilds rules
//! and header/throttle configs, and atomically swaps the shared config.
//!
//! Rate limiter state is preserved across reloads because the new `max_requests`
//! value from the DSL is applied to existing sliding windows on the next
//! `check()` call. Credit manager state is preserved by re-registering
//! credit rules with updated budgets (the `used` counters remain unchanged).

use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::config::ProxyConfig;
use crate::proxy::SharedConfig;
use crate::ratelimit::{CreditManager, CreditRuleConfig, ResetSchedule};
use crate::rules::RuleIndex;

/// Spawn a background task that periodically checks the config file for changes.
///
/// When changes are detected (byte-level comparison, no hashing overhead for
/// typical <10KB config files), the new config is parsed, rules are rebuilt,
/// and the `SharedConfig` is atomically swapped via `ArcSwap`.
///
/// Credit rules are re-registered with updated budgets so that in-flight
/// `used` counters are preserved while the ceiling changes immediately.
/// Rate limit changes take effect on the next `check()` call because the
/// new `max_requests` value from the DSL is applied to existing sliding windows.
///
/// Returns the `JoinHandle` for the spawned task.
///
/// # Arguments
///
/// * `config_path` - Path to the YAML config file
/// * `shared_config` - The ArcSwap holding the current hot-reloadable config
/// * `credit_manager` - The credit manager to re-register credit rules on reload
/// * `interval_secs` - How often to check for changes (seconds)
/// * `shutdown` - Notify handle for graceful shutdown
pub async fn spawn_config_watcher(
    config_path: PathBuf,
    shared_config: Arc<ArcSwap<SharedConfig>>,
    credit_manager: Arc<CreditManager>,
    interval_secs: u64,
    shutdown: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    // Read initial config bytes before spawning to avoid racing with caller writes
    let initial_bytes = tokio::fs::read(&config_path).await.unwrap_or_default();

    tokio::spawn(async move {
        let mut last_bytes = initial_bytes;
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        // Skip the immediate first tick (just loaded config)
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.notified() => {
                    info!(target: "reload", "Config watcher shutting down");
                    break;
                }
            }

            // Read config file — if it fails, log and skip this cycle
            let new_bytes = match tokio::fs::read(&config_path).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        target: "reload",
                        path = %config_path.display(),
                        error = %e,
                        "Failed to read config file, skipping reload check"
                    );
                    continue;
                }
            };

            // Byte-level comparison (faster than hashing for <10KB files)
            if new_bytes == last_bytes {
                continue;
            }

            info!(
                target: "reload",
                path = %config_path.display(),
                "Config file changed, reloading"
            );

            // Parse the new config
            let new_config = match std::str::from_utf8(&new_bytes) {
                Ok(s) => match s.parse::<ProxyConfig>() {
                    Ok(c) => c,
                    Err(e) => {
                        error!(
                            target: "reload",
                            error = %e,
                            "Failed to parse new config, keeping current config"
                        );
                        // Don't update last_bytes — retry on next cycle
                        continue;
                    }
                },
                Err(e) => {
                    error!(
                        target: "reload",
                        error = %e,
                        "Config file is not valid UTF-8, keeping current config"
                    );
                    continue;
                }
            };

            // Build new rule index
            let new_rules = match RuleIndex::from_config(&new_config.rules) {
                Ok(r) => r,
                Err(errors) => {
                    for e in &errors {
                        error!(target: "reload", error = %e, "Rule parse error in new config");
                    }
                    error!(
                        target: "reload",
                        count = errors.len(),
                        "Failed to parse rules in new config, keeping current config"
                    );
                    continue;
                }
            };

            // Warn about unreachable/duplicate rules in new config
            new_rules.warn_unreachable();
            new_rules.warn_duplicate_conditions();

            let rule_count = new_rules.rule_count();

            // Re-register credit rules with updated budgets.
            // Existing CreditBucket.used counters are preserved because
            // register_rule() only updates the configs DashMap, not the
            // buckets DashMap. This means changing budget from 100→200
            // keeps the current usage and adds the extra capacity.
            let credit_budgets: std::collections::HashMap<String, u64> =
                new_rules.credit_budgets().into_iter().collect();
            let mut credit_updates = 0u32;

            for credit_cfg in &new_config.credits {
                let schedule = match ResetSchedule::parse(&credit_cfg.reset_schedule) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            target: "reload",
                            rule = %credit_cfg.rule,
                            error = %e,
                            "Invalid credit reset schedule in new config, skipping credit update"
                        );
                        continue;
                    }
                };

                let budget = match credit_budgets.get(&credit_cfg.rule) {
                    Some(&b) => b,
                    None => {
                        warn!(
                            target: "reload",
                            rule = %credit_cfg.rule,
                            "Credit config references rule without credit() action, skipping"
                        );
                        continue;
                    }
                };

                // Cross-validate soft_limit < budget
                if let Some(soft_limit) = credit_cfg.soft_limit
                    && soft_limit >= budget
                {
                    warn!(
                        target: "reload",
                        rule = %credit_cfg.rule,
                        soft_limit = soft_limit,
                        budget = budget,
                        "Credit soft_limit >= budget, skipping credit update"
                    );
                    continue;
                }

                credit_manager.register_rule(
                    credit_cfg.rule.clone(),
                    CreditRuleConfig {
                        budget,
                        soft_limit: credit_cfg.soft_limit,
                        max_delay_ms: credit_cfg.max_delay_ms,
                        schedule,
                        message: credit_cfg.message.clone(),
                    },
                );
                credit_updates += 1;

                info!(
                    target: "reload",
                    rule = %credit_cfg.rule,
                    budget = budget,
                    reset_schedule = %credit_cfg.reset_schedule,
                    "Re-registered credit rule"
                );
            }

            // Reverse validation: every DSL credit() rule must have a config.credits entry
            let configured_credit_rules: std::collections::HashSet<&str> =
                new_config.credits.iter().map(|c| c.rule.as_str()).collect();
            let mut orphan_credit = false;
            for rule_name in credit_budgets.keys() {
                if !configured_credit_rules.contains(rule_name.as_str()) {
                    warn!(
                        target: "reload",
                        rule = %rule_name,
                        "DSL rule has credit() action but no matching entry in config.credits, rejecting reload"
                    );
                    orphan_credit = true;
                }
            }
            if orphan_credit {
                warn!(target: "reload", "Config reload rejected: orphan credit rules detected");
                continue;
            }

            // Build new shared config and atomically swap
            let new_shared = SharedConfig::new(new_rules, new_config.headers, new_config.throttle);
            shared_config.store(Arc::new(new_shared));

            // Update baseline for next comparison
            last_bytes = new_bytes;

            info!(
                target: "reload",
                rule_count = rule_count,
                credit_updates = credit_updates,
                "Config reloaded successfully"
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_watcher_detects_change() {
        let yaml1 = "listen: \"0.0.0.0:8080\"\nrules:\n  - name: \"r1\"\n    rule: 'host(\"a.com\") = block'\n";
        let yaml2 = "listen: \"0.0.0.0:8080\"\nrules:\n  - name: \"r1\"\n    rule: 'host(\"a.com\") = block'\n  - name: \"r2\"\n    rule: 'host(\"b.com\") = block'\n";

        // Write initial config
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, yaml1).unwrap();

        // Build initial shared config
        let config: ProxyConfig = yaml1.parse().unwrap();
        let rules = RuleIndex::from_config(&config.rules).unwrap();
        assert_eq!(rules.rule_count(), 1);
        let shared = SharedConfig::new(rules, config.headers, config.throttle);
        let arc = Arc::new(ArcSwap::from_pointee(shared));

        let shutdown = Arc::new(Notify::new());
        let credit_manager = Arc::new(CreditManager::new());

        // Spawn watcher with 1-second interval
        let _handle = spawn_config_watcher(
            config_path.clone(),
            Arc::clone(&arc),
            Arc::clone(&credit_manager),
            1,
            Arc::clone(&shutdown),
        )
        .await;

        // Verify initial state
        assert_eq!(arc.load().rules.rule_count(), 1);

        // Write new config
        std::fs::write(&config_path, yaml2).unwrap();

        // Wait for watcher to pick up the change
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify config was reloaded
        assert_eq!(arc.load().rules.rule_count(), 2);

        // Shutdown watcher
        shutdown.notify_waiters();
    }

    #[tokio::test]
    async fn test_watcher_ignores_invalid_config() {
        let yaml_valid = "listen: \"0.0.0.0:8080\"\nrules:\n  - name: \"r1\"\n    rule: 'host(\"a.com\") = block'\n";
        let yaml_invalid = "this is not valid yaml: [[[";

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, yaml_valid).unwrap();

        let config: ProxyConfig = yaml_valid.parse().unwrap();
        let rules = RuleIndex::from_config(&config.rules).unwrap();
        let shared = SharedConfig::new(rules, config.headers, config.throttle);
        let arc = Arc::new(ArcSwap::from_pointee(shared));

        let shutdown = Arc::new(Notify::new());
        let credit_manager = Arc::new(CreditManager::new());
        let _handle = spawn_config_watcher(
            config_path.clone(),
            Arc::clone(&arc),
            Arc::clone(&credit_manager),
            1,
            Arc::clone(&shutdown),
        )
        .await;

        // Write invalid config
        std::fs::write(&config_path, yaml_invalid).unwrap();

        // Wait for watcher cycle
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Config should remain unchanged (1 rule)
        assert_eq!(arc.load().rules.rule_count(), 1);

        shutdown.notify_waiters();
    }

    #[tokio::test]
    async fn test_watcher_updates_credit_budget_on_reload() {
        use crate::ratelimit::CreditResult;

        // Initial config: credit rule with budget 100
        let yaml1 = r#"listen: "0.0.0.0:8080"
rules:
  - name: "credit-rule"
    rule: 'host("api.example.com") = credit(100/d, header(X-Key))'
credits:
  - rule: "credit-rule"
    reset_schedule: "daily@00:00"
"#;
        // Updated config: same rule, budget bumped to 200
        let yaml2 = r#"listen: "0.0.0.0:8080"
rules:
  - name: "credit-rule"
    rule: 'host("api.example.com") = credit(200/d, header(X-Key))'
credits:
  - rule: "credit-rule"
    reset_schedule: "daily@00:00"
"#;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, yaml1).unwrap();

        // Set up initial state
        let config: ProxyConfig = yaml1.parse().unwrap();
        let rules = RuleIndex::from_config(&config.rules).unwrap();

        // Extract credit budgets before moving rules into SharedConfig
        let credit_budgets: std::collections::HashMap<String, u64> =
            rules.credit_budgets().into_iter().collect();

        let shared = SharedConfig::new(rules, config.headers.clone(), config.throttle.clone());
        let arc = Arc::new(ArcSwap::from_pointee(shared));

        let credit_manager = Arc::new(CreditManager::new());

        // Register credit rule with initial budget (as main.rs does)
        for credit_cfg in &config.credits {
            let schedule = ResetSchedule::parse(&credit_cfg.reset_schedule).unwrap();
            let budget = *credit_budgets.get(&credit_cfg.rule).unwrap();
            credit_manager.register_rule(
                credit_cfg.rule.clone(),
                CreditRuleConfig {
                    budget,
                    soft_limit: credit_cfg.soft_limit,
                    max_delay_ms: credit_cfg.max_delay_ms,
                    schedule,
                    message: credit_cfg.message.clone(),
                },
            );
        }

        // Use 50 credits
        for _ in 0..50 {
            let result = credit_manager.check("credit-rule", "user1");
            assert!(matches!(result, CreditResult::Allowed { .. }));
        }

        // Verify: 50 remaining out of 100
        if let CreditResult::Allowed {
            remaining, limit, ..
        } = credit_manager.check("credit-rule", "user1")
        {
            assert_eq!(limit, 100);
            assert_eq!(remaining, 49); // 50 used + this check = 51 used, 100 - 51 = 49
        } else {
            panic!("Expected Allowed");
        }

        let shutdown = Arc::new(Notify::new());
        let _handle = spawn_config_watcher(
            config_path.clone(),
            Arc::clone(&arc),
            Arc::clone(&credit_manager),
            1,
            Arc::clone(&shutdown),
        )
        .await;

        // Write updated config with budget 200
        std::fs::write(&config_path, yaml2).unwrap();

        // Wait for reload
        tokio::time::sleep(Duration::from_secs(2)).await;

        // After reload: budget is now 200, used is still 51
        // So remaining should be 200 - 52 = 148 (one more check)
        if let CreditResult::Allowed {
            remaining, limit, ..
        } = credit_manager.check("credit-rule", "user1")
        {
            assert_eq!(limit, 200);
            assert_eq!(remaining, 148); // 51 + 1 = 52 used, 200 - 52 = 148
        } else {
            panic!("Expected Allowed after budget increase");
        }

        shutdown.notify_waiters();
    }
}
