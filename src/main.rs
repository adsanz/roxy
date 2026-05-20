//! Roxy - High-performance forward HTTP/S proxy with MITM support
//!
//! Built on Hudsucker with a custom rule DSL.

// Use jemalloc on non-MSVC targets to avoid glibc malloc fragmentation.
// glibc retains high-water RSS indefinitely; jemalloc actively defragments.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use hudsucker::{
    Proxy,
    rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose},
    rustls::{ClientConfig, crypto::aws_lc_rs},
};
use hyper_util::client::legacy::Builder as ClientBuilder;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use arc_swap::ArcSwap;
use roxy::config::ProxyConfig;
use roxy::proxy::{RoxyAuthority, RoxyHandler, SharedConfig};
use roxy::ratelimit::{CreditManager, CreditRuleConfig, RateLimiter, ResetSchedule};
use roxy::rules::RuleIndex;

/// Command line arguments.
struct Args {
    config_path: PathBuf,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();

        // Handle --help and -h
        if args.iter().any(|a| a == "--help" || a == "-h") {
            eprintln!("Usage: roxy [OPTIONS]");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  -c, --config <FILE>  Path to config file [default: config.yaml]");
            eprintln!("  -h, --help           Print help information");
            eprintln!("  -V, --version        Print version information");
            std::process::exit(0);
        }

        // Handle --version and -V
        if args.iter().any(|a| a == "--version" || a == "-V") {
            eprintln!("roxy {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }

        let config_path = if let Some(pos) = args.iter().position(|a| a == "--config" || a == "-c")
        {
            args.get(pos + 1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("config.yaml"))
        } else if args.len() > 1 && !args[1].starts_with('-') {
            PathBuf::from(&args[1])
        } else {
            PathBuf::from("config.yaml")
        };

        Self { config_path }
    }
}

fn setup_logging() {
    // Set up tracing with JSON output
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();
}

/// Create a Certificate Authority for MITM.
/// Uses config if provided, otherwise generates an ephemeral CA.
fn create_ca(config: &ProxyConfig) -> RoxyAuthority {
    if let Some(tls_config) = &config.tls {
        // Load CA from files
        let key_pem = std::fs::read_to_string(&tls_config.ca_key)
            .unwrap_or_else(|e| {
                error!(target: "proxy", path = %tls_config.ca_key.display(), error = %e, "Failed to read CA key");
                std::process::exit(1);
            });

        // Warn if CA private key is readable by group or others (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&tls_config.ca_key) {
                let mode = meta.mode();
                if mode & 0o077 != 0 {
                    warn!(
                        target: "proxy",
                        path = %tls_config.ca_key.display(),
                        mode = format!("{:04o}", mode & 0o7777),
                        "CA private key is readable by group/others — consider chmod 600"
                    );
                }
            }
        }

        let cert_pem = std::fs::read_to_string(&tls_config.ca_cert)
            .unwrap_or_else(|e| {
                error!(target: "proxy", path = %tls_config.ca_cert.display(), error = %e, "Failed to read CA cert");
                std::process::exit(1);
            });

        let key_pair = KeyPair::from_pem(&key_pem).unwrap_or_else(|e| {
            error!(target: "proxy", error = %e, "Failed to parse CA key");
            std::process::exit(1);
        });

        let issuer = hudsucker::rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .unwrap_or_else(|e| {
                error!(target: "proxy", error = %e, "Failed to parse CA certificate");
                std::process::exit(1);
            });

        info!(target: "proxy", "Loaded CA from config");
        RoxyAuthority::new(
            issuer,
            &cert_pem,
            tls_config.cert_cache_size as u64,
            aws_lc_rs::default_provider(),
        )
    } else {
        // Generate ephemeral CA
        info!(target: "proxy", "Generating ephemeral CA (use tls config for persistent CA)");

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Roxy Proxy CA");
        dn.push(DnType::OrganizationName, "Roxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(hudsucker::rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key_pair = KeyPair::generate().expect("Failed to generate CA key");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to generate CA cert");
        let cert_pem = cert.pem();

        let issuer = hudsucker::rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .expect("Failed to create issuer from generated CA");

        RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider())
    }
}

/// Graceful shutdown signal handler.
/// Waits for Ctrl+C or SIGTERM (Unix), then notifies all background tasks.
async fn shutdown_signal(shutdown: Arc<tokio::sync::Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    error!(target: "proxy", error = %e, "Failed to listen for CTRL+C");
                }
                info!(target: "proxy", signal = "SIGINT", "Shutdown signal received");
            }
            _ = sigterm.recv() => {
                info!(target: "proxy", signal = "SIGTERM", "Shutdown signal received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(target: "proxy", error = %e, "Failed to listen for CTRL+C");
        }
        info!(target: "proxy", "Shutdown signal received");
    }
    shutdown.notify_waiters();
}

#[tokio::main]
async fn main() {
    setup_logging();

    let args = Args::parse();

    info!(
        target: "proxy",
        config = %args.config_path.display(),
        "Starting Roxy proxy"
    );

    // Load configuration
    let config = match ProxyConfig::from_file(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(target: "proxy", error = %e, "Failed to load configuration");
            std::process::exit(1);
        }
    };

    // Build rule index
    let rules = match RuleIndex::from_config(&config.rules) {
        Ok(r) => r,
        Err(errors) => {
            for e in &errors {
                error!(target: "proxy", error = %e, "Rule parse error");
            }
            error!(target: "proxy", count = errors.len(), "Failed to parse rules — fix all errors above");
            std::process::exit(1);
        }
    };

    info!(
        target: "proxy",
        rule_count = rules.rule_count(),
        "Loaded rules"
    );

    // Warn about unreachable rules (ternary rules shadow subsequent rules)
    rules.warn_unreachable();

    // Warn about rules with duplicate conditions (only first can ever match)
    rules.warn_duplicate_conditions();

    // Create rate limiter
    let cleanup_interval = config
        .rate_limit
        .as_ref()
        .map(|rl| std::time::Duration::from_secs(rl.cleanup_interval_secs))
        .unwrap_or(std::time::Duration::from_secs(60));

    let rate_limiter = Arc::new(RateLimiter::new(cleanup_interval));

    // Shutdown signal for background tasks
    let shutdown = Arc::new(tokio::sync::Notify::new());

    // Spawn background cleanup task for rate limiter.
    // Cleanup is also piggybacked on check() calls, but with low traffic
    // or no rate-limit rules matching, check() may never be called.
    let cleanup_limiter = Arc::clone(&rate_limiter);
    let shutdown_rl = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        interval.tick().await; // Skip immediate first tick
        loop {
            tokio::select! {
                _ = interval.tick() => cleanup_limiter.force_cleanup(),
                _ = shutdown_rl.notified() => break,
            }
        }
    });

    // Create credit manager and register credit rules from config
    let credit_manager = Arc::new(CreditManager::new());

    // Get credit budgets from parsed DSL rules
    let credit_budgets: std::collections::HashMap<String, u64> =
        rules.credit_budgets().into_iter().collect();

    for credit_cfg in &config.credits {
        let schedule = match ResetSchedule::parse(&credit_cfg.reset_schedule) {
            Ok(s) => s,
            Err(e) => {
                error!(target: "proxy", rule = %credit_cfg.rule, error = %e, "Invalid credit reset schedule");
                std::process::exit(1);
            }
        };

        let budget = match credit_budgets.get(&credit_cfg.rule) {
            Some(&b) => b,
            None => {
                error!(target: "proxy", rule = %credit_cfg.rule, "Credit config references rule without credit() action in DSL");
                std::process::exit(1);
            }
        };

        // Cross-validate: soft_limit must be less than budget
        if let Some(soft_limit) = credit_cfg.soft_limit
            && soft_limit >= budget
        {
            error!(
                target: "proxy",
                rule = %credit_cfg.rule,
                soft_limit = soft_limit,
                budget = budget,
                "Credit soft_limit ({}) must be less than budget ({})",
                soft_limit,
                budget
            );
            std::process::exit(1);
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
        info!(
            target: "proxy",
            rule = %credit_cfg.rule,
            budget = budget,
            reset_schedule = %credit_cfg.reset_schedule,
            "Registered credit rule"
        );
    }

    // Validate: every DSL credit() rule must have a matching config.credits entry
    let configured_credit_rules: std::collections::HashSet<&str> =
        config.credits.iter().map(|c| c.rule.as_str()).collect();
    for rule_name in credit_budgets.keys() {
        if !configured_credit_rules.contains(rule_name.as_str()) {
            error!(
                target: "proxy",
                rule = %rule_name,
                "DSL rule has credit() action but no matching entry in config.credits"
            );
            std::process::exit(1);
        }
    }

    // Spawn background cleanup task for credit manager
    let cleanup_credits = Arc::clone(&credit_manager);
    let shutdown_cr = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => cleanup_credits.force_cleanup(),
                _ = shutdown_cr.notified() => break,
            }
        }
    });

    // Build hot-reloadable shared config (rules + headers + throttle)
    let shared_config = SharedConfig::new(rules, config.headers.clone(), config.throttle.clone());
    let shared_config = Arc::new(ArcSwap::from_pointee(shared_config));

    // Create handler
    let handler = RoxyHandler::new(
        Arc::clone(&shared_config),
        rate_limiter,
        Arc::clone(&credit_manager),
    );

    // Spawn config reload watcher (if enabled)
    if config.reload_interval_secs > 0 {
        info!(
            target: "proxy",
            interval_secs = config.reload_interval_secs,
            "Config hot reload enabled"
        );
        roxy::config::reload::spawn_config_watcher(
            args.config_path.clone(),
            shared_config,
            credit_manager,
            config.reload_interval_secs,
            Arc::clone(&shutdown),
        )
        .await;
    } else {
        info!(target: "proxy", "Config hot reload disabled (reload_interval_secs = 0)");
    }

    // Create Certificate Authority for MITM
    let ca = create_ca(&config);

    // Parse listen address
    let addr: SocketAddr = config.listen.parse().unwrap_or_else(|e| {
        error!(target: "proxy", listen = %config.listen, error = %e, "Invalid listen address");
        std::process::exit(1);
    });

    // ---------------------------------------------------------
    // Inbound TCP Keepalive via socket2 - prevents zombie connections when clients disappear without proper TCP teardown (e.g. mobile clients, bad network, OOM kills inside containers...)
    // ---------------------------------------------------------
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .expect("Failed to create listening socket");

    // Tokio requires non-blocking sockets, and we want to reuse the address
    socket
        .set_reuse_address(true)
        .expect("Failed to set reuse_address");
    socket
        .set_nonblocking(true)
        .expect("Failed to set nonblocking");

    // Inject 15s TCP Keepalive into the Listener.
    // Linux inherits this to all incoming client connections!
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(15));
    socket
        .set_tcp_keepalive(&keepalive)
        .expect("Failed to set TCP keepalive");

    socket.bind(&addr.into()).expect("Failed to bind socket");
    socket.listen(1024).expect("Failed to listen on socket");

    // Convert raw socket into a Tokio TcpListener
    let std_listener: std::net::TcpListener = socket.into();
    let tokio_listener = tokio::net::TcpListener::from_std(std_listener)
        .expect("Failed to convert to Tokio TcpListener");

    info!(
        target: "proxy",
        listen = %addr,
        "Starting MITM proxy (Inbound Keepalive Enabled)"
    );

    // Configure connection pool limits to prevent unbounded memory growth.
    // This mitigates DoS attacks where an attacker forces connections to many unique hosts.
    let pool_config = config.pool.clone().unwrap_or_default();
    let mut client_builder = ClientBuilder::new(TokioExecutor::new());
    client_builder
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .pool_max_idle_per_host(pool_config.max_idle_per_host);

    info!(
        target: "proxy",
        pool_max_idle_per_host = pool_config.max_idle_per_host,
        pool_idle_timeout_secs = pool_config.idle_timeout_secs,
        "Connection pool configured"
    );

    // Build and start proxy
    let result = if config.unsafe_skip_verify {
        warn!(
            target: "proxy",
            "Upstream TLS verification DISABLED — self-signed and invalid certificates will be accepted"
        );

        let provider = Arc::new(aws_lc_rs::default_provider());
        let rustls_config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("Failed to configure TLS protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(roxy::proxy::NoVerifier::new(provider)))
            .with_no_client_auth();

        // Inject custom HTTP connector with 15s TCP Keepalive to kill zombie connections
        let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
        http_connector.set_keepalive(Some(Duration::from_secs(15)));
        http_connector.enforce_http(false);

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(rustls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        Proxy::builder()
            .with_listener(tokio_listener)
            .with_ca(ca)
            .with_http_connector(connector)
            .with_client(client_builder)
            .with_http_handler(handler)
            .with_graceful_shutdown(shutdown_signal(Arc::clone(&shutdown)))
            .build()
            .expect("Failed to create proxy")
            .start()
            .await
    } else {
        // Safe Mode: Inject custom HTTP connector with 15s TCP Keepalive
        let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector.set_keepalive(Some(Duration::from_secs(15)));

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        Proxy::builder()
            .with_listener(tokio_listener)
            .with_ca(ca)
            .with_http_connector(connector)
            .with_client(client_builder)
            .with_http_handler(handler)
            .with_graceful_shutdown(shutdown_signal(Arc::clone(&shutdown)))
            .build()
            .expect("Failed to create proxy")
            .start()
            .await
    };

    if let Err(e) = result {
        error!(target: "proxy", error = %e, "Proxy error");
        std::process::exit(1);
    }
}
