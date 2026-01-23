//! Roxy - High-performance forward HTTP/S proxy with MITM support
//!
//! Built on Hudsucker with a custom rule DSL.

use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
    Proxy,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use roxy::config::ProxyConfig;
use roxy::proxy::RoxyHandler;
use roxy::ratelimit::RateLimiter;
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

        let config_path = if let Some(pos) = args.iter().position(|a| a == "--config" || a == "-c") {
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
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();
}

/// Create a Certificate Authority for MITM.
/// Uses config if provided, otherwise generates an ephemeral CA.
fn create_ca(config: &ProxyConfig) -> RcgenAuthority {
    if let Some(tls_config) = &config.tls {
        // Load CA from files
        let key_pem = std::fs::read_to_string(&tls_config.ca_key)
            .unwrap_or_else(|e| {
                error!(target: "proxy", path = %tls_config.ca_key.display(), error = %e, "Failed to read CA key");
                std::process::exit(1);
            });
        
        let cert_pem = std::fs::read_to_string(&tls_config.ca_cert)
            .unwrap_or_else(|e| {
                error!(target: "proxy", path = %tls_config.ca_cert.display(), error = %e, "Failed to read CA cert");
                std::process::exit(1);
            });

        let key_pair = KeyPair::from_pem(&key_pem)
            .unwrap_or_else(|e| {
                error!(target: "proxy", error = %e, "Failed to parse CA key");
                std::process::exit(1);
            });

        let issuer = hudsucker::rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .unwrap_or_else(|e| {
                error!(target: "proxy", error = %e, "Failed to parse CA certificate");
                std::process::exit(1);
            });

        info!(target: "proxy", "Loaded CA from config");
        RcgenAuthority::new(issuer, tls_config.cert_cache_size as u64, aws_lc_rs::default_provider())
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
        let cert = params.self_signed(&key_pair).expect("Failed to generate CA cert");
        
        let issuer = hudsucker::rcgen::Issuer::from_ca_cert_pem(&cert.pem(), key_pair)
            .expect("Failed to create issuer from generated CA");

        RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider())
    }
}

/// Graceful shutdown signal handler.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
    info!(target: "proxy", "Shutdown signal received");
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
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!(target: "proxy", error = %e, "Failed to parse rules");
            std::process::exit(1);
        }
    };

    info!(
        target: "proxy",
        rule_count = rules.rule_count(),
        "Loaded rules"
    );

    // Create rate limiter
    let cleanup_interval = config
        .rate_limit
        .as_ref()
        .map(|rl| std::time::Duration::from_secs(rl.cleanup_interval_secs))
        .unwrap_or(std::time::Duration::from_secs(60));

    let rate_limiter = Arc::new(RateLimiter::new(cleanup_interval));

    // Create handler
    let handler = RoxyHandler::new(rules, rate_limiter, config.headers.clone());

    // Create Certificate Authority for MITM
    let ca = create_ca(&config);

    // Parse listen address
    let addr: SocketAddr = config.listen.parse().unwrap_or_else(|e| {
        error!(target: "proxy", listen = %config.listen, error = %e, "Invalid listen address");
        std::process::exit(1);
    });

    info!(
        target: "proxy",
        listen = %addr,
        "Starting MITM proxy"
    );

    // Build and start proxy
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .expect("Failed to create proxy");

    if let Err(e) = proxy.start().await {
        error!(target: "proxy", error = %e, "Proxy error");
        std::process::exit(1);
    }
}
