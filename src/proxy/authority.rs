//! Custom Certificate Authority that includes the CA cert in the chain.
//!
//! This is a modified version of Hudsucker's RcgenAuthority that sends
//! the full certificate chain (leaf + CA) to clients. This is required
//! for strict TLS clients like Node.js that need to verify the full chain.
//!
//! Based on: https://docs.rs/hudsucker/latest/src/hudsucker/certificate_authority/rcgen_authority.rs.html

use http::uri::Authority;
use hudsucker::certificate_authority::CertificateAuthority;
use hudsucker::rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType, string::Ia5String,
};
use hudsucker::rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::NoServerSessionStorage,
};
use moka::future::Cache;
use rand::{Rng, rng};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tracing::{debug, warn};

/// Certificate validity period in seconds (1 year)
const TTL_SECS: i64 = 365 * 24 * 60 * 60;

/// Cache TTL - 24 hours.
/// Certificates are cheap to regenerate; keeping them for the full validity
/// period (182 days) causes unbounded memory growth from accumulated
/// TLS session caches inside each ServerConfig.
const CACHE_TTL: u64 = 24 * 60 * 60;

/// Offset for not_before to handle clock skew (60 seconds)
const NOT_BEFORE_OFFSET: i64 = 60;

/// Certificate Authority that includes the CA certificate in the chain.
///
/// Unlike Hudsucker's RcgenAuthority which only sends the leaf certificate,
/// this implementation sends both the leaf and CA certificates. This is
/// required for clients that need to verify the full certificate chain
/// (e.g., Node.js, n8n, strict TLS clients).
///
/// # Certificate Chain
///
/// When a client connects, it receives:
/// 1. Leaf certificate (dynamically generated for the target host)
/// 2. CA certificate (the issuing authority)
///
/// This allows clients to verify: leaf → CA → (trusted root)
pub struct RoxyAuthority {
    /// The certificate issuer (CA)
    issuer: Issuer<'static, KeyPair>,

    /// CA certificate in DER format (included in chain)
    ca_cert_der: CertificateDer<'static>,

    /// Private key for signing
    private_key: PrivateKeyDer<'static>,

    /// Cache for generated server configs
    cache: Cache<Authority, Arc<ServerConfig>>,

    /// Crypto provider for TLS
    provider: Arc<CryptoProvider>,
}

impl RoxyAuthority {
    /// Creates a new RoxyAuthority with the given CA certificate and key.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The certificate issuer created from CA cert and key
    /// * `ca_cert_pem` - The CA certificate in PEM format (will be included in chain)
    /// * `cache_size` - Maximum number of server configs to cache
    /// * `provider` - The cryptographic provider to use
    pub fn new(
        issuer: Issuer<'static, KeyPair>,
        ca_cert_pem: &str,
        cache_size: u64,
        provider: CryptoProvider,
    ) -> Self {
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(issuer.key().serialize_der()));

        // Parse CA certificate from PEM to DER
        let ca_cert_der = pem_to_der(ca_cert_pem);

        debug!(
            target: "proxy",
            ca_cert_der_len = ca_cert_der.len(),
            "Loaded CA certificate for chain"
        );

        Self {
            issuer,
            ca_cert_der,
            private_key,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(std::time::Duration::from_secs(CACHE_TTL))
                .build(),
            provider: Arc::new(provider),
        }
    }

    /// Generate a certificate for the given authority (host).
    ///
    /// Returns `Err` if the hostname contains non-ASCII characters that
    /// cannot be encoded as an IA5String, or if certificate signing fails.
    /// Callers must handle the error to avoid crashing on malformed network input.
    fn gen_cert(&self, authority: &Authority) -> Result<CertificateDer<'static>, String> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(rng().random::<u64>().into());

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, authority.host());
        params.distinguished_name = distinguished_name;

        let san = Ia5String::try_from(authority.host())
            .map_err(|e| format!("invalid hostname for SAN: {e}"))?;
        params.subject_alt_names.push(SanType::DnsName(san));

        let cert = params
            .signed_by(self.issuer.key(), &self.issuer)
            .map_err(|e| format!("certificate signing failed: {e}"))?;
        Ok(cert.into())
    }

    /// Build a fallback ServerConfig used when certificate generation fails
    /// (e.g., malformed hostname). This presents a self-signed cert for
    /// "invalid.proxy.internal" so the TLS handshake completes with an
    /// obvious error rather than crashing the process.
    fn fallback_server_config(&self) -> Arc<ServerConfig> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "invalid.proxy.internal");
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(
            Ia5String::try_from("invalid.proxy.internal").unwrap(),
        ));
        let fallback_cert = params
            .signed_by(self.issuer.key(), &self.issuer)
            .expect("BUG: failed to sign fallback cert with known-good CA");
        let certs = vec![
            CertificateDer::from(fallback_cert),
            self.ca_cert_der.clone(),
        ];

        let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("BUG: protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone_key())
            .expect("BUG: fallback ServerConfig");
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        Arc::new(cfg)
    }
}

impl CertificateAuthority for RoxyAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            debug!("Using cached server config");
            return server_cfg;
        }
        debug!("Generating server config");

        // Generate leaf certificate for the target host.
        // If the hostname is malformed (e.g., non-ASCII from a crafted CONNECT),
        // return a fallback config instead of crashing the process.
        let leaf_cert = match self.gen_cert(authority) {
            Ok(cert) => cert,
            Err(e) => {
                warn!(
                    target: "proxy",
                    authority = %authority,
                    error = %e,
                    "Failed to generate certificate for host — returning fallback"
                );
                let fallback = self.fallback_server_config();
                // Do NOT cache the fallback — retry on next request in case
                // the same authority arrives with a valid representation later.
                return fallback;
            }
        };

        // Include both leaf and CA certificates in the chain
        // Order: leaf certificate first, then CA certificate
        let certs = vec![leaf_cert, self.ca_cert_der.clone()];

        debug!(
            target: "proxy",
            authority = %authority,
            cert_chain_length = certs.len(),
            leaf_cert_len = certs[0].len(),
            ca_cert_len = certs[1].len(),
            "Building TLS config with certificate chain"
        );

        // Build ServerConfig — fall back on any error instead of panicking
        let builder = match ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "proxy", error = %e,
                      "Protocol version error — returning fallback");
                return self.fallback_server_config();
            }
        };

        let mut server_cfg = match builder
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone_key())
        {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!(target: "proxy", authority = %authority, error = %e,
                      "Failed to build ServerConfig — returning fallback");
                return self.fallback_server_config();
            }
        };

        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        // Disable TLS session resumption cache. Each ServerSessionMemoryCache
        // pre-allocates ~25KB of hash table. With hundreds of cached hosts,
        // this causes significant memory growth. Session resumption between
        // client and MITM proxy has no value since certs are generated on the fly.
        server_cfg.session_storage = Arc::new(NoServerSessionStorage {});

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        server_cfg
    }
}

/// Parse a PEM-encoded certificate to DER format.
fn pem_to_der(pem_str: &str) -> CertificateDer<'static> {
    let parsed = pem::parse(pem_str).expect("Failed to parse PEM certificate");
    CertificateDer::from(parsed.into_contents())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};
    use hudsucker::rustls::crypto::aws_lc_rs;

    fn generate_test_ca() -> (Issuer<'static, KeyPair>, String) {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key_pair = KeyPair::generate().expect("Failed to generate key");
        let cert = params.self_signed(&key_pair).expect("Failed to self-sign");
        let cert_pem = cert.pem();

        let issuer =
            Issuer::from_ca_cert_pem(&cert_pem, key_pair).expect("Failed to create issuer");

        (issuer, cert_pem)
    }

    #[test]
    fn test_pem_to_der() {
        let (_, cert_pem) = generate_test_ca();
        let der = pem_to_der(&cert_pem);
        assert!(!der.is_empty());
    }

    #[test]
    fn test_authority_creation() {
        let (issuer, cert_pem) = generate_test_ca();
        let _authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());
    }

    #[tokio::test]
    async fn test_gen_server_config() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        let host = Authority::from_static("example.com");
        let config = authority.gen_server_config(&host).await;

        // Verify config was created
        assert!(!config.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn test_config_caching() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        let host = Authority::from_static("example.com");

        // First call generates
        let config1 = authority.gen_server_config(&host).await;

        // Second call should return cached
        let config2 = authority.gen_server_config(&host).await;

        // Both should point to the same Arc
        assert!(Arc::ptr_eq(&config1, &config2));
    }

    #[test]
    fn test_gen_cert_succeeds_for_valid_host() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        // Valid ASCII hostnames must produce a certificate.
        let host = Authority::from_static("example.com");
        assert!(authority.gen_cert(&host).is_ok());
    }

    #[test]
    fn test_gen_cert_succeeds_for_wildcard_subdomain() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        let host = Authority::from_static("sub.deep.example.com");
        assert!(authority.gen_cert(&host).is_ok());
    }

    #[test]
    fn test_gen_cert_succeeds_for_host_with_port() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        // Authority::host() strips the port, so this exercises that path
        let host = Authority::from_static("example.com:8443");
        assert!(authority.gen_cert(&host).is_ok());
    }

    #[test]
    fn test_fallback_server_config_is_valid() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        // The fallback must always succeed — it's the last resort when
        // gen_cert fails on a malformed hostname.
        let fallback = authority.fallback_server_config();
        assert!(!fallback.alpn_protocols.is_empty());
        assert_eq!(fallback.alpn_protocols.len(), 2);
    }

    #[tokio::test]
    async fn test_malformed_host_returns_fallback_without_crash() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        // A valid ASCII host should work and be cached
        let good_host = Authority::from_static("example.com");
        let config = authority.gen_server_config(&good_host).await;
        assert!(!config.alpn_protocols.is_empty());

        // Fallback must also be constructable independently
        let fallback = authority.fallback_server_config();
        assert!(!fallback.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn test_fallback_is_not_cached() {
        let (issuer, cert_pem) = generate_test_ca();
        let authority = RoxyAuthority::new(issuer, &cert_pem, 100, aws_lc_rs::default_provider());

        // Generate config for a valid host — should be cached
        let host = Authority::from_static("cached.example.com");
        let config1 = authority.gen_server_config(&host).await;
        let config2 = authority.gen_server_config(&host).await;
        assert!(
            Arc::ptr_eq(&config1, &config2),
            "valid host configs must be cached"
        );

        // Fallback configs are NOT cached (each call returns a new Arc)
        let fb1 = authority.fallback_server_config();
        let fb2 = authority.fallback_server_config();
        assert!(
            !Arc::ptr_eq(&fb1, &fb2),
            "fallback configs must not be reused"
        );
    }
}
