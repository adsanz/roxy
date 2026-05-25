//! Proxy module for Roxy.
//!
//! Implements Hudsucker's HttpHandler trait for request handling.

mod authority;
mod bounded;
mod handler;
mod tls;

pub use authority::RoxyAuthority;
pub use bounded::ConnectionLifecycle;
pub use bounded::RoxyProxy;
pub use handler::RoxyHandler;
pub use handler::SharedConfig;
pub use tls::NoVerifier;
