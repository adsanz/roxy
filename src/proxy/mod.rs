//! Proxy module for Roxy.
//!
//! Implements Hudsucker's HttpHandler trait for request handling.

mod authority;
mod handler;

pub use authority::RoxyAuthority;
pub use handler::RoxyHandler;
pub use handler::SharedConfig;
