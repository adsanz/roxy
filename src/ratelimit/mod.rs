//! Rate limiting module for Roxy proxy.
//!
//! Provides in-memory sliding window rate limiting with DashMap storage.

mod limiter;

pub use limiter::*;
