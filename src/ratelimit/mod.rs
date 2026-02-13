//! Rate limiting module for Roxy proxy.
//!
//! Provides in-memory sliding window rate limiting with DashMap storage,
//! and credit-based rate limiting with scheduled resets.

mod credit;
mod limiter;

pub use credit::*;
pub use limiter::*;
