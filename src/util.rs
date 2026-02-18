//! Shared utilities for zero-allocation hot-path operations.

use std::fmt::{self, Write};

/// A fixed-capacity string buffer allocated entirely on the stack.
///
/// Used for formatting DashMap lookup keys (ip-baseline, credit bucket)
/// without heap allocation on the fast path. Falls back to [`String`]
/// via [`StackString::to_cow`] only if the formatted key exceeds `N` bytes.
///
/// `N` should be chosen to cover the common case. For rate-limit keys
/// like `__ip_baseline__:rule-name:255.255.255.255`, 128 bytes is generous.
pub(crate) struct StackString<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackString<N> {
    /// Create a new empty `StackString`.
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// View the contents as a `&str`.
    ///
    /// All writes go through `fmt::Write` which only accepts valid UTF-8,
    /// so this conversion cannot fail in practice.
    #[inline]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len])
            .expect("BUG: StackString contains invalid UTF-8")
    }

    /// Push a `&str` directly (faster than going through `fmt::Write`
    /// when no formatting is needed).
    #[inline]
    pub fn push_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        let remaining = N - self.len;
        if s.len() > remaining {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
        self.len += s.len();
        Ok(())
    }

    /// Push a single ASCII byte.
    #[inline]
    pub fn push(&mut self, c: char) -> Result<(), fmt::Error> {
        if self.len >= N {
            return Err(fmt::Error);
        }
        // Only safe for single-byte chars; callers use ':' exclusively.
        debug_assert!(c.is_ascii());
        self.buf[self.len] = c as u8;
        self.len += 1;
        Ok(())
    }

}

impl<const N: usize> Write for StackString<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn test_stack_string_basic() {
        let mut s = StackString::<64>::new();
        s.push_str("hello").unwrap();
        s.push(':').unwrap();
        s.push_str("world").unwrap();
        assert_eq!(s.as_str(), "hello:world");
    }

    #[test]
    fn test_stack_string_write_fmt() {
        let mut s = StackString::<64>::new();
        write!(s, "__ip__:{}:{}", "rule", "10.0.0.1").unwrap();
        assert_eq!(s.as_str(), "__ip__:rule:10.0.0.1");
    }

    #[test]
    fn test_stack_string_overflow() {
        let mut s = StackString::<5>::new();
        assert!(s.push_str("hello").is_ok());
        assert!(s.push_str("!").is_err()); // overflow
        assert_eq!(s.as_str(), "hello"); // partial content preserved
    }

    #[test]
    fn test_stack_string_exact_fit() {
        let mut s = StackString::<11>::new();
        s.push_str("hello").unwrap();
        s.push(':').unwrap();
        s.push_str("world").unwrap();
        assert_eq!(s.as_str(), "hello:world");
        assert_eq!(s.as_str().len(), 11);
    }
}
