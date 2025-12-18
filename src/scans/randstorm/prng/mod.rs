pub mod bitcoinjs_v013;
/// PRNG implementations for various browser engines
///
/// This module reconstructs the Pseudo-Random Number Generators (PRNGs) used by
/// different browser JavaScript engines from 2011-2015. These PRNGs had insufficient
/// entropy, making wallet private keys predictable.
pub mod chrome_v8;

pub use bitcoinjs_v013::{Arc4, BitcoinJsV013Prng, WeakMathRandom};
pub use chrome_v8::ChromeV8Prng;

/// Browser version range
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVersion {
    pub name: String,
    pub version_min: u32,
    pub version_max: u32,
}

impl BrowserVersion {
    pub fn new(name: &str, range: std::ops::RangeInclusive<u32>) -> Self {
        Self {
            name: name.to_string(),
            version_min: *range.start(),
            version_max: *range.end(),
        }
    }
}

/// Components used to seed the PRNG
#[derive(Debug, Clone)]
pub struct SeedComponents {
    pub timestamp_ms: u64,
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub language: String,
    pub platform: String,
}

/// PRNG internal state
#[derive(Debug, Clone)]
pub struct PrngState {
    pub s1: u32,
    pub s2: u32,
}

/// Trait for browser PRNG implementations
pub trait PrngEngine {
    /// Generate initial PRNG state from seed components
    fn generate_state(&self, seed: &SeedComponents) -> PrngState;

    /// Generate random bytes from PRNG state
    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8>;

    /// Return applicable browser versions for this PRNG
    fn applicable_to(&self) -> &[BrowserVersion];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_version() {
        let version = BrowserVersion::new("Chrome", 20..=45);
        assert_eq!(version.name, "Chrome");
        assert_eq!(version.version_min, 20);
        assert_eq!(version.version_max, 45);
    }
}
