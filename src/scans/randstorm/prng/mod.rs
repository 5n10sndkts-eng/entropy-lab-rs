pub mod bitcoinjs_v013;
/// PRNG implementations for various browser engines
///
/// This module reconstructs the Pseudo-Random Number Generators (PRNGs) used by
/// different browser JavaScript engines from 2011-2015. These PRNGs had insufficient
/// entropy, making wallet private keys predictable.
pub mod chrome_v8;

pub use bitcoinjs_v013::{Arc4, BitcoinJsV013Prng, WeakMathRandom};
pub use chrome_v8::ChromeV8Prng;

/// Math.random() engine variants for historical browsers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MathRandomEngine {
    /// Chrome/V8-era MWC1616
    V8Mwc1616,
    /// 48-bit LCG (drand48-style)
    Drand48,
    /// Java.util.Random-style 48-bit LCG with double output
    JavaUtil,
    /// XorShift128+ (used by some browser engines, e.g., later SpiderMonkey/JSC)
    XorShift128Plus,
    /// SpiderMonkey-era Math.random (modeled as xorshift128+)
    SpiderMonkey,
    /// WebKit JSC-era Math.random (LCG-based)
    Jsc,
}

impl MathRandomEngine {
    pub fn from_str(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "v8" | "v8_mwc1616" | "chrome" => Some(Self::V8Mwc1616),
            "drand48" | "lcg48" | "srand48" => Some(Self::Drand48),
            "java" | "java_util" | "javautil" => Some(Self::JavaUtil),
            "xorshift" | "xorshift128" | "xorshift128plus" | "spidermonkey" | "jsc" | "safari" => {
                Some(Self::XorShift128Plus)
            }
            "spidermonkey_exact" | "sm" => Some(Self::SpiderMonkey),
            "jsc_exact" | "webkit" => Some(Self::Jsc),
            _ => None,
        }
    }
}

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
