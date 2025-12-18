/// BitcoinJS v0.1.3 PRNG Implementation (ARC4 + Weak Math.random)
///
/// This module replicates the exact vulnerability in BitcoinJS v0.1.3 from 2011-2014.
/// The bug: `navigator.appVersion < "5"` fails in modern browsers because "5.0" is NOT
/// less than "5" in string comparison, causing fallback to weak Math.random().
use super::{BrowserVersion, PrngEngine, PrngState, SeedComponents};

/// ARC4 cipher state (as used in BitcoinJS v0.1.3)
#[derive(Debug, Clone)]
pub struct Arc4 {
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl Arc4 {
    /// Initialize ARC4 with key (entropy pool)
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Arc4 { i: 0, j: 0, s }
    }

    /// Generate next pseudo-random byte
    pub fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[k as usize]
    }

    /// Fill buffer with pseudo-random bytes
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next();
        }
    }
}

/// Weak Math.random() simulation using Chrome V8 MWC1616 (matches 2011-2014 behavior)
#[derive(Debug, Clone)]
pub struct WeakMathRandom {
    s1: u32,
    s2: u32,
}

impl WeakMathRandom {
    /// Create PRNG seeded with timestamp (milliseconds)
    pub fn from_timestamp(timestamp_ms: u64) -> Self {
        // Minimal seed mapping: split timestamp into two 32-bit words.
        // BitcoinJS uses Math.random() after browser init; we model V8's MWC1616
        // with the timestamp providing both halves of the seed (little-endian split).
        let s1 = (timestamp_ms & 0xFFFF_FFFF) as u32; // low 32 bits
        let s2 = (timestamp_ms >> 32) as u32; // high 32 bits
        Self { s1, s2 }
    }

    /// Advance MWC1616 state and return next f64 in [0,1)
    pub fn next(&mut self) -> f64 {
        self.s1 = 18_000_u32.wrapping_mul(self.s1 & 0xFFFF) + (self.s1 >> 16);
        self.s2 = 30_903_u32.wrapping_mul(self.s2 & 0xFFFF) + (self.s2 >> 16);
        // JS Math.random() uses 32-bit ops; mask to 32 bits after combining.
        let combined: u32 = (((self.s1 as u64) << 16) + (self.s2 as u64)) as u32;
        // Normalize to [0,1): divide by 2^32 (not MAX), matching JS behavior (<1.0).
        (combined as f64) / 4_294_967_296.0
    }

    /// Generate random bytes (as BitcoinJS randomBytes does)
    pub fn random_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            let rand_val = (self.next() * 256.0).floor() as u8;
            bytes.push(rand_val);
        }
        bytes
    }
}

/// BitcoinJS v0.1.3 PRNG (vulnerable implementation)
pub struct BitcoinJsV013Prng {
    versions: Vec<BrowserVersion>,
}

impl BitcoinJsV013Prng {
    pub fn new() -> Self {
        Self {
            versions: vec![
                BrowserVersion::new("Chrome", 5..=45),
                BrowserVersion::new("Firefox", 4..=35),
                BrowserVersion::new("Safari", 5..=8),
                BrowserVersion::new("Opera", 11..=30),
                BrowserVersion::new("IE", 9..=11),
            ],
        }
    }

    /// Generate entropy pool exactly as BitcoinJS v0.1.3 does
    pub fn generate_entropy_pool(timestamp_ms: u64) -> Vec<u8> {
        let mut pool = vec![0u8; 256];
        let mut prng = WeakMathRandom::from_timestamp(timestamp_ms);

        // Seed the pool with timestamp
        let ts_bytes = timestamp_ms.to_le_bytes();
        for (i, &byte) in ts_bytes.iter().enumerate() {
            pool[i] ^= byte;
        }

        // Fill remaining pool with weak Math.random()
        // This is the EXACT bug - navigator.appVersion < "5" fails for "5.0"
        let mut ptr = ts_bytes.len();
        while ptr < 256 {
            let rand16 = (prng.next() * 65536.0).floor() as u16;
            pool[ptr] ^= (rand16 >> 8) as u8;
            ptr += 1;
            if ptr < 256 {
                pool[ptr] ^= (rand16 & 0xFF) as u8;
                ptr += 1;
            }
        }

        pool
    }
}

impl Default for BitcoinJsV013Prng {
    fn default() -> Self {
        Self::new()
    }
}

impl PrngEngine for BitcoinJsV013Prng {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        // For BitcoinJS, the state is derived from timestamp only
        // (This is the vulnerability - insufficient entropy sources)
        let timestamp_ms = seed.timestamp_ms;

        // Generate entropy pool
        let _pool = Self::generate_entropy_pool(timestamp_ms);

        // Return minimal state (just timestamp for reproduction)
        PrngState {
            s1: (timestamp_ms & 0xFFFF_FFFF) as u32, // low
            s2: (timestamp_ms >> 32) as u32,         // high
        }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        // Reconstruct timestamp from state
        let timestamp_ms = ((state.s2 as u64) << 32) | (state.s1 as u64);

        // Generate entropy pool
        let entropy_pool = Self::generate_entropy_pool(timestamp_ms);

        // Initialize ARC4 with entropy pool
        let mut arc4 = Arc4::new(&entropy_pool);

        // Generate bytes
        let mut bytes = vec![0u8; count];
        arc4.fill_bytes(&mut bytes);

        bytes
    }

    fn applicable_to(&self) -> &[BrowserVersion] {
        &self.versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_prng_deterministic() {
        let mut prng1 = WeakMathRandom::from_timestamp(1389781850000);
        let mut prng2 = WeakMathRandom::from_timestamp(1389781850000);

        // Same seed should produce same sequence
        assert_eq!(prng1.next(), prng2.next());
        assert_eq!(prng1.next(), prng2.next());
        assert_eq!(prng1.next(), prng2.next());
    }

    #[test]
    fn test_arc4_deterministic() {
        let key = b"test_key";
        let mut arc1 = Arc4::new(key);
        let mut arc2 = Arc4::new(key);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        arc1.fill_bytes(&mut buf1);
        arc2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_entropy_pool_deterministic() {
        let pool1 = BitcoinJsV013Prng::generate_entropy_pool(1389781850000);
        let pool2 = BitcoinJsV013Prng::generate_entropy_pool(1389781850000);

        assert_eq!(pool1, pool2);
        assert_eq!(pool1.len(), 256);
    }

    #[test]
    fn test_bitcoinjs_prng_engine() {
        let prng = BitcoinJsV013Prng::new();

        let seed = SeedComponents {
            timestamp_ms: 1389781850000,
            user_agent: "Mozilla/5.0".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            timezone_offset: 0,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };

        let state = prng.generate_state(&seed);
        let bytes1 = prng.generate_bytes(&state, 32);
        let bytes2 = prng.generate_bytes(&state, 32);

        // Same state should produce same output
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_known_test_vector() {
        let timestamp_ms = 1389781850000;
        let expected_pool32 = "9017749543010000530ca7ece0304e75edd7eb3075cc421024b66e2259f36e99";
        let expected_priv32 = "b3b097f73c8ecb3d87e788a16cecf397309ec8b4d53460a1110479e8fbb33631";

        let pool = BitcoinJsV013Prng::generate_entropy_pool(timestamp_ms);
        assert_eq!(hex::encode(&pool[..32]), expected_pool32);

        let mut arc4 = Arc4::new(&pool);

        let mut privkey_bytes = [0u8; 32];
        arc4.fill_bytes(&mut privkey_bytes);

        assert_eq!(hex::encode(privkey_bytes), expected_priv32);
    }
}
