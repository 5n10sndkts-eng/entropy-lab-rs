use super::config::{ScanConfig, ScanMode};
/// Integration layer for Randstorm scanner
///
/// Orchestrates PRNG reconstruction, fingerprint database, GPU acceleration,
/// and wallet address derivation to detect vulnerable wallets.
use super::fingerprints::{BrowserConfig, FingerprintDatabase, Phase, TimestampGenerator};
use super::gpu_integration::{GpuScanner, MatchedKey};
use super::prng::{ChromeV8Prng, SeedComponents};
use super::progress::ProgressTracker;
use anyhow::{Context, Result};
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use secp256k1::Secp256k1;
use tracing::{info, warn};

/// Vulnerability finding result
#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    pub address: String,
    pub confidence: Confidence,
    pub browser_config: BrowserConfig,
    pub timestamp: u64,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Main Randstorm scanner
pub struct RandstormScanner {
    database: FingerprintDatabase,
    prng: ChromeV8Prng,
    secp: Secp256k1<secp256k1::All>,
    config: ScanConfig,
    gpu_scanner: Option<GpuScanner>,
}

impl RandstormScanner {
    /// Create new scanner instance
    pub fn new() -> Result<Self> {
        Self::with_config(ScanConfig::default())
    }

    /// Create scanner with custom configuration
    pub fn with_config(config: ScanConfig) -> Result<Self> {
        let database =
            FingerprintDatabase::load().context("Failed to load fingerprint database")?;

        // Initialize GPU scanner if enabled
        let gpu_scanner = if config.use_gpu {
            match GpuScanner::new(config.clone()) {
                Ok(scanner) => {
                    info!("✅ GPU acceleration enabled");
                    Some(scanner)
                }
                Err(e) => {
                    warn!("GPU initialization failed: {}", e);
                    warn!("Falling back to CPU-only mode");
                    None
                }
            }
        } else {
            info!("GPU acceleration disabled by config");
            None
        };

        Ok(Self {
            database,
            prng: ChromeV8Prng::new(),
            secp: Secp256k1::new(),
            config,
            gpu_scanner,
        })
    }

    /// Scan with GPU acceleration and progress tracking
    pub fn scan_with_progress(
        &mut self,
        target_addresses: &[String],
        phase: Phase,
    ) -> Result<Vec<VulnerabilityFinding>> {
        // Convert addresses to hash format for GPU
        let address_hashes = self.prepare_target_addresses(target_addresses)?;

        // Get fingerprints for the phase
        let fingerprints = self.database.get_fingerprints_for_phase(phase);
        let total = fingerprints.len() as u64;

        info!("🔍 Starting Randstorm scan");
        info!("   Phase: {:?}", phase);
        info!("   Targets: {}", target_addresses.len());
        info!("   Fingerprints: {}", total);

        let mut progress = ProgressTracker::new(total);
        let mut findings = Vec::new();

        #[cfg(feature = "gpu")]
        if let Some(ref mut gpu) = self.gpu_scanner {
            // GPU-accelerated scan
            let batch_size = gpu.calculate_batch_size()?;
            info!("   Batch size: {}", batch_size);

            let mut all_matches = Vec::new();
            let mut total_processed = 0u64;

            for chunk in fingerprints.chunks(batch_size) {
                let result =
                    gpu.process_batch(chunk, &address_hashes, target_addresses.len() as u32)?;

                total_processed += result.keys_processed;
                all_matches.extend(result.matches_found);

                if total_processed % (batch_size as u64 * 10) == 0 {
                    progress.update(total_processed, all_matches.len() as u64);
                    progress.print_update();
                }
            }

            // Convert all matches to findings after releasing the mutable borrow
            for matched in all_matches {
                findings.push(self.match_to_finding(matched, phase)?);
            }

            progress.update(total_processed, findings.len() as u64);
        }

        // CPU fallback when GPU unavailable or --cpu flag set
        if self.gpu_scanner.is_none() {
            warn!("Using CPU fallback (slower)");
            findings = self.cpu_scan(target_addresses, &fingerprints)?;
            progress.update(fingerprints.len() as u64, findings.len() as u64);
        }

        info!("\n✅ Scan complete!");
        info!("   Total processed: {}", progress.processed());
        info!("   Matches found: {}", findings.len());
        info!("   Time elapsed: {:?}", progress.elapsed());

        Ok(findings)
    }

    /// Prepare target addresses for GPU comparison
    fn prepare_target_addresses(&self, addresses: &[String]) -> Result<[Vec<u8>; 20]> {
        use bitcoin::Address;
        use std::str::FromStr;

        let mut result: [Vec<u8>; 20] = Default::default();

        for (i, addr_str) in addresses.iter().enumerate().take(20) {
            // Parse Bitcoin address and extract hash160
            let address_unchecked = Address::from_str(addr_str)
                .context(format!("Invalid Bitcoin address: {}", addr_str))?;

            // Assume mainnet for Randstorm scanning (most vulnerable wallets were mainnet)
            let address = address_unchecked.assume_checked();

            // Extract the payload (hash160) from the address
            let script_pubkey = address.script_pubkey();

            // For P2PKH addresses, extract the 20-byte hash
            if script_pubkey.is_p2pkh() {
                // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                let hash_bytes = &script_pubkey.as_bytes()[3..23]; // Skip 3-byte prefix, take 20 bytes
                result[i] = hash_bytes.to_vec();
            } else if script_pubkey.is_p2sh() {
                // P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
                let hash_bytes = &script_pubkey.as_bytes()[2..22]; // Skip 2-byte prefix, take 20 bytes
                result[i] = hash_bytes.to_vec();
            } else {
                // For other address types (P2WPKH, P2WSH), this is a placeholder
                // Randstorm primarily affects P2PKH addresses from browser wallets
                anyhow::bail!(
                    "Address type not supported for Randstorm scanning: {}",
                    addr_str
                );
            }
        }

        Ok(result)
    }

    /// Convert GPU match to vulnerability finding
    fn match_to_finding(&self, matched: MatchedKey, phase: Phase) -> Result<VulnerabilityFinding> {
        // Convert fingerprint to browser config
        let browser_config = BrowserConfig {
            priority: 1,
            user_agent: "Chrome".to_string(),
            screen_width: matched.fingerprint.screen_width,
            screen_height: matched.fingerprint.screen_height,
            color_depth: 24,
            timezone_offset: matched.fingerprint.timezone_offset as i16,
            language: matched.fingerprint.language.clone(),
            platform: matched.fingerprint.platform.clone(),
            market_share_estimate: 0.0,
            year_min: 2014,
            year_max: 2016,
        };

        Ok(VulnerabilityFinding {
            address: matched.address,
            confidence: match phase {
                Phase::One => Confidence::High,
                Phase::Two => Confidence::Medium,
                Phase::Three => Confidence::Low,
            },
            browser_config,
            timestamp: matched.fingerprint.timestamp_ms,
            derivation_path: "m/0".to_string(), // Pre-BIP32
        })
    }

    /// CPU fallback implementation
    fn cpu_scan(
        &self,
        target_addresses: &[String],
        fingerprints: &[super::fingerprint::BrowserFingerprint],
    ) -> Result<Vec<VulnerabilityFinding>> {
        use super::prng::{PrngEngine, SeedComponents};
        use bitcoin::Address;
        use rayon::prelude::*;
        use std::str::FromStr;

        // Parse and decode target addresses
        let target_hashes: Vec<Vec<u8>> = target_addresses
            .iter()
            .filter_map(|addr_str| {
                Address::from_str(addr_str)
                    .ok()
                    .and_then(|address_unchecked| {
                        let address = address_unchecked.assume_checked();
                        let script_pubkey = address.script_pubkey();

                        if script_pubkey.is_p2pkh() {
                            Some(script_pubkey.as_bytes()[3..23].to_vec())
                        } else if script_pubkey.is_p2sh() {
                            Some(script_pubkey.as_bytes()[2..22].to_vec())
                        } else {
                            None
                        }
                    })
            })
            .collect();

        // Parallel scan using Rayon
        let findings: Vec<VulnerabilityFinding> = fingerprints
            .par_iter()
            .filter_map(|fp| {
                // Create thread-local PRNG and secp context
                use super::prng::ChromeV8Prng;
                use bitcoin::secp256k1::Secp256k1;

                let prng = ChromeV8Prng::new();
                let secp = Secp256k1::new();

                // Create seed from fingerprint
                let seed = SeedComponents {
                    timestamp_ms: fp.timestamp_ms,
                    user_agent: fp.user_agent.clone(),
                    screen_width: fp.screen_width,
                    screen_height: fp.screen_height,
                    color_depth: fp.color_depth,
                    timezone_offset: fp.timezone_offset as i16,
                    language: fp.language.clone(),
                    platform: fp.platform.clone(),
                };

                // Generate PRNG state
                let state = prng.generate_state(&seed);

                // Generate key bytes
                let key_bytes = prng.generate_bytes(&state, 32);
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key_bytes[..32]);

                // Create secret key
                if let Ok(secret_key) = bitcoin::secp256k1::SecretKey::from_slice(&key_array) {
                    let public_key =
                        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                    let address_hash = super::derivation::derive_address_hash(&public_key);

                    // Check against target hashes
                    for (idx, target_hash) in target_hashes.iter().enumerate() {
                        if address_hash.as_slice() == target_hash.as_slice() {
                            // Found a match!
                            let browser_config = BrowserConfig {
                                priority: 1,
                                user_agent: fp.user_agent.clone(),
                                screen_width: fp.screen_width,
                                screen_height: fp.screen_height,
                                color_depth: 24,
                                timezone_offset: fp.timezone_offset as i16,
                                language: fp.language.clone(),
                                platform: fp.platform.clone(),
                                market_share_estimate: 0.0,
                                year_min: 2014,
                                year_max: 2016,
                            };

                            return Some(VulnerabilityFinding {
                                address: target_addresses[idx].clone(),
                                confidence: Confidence::High,
                                browser_config,
                                timestamp: fp.timestamp_ms,
                                derivation_path: "direct".to_string(),
                            });
                        }
                    }
                }

                None
            })
            .collect();

        Ok(findings)
    }

    /// Scan an address for Randstorm vulnerability
    pub fn scan(&self, _address: &str, _phase: Phase) -> Result<Option<VulnerabilityFinding>> {
        // TODO Phase 1: Implement full scanning logic
        // This is a placeholder for Story 1.6-1.8
        Ok(None)
    }

    /// Derive Bitcoin address from PRNG output (pre-BIP32)
    fn derive_direct_key(&self, prng_bytes: &[u8; 32]) -> Result<Address> {
        let privkey = PrivateKey::from_slice(prng_bytes, Network::Bitcoin)
            .context("Invalid private key from PRNG")?;

        let pubkey = PublicKey::from_private_key(&self.secp, &privkey);

        let address = Address::p2pkh(&pubkey, Network::Bitcoin);

        Ok(address)
    }

    /// Convert browser config to seed components
    fn config_to_seed(&self, config: &BrowserConfig, timestamp: u64) -> SeedComponents {
        SeedComponents {
            timestamp_ms: timestamp,
            user_agent: config.user_agent.clone(),
            screen_width: config.screen_width,
            screen_height: config.screen_height,
            color_depth: config.color_depth,
            timezone_offset: config.timezone_offset,
            language: config.language.clone(),
            platform: config.platform.clone(),
        }
    }
}

impl Default for RandstormScanner {
    fn default() -> Self {
        Self::new().expect("Failed to initialize scanner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = RandstormScanner::new();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_direct_key_derivation() {
        let scanner = RandstormScanner::new().unwrap();

        // Test with known private key bytes (all zeros - invalid but for test)
        let mut prng_bytes = [0u8; 32];
        prng_bytes[31] = 1; // Make it valid (non-zero)

        let result = scanner.derive_direct_key(&prng_bytes);
        assert!(result.is_ok());

        let address = result.unwrap();
        // Should be P2PKH address (starts with 1)
        assert!(address.to_string().starts_with('1'));
    }

    #[test]
    fn test_config_to_seed() {
        let scanner = RandstormScanner::new().unwrap();

        let config = BrowserConfig {
            priority: 1,
            user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            market_share_estimate: 0.1,
            year_min: 2011,
            year_max: 2015,
        };

        let seed = scanner.config_to_seed(&config, 1234567890000);

        assert_eq!(seed.timestamp_ms, 1234567890000);
        assert_eq!(seed.screen_width, 1366);
        assert_eq!(seed.screen_height, 768);
    }
}

/// Streaming scan infrastructure for massive-scale Randstorm scanning
pub struct StreamingScan {
    configs: Vec<BrowserConfig>,
    timestamp_gen: TimestampGenerator,
    current_config_idx: usize,
    scan_mode: ScanMode,
}

impl StreamingScan {
    /// Create new streaming scan
    pub fn new(configs: Vec<BrowserConfig>, scan_mode: ScanMode) -> Self {
        // Default to June 2011 - June 2015 vulnerable window
        let start_ms = 1306886400000; // June 1, 2011
        let end_ms = 1435708799000;   // June 30, 2015
        let interval_ms = scan_mode.interval_ms();
        
        Self {
            configs,
            timestamp_gen: TimestampGenerator::new(start_ms, end_ms, interval_ms),
            current_config_idx: 0,
            scan_mode,
        }
    }
    
    /// Create with custom time range
    pub fn with_time_range(
        configs: Vec<BrowserConfig>,
        scan_mode: ScanMode,
        start_ms: u64,
        end_ms: u64,
    ) -> Self {
        let interval_ms = scan_mode.interval_ms();
        
        Self {
            configs,
            timestamp_gen: TimestampGenerator::new(start_ms, end_ms, interval_ms),
            current_config_idx: 0,
            scan_mode,
        }
    }
    
    /// Get next fingerprint in stream (config × timestamp permutation)
    pub fn next_fingerprint(&mut self) -> Option<super::fingerprint::BrowserFingerprint> {
        use super::fingerprint::BrowserFingerprint;
        
        // Try next timestamp for current config
        if let Some(ts) = self.timestamp_gen.next() {
            let config = &self.configs[self.current_config_idx];
            return Some(BrowserFingerprint::from_config_and_timestamp(config, ts));
        }
        
        // Move to next config
        self.current_config_idx += 1;
        if self.current_config_idx >= self.configs.len() {
            return None; // Scan complete
        }
        
        // Reset timestamp generator for new config
        self.timestamp_gen.reset();
        self.next_fingerprint()
    }
    
    /// Get total fingerprint count for this scan
    pub fn total_fingerprints(&self) -> u64 {
        let timestamps_per_config = (self.timestamp_gen.end_ms - self.timestamp_gen.start_ms) 
            / self.timestamp_gen.interval_ms;
        timestamps_per_config * self.configs.len() as u64
    }
    
    /// Get current scan mode
    pub fn scan_mode(&self) -> ScanMode {
        self.scan_mode
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    // TEST-ID: 1.9-UNIT-009
    // AC: AC-5 (Streaming Scan)
    // PRIORITY: P0
    #[test]
    fn test_streaming_scan_iteration() {
        let configs = vec![
            BrowserConfig {
                priority: 1,
                user_agent: "Chrome/25".to_string(),
                screen_width: 1366,
                screen_height: 768,
                color_depth: 24,
                timezone_offset: -300,
                language: "en-US".to_string(),
                platform: "Win32".to_string(),
                market_share_estimate: 0.5,
                year_min: 2011,
                year_max: 2015,
            },
            BrowserConfig {
                priority: 2,
                user_agent: "Chrome/30".to_string(),
                screen_width: 1920,
                screen_height: 1080,
                color_depth: 24,
                timezone_offset: -300,
                language: "en-US".to_string(),
                platform: "Win32".to_string(),
                market_share_estimate: 0.3,
                year_min: 2012,
                year_max: 2015,
            },
        ];
        
        let start_ms = 1293840000000; // 2011-01-01
        let end_ms = 1293926400000;   // 2011-01-02
        
        let mut scan = StreamingScan::with_time_range(
            configs,
            ScanMode::Standard, // 1 hour intervals
            start_ms,
            end_ms,
        );
        
        // Should iterate through 24 timestamps × 2 configs = 48 fingerprints
        let mut count = 0;
        while scan.next_fingerprint().is_some() {
            count += 1;
        }
        
        assert_eq!(count, 48, "Expected 24 timestamps × 2 configs");
    }
}

