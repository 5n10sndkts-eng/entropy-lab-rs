//! Configuration for Randstorm scanner

use serde::{Deserialize, Serialize};

/// Scan mode determining timestamp interval granularity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Quick scan: ~1000 timestamps per config (~100K total keys, ~1 hour)
    Quick,
    /// Standard scan: Hourly intervals (~35K timestamps per config, ~8.6M total keys, ~24 hours)
    Standard,
    /// Deep scan: Minutely intervals (~2.1M timestamps per config, ~517M total keys, ~1 week)
    Deep,
    /// Exhaustive scan: Per-second intervals (~126M timestamps per config, ~31B total keys, ~1 month)
    Exhaustive,
}

impl ScanMode {
    /// Get timestamp interval in milliseconds for this scan mode
    pub fn interval_ms(&self) -> u64 {
        match self {
            ScanMode::Quick => 126_000_000, // ~35 hour intervals (1000 timestamps total)
            ScanMode::Standard => 3_600_000, // 1 hour
            ScanMode::Deep => 60_000,       // 1 minute
            ScanMode::Exhaustive => 1_000,  // 1 second
        }
    }
}

impl Default for ScanMode {
    fn default() -> Self {
        ScanMode::Standard
    }
}

/// Configuration for Randstorm vulnerability scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scan mode controlling timestamp interval granularity
    #[serde(default)]
    pub scan_mode: ScanMode,

    /// Maximum batch size for GPU processing
    pub batch_size: Option<usize>,

    /// Enable GPU acceleration (default: true)
    pub use_gpu: bool,

    /// Number of CPU threads for fallback (default: num_cpus)
    pub cpu_threads: Option<usize>,

    /// Progress update interval in seconds (default: 5)
    pub progress_interval_secs: u64,

    /// Maximum number of fingerprints to scan (None = unlimited)
    pub max_fingerprints: Option<u64>,

    /// Start date for fingerprint generation (Unix timestamp ms)
    pub start_date_ms: Option<u64>,

    /// End date for fingerprint generation (Unix timestamp ms)
    pub end_date_ms: Option<u64>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_mode: ScanMode::Standard,
            batch_size: None, // Auto-detect from GPU
            use_gpu: true,
            cpu_threads: None, // Auto-detect
            progress_interval_secs: 5,
            max_fingerprints: None,
            start_date_ms: None,
            end_date_ms: None,
        }
    }
}

impl ScanConfig {
    /// Create config for Chrome V8 vulnerable period (2011-2015)
    pub fn chrome_v8_vulnerable_period() -> Self {
        Self {
            // 2011-01-01 to 2015-12-31
            start_date_ms: Some(1293840000000),
            end_date_ms: Some(1451520000000),
            ..Default::default()
        }
    }

    /// Create config for quick testing (small dataset)
    pub fn test_mode() -> Self {
        Self {
            max_fingerprints: Some(10_000),
            batch_size: Some(1_000),
            progress_interval_secs: 1,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert!(config.use_gpu);
        assert_eq!(config.progress_interval_secs, 5);
    }

    #[test]
    fn test_vulnerable_period_config() {
        let config = ScanConfig::chrome_v8_vulnerable_period();
        assert!(config.start_date_ms.is_some());
        assert!(config.end_date_ms.is_some());
    }

    // TEST-ID: 1.9-UNIT-003
    // AC: AC-4 (Granular Scan Phases)
    // PRIORITY: P0
    #[test]
    fn test_scan_mode_intervals() {
        assert_eq!(ScanMode::Quick.interval_ms(), 126_000_000);
        assert_eq!(ScanMode::Standard.interval_ms(), 3_600_000);
        assert_eq!(ScanMode::Deep.interval_ms(), 60_000);
        assert_eq!(ScanMode::Exhaustive.interval_ms(), 1_000);
    }
}
