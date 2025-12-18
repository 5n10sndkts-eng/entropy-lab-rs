/// Browser fingerprint database
///
/// Curated database of browser configurations from 2011-2015 ranked by
/// estimated market share. Used to prioritize scanning of most common
/// wallet generation scenarios.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    pub priority: u32,
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub language: String,
    pub platform: String,
    pub market_share_estimate: f64,
    pub year_min: u16,
    pub year_max: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    One,   // Top 100 configs
    Two,   // Top 500 configs
    Three, // All configs + probabilistic
}

pub struct FingerprintDatabase {
    configs: Vec<BrowserConfig>,
}

impl FingerprintDatabase {
    /// Load fingerprint database from embedded data
    pub fn load() -> Result<Self> {
        const EMBEDDED_CSV: &str = include_str!("data/phase1_top100.csv");

        let mut reader = csv::Reader::from_reader(EMBEDDED_CSV.as_bytes());
        let mut configs = Vec::new();

        for result in reader.deserialize() {
            let config: BrowserConfig =
                result.context("Failed to parse embedded browser config")?;
            configs.push(config);
        }

        // Already sorted by priority in the CSV
        Ok(Self { configs })
    }

    /// Load from custom CSV file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut reader =
            csv::Reader::from_path(path).context("Failed to open fingerprint database CSV")?;

        let mut configs = Vec::new();
        for result in reader.deserialize() {
            let config: BrowserConfig =
                result.context("Failed to parse browser config from CSV")?;
            configs.push(config);
        }

        // Sort by market share descending
        configs.sort_by(|a, b| {
            b.market_share_estimate
                .partial_cmp(&a.market_share_estimate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(Self { configs })
    }

    /// Get configurations for specified phase
    pub fn get_configs_for_phase(&self, phase: Phase) -> &[BrowserConfig] {
        match phase {
            Phase::One => &self.configs[0..self.configs.len().min(100)],
            Phase::Two => &self.configs[0..self.configs.len().min(500)],
            Phase::Three => &self.configs,
        }
    }

    /// Get total number of configurations
    pub fn len(&self) -> usize {
        self.configs.len()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Get fingerprints for specified phase (converts BrowserConfig to BrowserFingerprint)
    pub fn get_fingerprints_for_phase(
        &self,
        phase: Phase,
    ) -> Vec<super::fingerprint::BrowserFingerprint> {
        let configs = self.get_configs_for_phase(phase);
        configs
            .iter()
            .map(|config| {
                super::fingerprint::BrowserFingerprint {
                    timestamp_ms: 1420070400000, // Jan 1, 2015 - midpoint of vulnerable period
                    screen_width: config.screen_width,
                    screen_height: config.screen_height,
                    color_depth: config.color_depth,
                    timezone_offset: config.timezone_offset as i32,
                    language: config.language.clone(),
                    platform: config.platform.clone(),
                    user_agent: config.user_agent.clone(),
                }
            })
            .collect()
    }

    /// Get cumulative market share for top N configs
    pub fn cumulative_market_share(&self, n: usize) -> f64 {
        self.configs
            .iter()
            .take(n)
            .map(|c| c.market_share_estimate)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_loads() {
        let db = FingerprintDatabase::load();
        match &db {
            Ok(database) => {
                assert!(!database.is_empty());
                assert_eq!(database.len(), 100);
            }
            Err(e) => panic!("Database failed to load: {}", e),
        }
    }

    #[test]
    fn test_phase_limits() {
        let base = BrowserConfig {
            priority: 1,
            user_agent: "Test".to_string(),
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

        // Build a list of 150 configs to exercise the slicing logic
        let configs = vec![base; 150];

        let db = FingerprintDatabase { configs };

        assert_eq!(db.get_configs_for_phase(Phase::One).len(), 100);
        assert_eq!(db.get_configs_for_phase(Phase::Two).len(), 150);
        assert_eq!(db.get_configs_for_phase(Phase::Three).len(), 150);
    }
}
