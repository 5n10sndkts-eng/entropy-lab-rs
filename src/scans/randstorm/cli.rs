//! CLI Interface for Randstorm Scanner
//!
//! Provides the command-line interface with CSV input/output, progress reporting,
//! and comprehensive error handling.
//!
//! ## Test Strategy
//!
//! Tests are organized into three levels:
//!
//! ### Unit Tests (13 tests)
//! - CSV Input: 5 tests covering valid/invalid addresses, comments, whitespace
//! - CSV Output: 5 tests for header, single/multiple findings, empty results
//! - Timestamp Formatting: 3 tests for ISO 8601, epoch zero, invalid values
//!
//! ### Integration Tests (5 tests)
//! - CLI help text validation
//! - File not found error handling
//! - Invalid phase validation
//! - Output file creation
//! - End-to-end CPU scan
//!
//! ### Test Fixtures
//! - `tests/fixtures/addresses_p2pkh.csv` - Valid P2PKH addresses
//! - `tests/fixtures/addresses_mixed.csv` - Mixed valid/invalid
//! - `tests/fixtures/addresses_edge_cases.csv` - Whitespace, comments
//!
//! All tests include TEST-ID, AC reference, and PRIORITY markers for traceability.

use super::fingerprints::Phase;
use super::integration::RandstormScanner;
use super::prng::bitcoinjs_v013::BitcoinJsV013Prng;
use super::prng::PrngEngine;
use anyhow::{Context, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Address;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use tracing::{info, warn};

/// Run the Randstorm scanner with CLI arguments
pub fn run_scan(
    target_addresses_path: &Path,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    interval_ms: u64,
    phase: u8,
    mode: &str,
    force_gpu: bool,
    force_cpu: bool,
    output_path: Option<&Path>,
) -> Result<()> {
    // Parse scan mode
    let scan_mode = match mode.to_lowercase().as_str() {
        "quick" => super::config::ScanMode::Quick,
        "standard" => super::config::ScanMode::Standard,
        "deep" => super::config::ScanMode::Deep,
        "exhaustive" => super::config::ScanMode::Exhaustive,
        _ => anyhow::bail!("Invalid mode: {}. Must be quick, standard, deep, or exhaustive", mode),
    };

    info!("🔍 Scan mode: {:?}", scan_mode);
    
    // TODO: Use scan_mode with StreamingScan in future implementation
    // For now, mode is validated but StreamingScan integration pending

    // Parse phase
    let phase = match phase {
        1 => Phase::One,
        2 => Phase::Two,
        3 => Phase::Three,
        _ => anyhow::bail!("Invalid phase: {}. Must be 1, 2, or 3", phase),
    };

    info!("🔍 Randstorm Scanner Starting");
    info!("Phase: {:?}", phase);
    info!("Target addresses: {}", target_addresses_path.display());

    // Load target addresses from CSV
    let addresses = load_addresses_from_csv(target_addresses_path)
        .context("Failed to load target addresses")?;

    if addresses.is_empty() {
        anyhow::bail!(
            "No valid addresses found in {}",
            target_addresses_path.display()
        );
    }

    info!("Loaded {} target addresses", addresses.len());

    if force_gpu && force_cpu {
        anyhow::bail!("Cannot specify both --gpu and --cpu flags");
    }

    // Mode selection: direct sweep if timestamps provided, else phase-based scanner.
    if let (Some(start), Some(end)) = (start_ms, end_ms) {
        direct_sweep_scan(&addresses, start, end, interval_ms, output_path)?;
    } else {
        // Initialize scanner with GPU/CPU preference
        let mut config = super::config::ScanConfig::default();
        config.use_gpu = if force_cpu {
            false
        } else if force_gpu {
            true
        } else {
            true // default prefers GPU when available
        };

        let mut scanner = RandstormScanner::with_config(config)?;

        // Create progress bar
        let pb = ProgressBar::new(addresses.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} addresses ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Scan all addresses
        let results = scanner.scan_with_progress(&addresses, phase)?;

        pb.finish_with_message("Scan complete!");

        // Output results
        output_results(&results, output_path)?;

        info!(
            "✅ Scan complete. Found {} vulnerable addresses",
            results.len()
        );
    }

    Ok(())
}

/// Load Bitcoin addresses from CSV file
fn load_addresses_from_csv(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open CSV file: {}", path.display()))?;

    let reader = BufReader::new(file);
    let mut addresses = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context(format!("Failed to read line {}", line_num + 1))?;
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Simple validation: Bitcoin addresses start with 1, 3, or bc1
        if trimmed.starts_with('1') || trimmed.starts_with('3') || trimmed.starts_with("bc1") {
            addresses.push(trimmed.to_string());
        } else {
            warn!(
                "Line {}: Invalid Bitcoin address format: {}",
                line_num + 1,
                trimmed
            );
        }
    }

    Ok(addresses)
}

/// Core CSV output logic (testable)
fn output_results_to_writer<W: Write>(
    results: &[super::integration::VulnerabilityFinding],
    writer: &mut W,
) -> Result<()> {
    // Write CSV header
    writeln!(
        writer,
        "Address,Status,Confidence,BrowserConfig,Timestamp,DerivationPath"
    )?;

    // Write results
    for finding in results {
        let browser_config = format!(
            "{}/{}/{}x{}",
            finding.browser_config.user_agent,
            finding.browser_config.platform,
            finding.browser_config.screen_width,
            finding.browser_config.screen_height
        );

        let timestamp = format_timestamp(finding.timestamp);
        let confidence = format_confidence(&finding.confidence);

        writeln!(
            writer,
            "{},{},{},{},{},{}",
            finding.address,
            "VULNERABLE",
            confidence,
            browser_config,
            timestamp,
            finding.derivation_path
        )?;
    }

    writer.flush()?;
    Ok(())
}

/// Output scan results in CSV format
fn output_results(
    results: &[super::integration::VulnerabilityFinding],
    output_path: Option<&Path>,
) -> Result<()> {
    if let Some(path) = output_path {
        let mut file = File::create(path).context("Failed to create output file")?;
        output_results_to_writer(results, &mut file)
    } else {
        let mut stdout = std::io::stdout();
        output_results_to_writer(results, &mut stdout)
    }
}

/// Direct sweep mode: iterate timestamps and replicate BitcoinJS v0.1.3 RNG to find matches.
fn direct_sweep_scan(
    target_addresses: &[String],
    start_ms: u64,
    end_ms: u64,
    interval_ms: u64,
    output_path: Option<&Path>,
) -> Result<()> {
    if interval_ms == 0 {
        anyhow::bail!("interval_ms must be > 0");
    }
    if start_ms > end_ms {
        anyhow::bail!("start_ms must be <= end_ms");
    }
    info!("🧪 Direct sweep mode (BitcoinJS v0.1.3)");
    info!("   Start: {}", start_ms);
    info!("   End:   {}", end_ms);
    info!("   Interval: {} ms", interval_ms);
    info!("   Targets: {}", target_addresses.len());

    // Precompute target hash160 set
    let mut target_set: HashSet<Vec<u8>> = HashSet::new();
    for addr_str in target_addresses {
        if let Ok(addr) = Address::from_str(addr_str) {
            let script = addr.assume_checked().script_pubkey();
            if script.is_p2pkh() {
                target_set.insert(script.as_bytes()[3..23].to_vec());
            } else if script.is_p2sh() {
                target_set.insert(script.as_bytes()[2..22].to_vec());
            } else {
                warn!("Unsupported address type in sweep mode: {}", addr_str);
            }
        } else {
            warn!("Invalid address skipped in sweep mode: {}", addr_str);
        }
    }

    if target_set.is_empty() {
        anyhow::bail!("No valid P2PKH/P2SH addresses to scan");
    }

    let secp = Secp256k1::new();
    let mut matches = Vec::new();

    let mut ts = start_ms;
    let total = ((end_ms.saturating_sub(start_ms)) / interval_ms) + 1;
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} timestamps ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    while ts <= end_ms {
        // Reconstruct vulnerable RNG
        let prng = BitcoinJsV013Prng::new();
        let seed = super::prng::SeedComponents {
            timestamp_ms: ts,
            user_agent: String::new(),
            screen_width: 0,
            screen_height: 0,
            color_depth: 0,
            timezone_offset: 0,
            language: String::new(),
            platform: String::new(),
        };
        let state = prng.generate_state(&seed);
        let key_bytes = prng.generate_bytes(&state, 32);

        if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let addr = super::derivation::derive_p2pkh_address(&public_key);

            // Compare hash160; skip invalid parses instead of aborting the scan
            if let Ok(parsed) = Address::from_str(&addr) {
                let script = parsed.assume_checked().script_pubkey();
                let hash = if script.is_p2pkh() {
                    script.as_bytes()[3..23].to_vec()
                } else if script.is_p2sh() {
                    script.as_bytes()[2..22].to_vec()
                } else {
                    Vec::new()
                };

                if target_set.contains(&hash) {
                    matches.push((ts, addr));
                }
            } else {
                warn!("Skipping unparsable address at ts {}: {}", ts, addr);
            }
        }

        ts = ts.saturating_add(interval_ms);
        pb.inc(1);
    }

    pb.finish_with_message("Sweep complete");

    // Write output
    let mut writer: Box<dyn Write> = if let Some(path) = output_path {
        Box::new(File::create(path).context("Failed to create output file")?)
    } else {
        Box::new(std::io::stdout())
    };

    writeln!(writer, "Timestamp,Address")?;
    for (ts, addr) in &matches {
        writeln!(writer, "{},{}", ts, addr)?;
    }
    writer.flush()?;

    info!("✅ Sweep complete. Matches: {}", matches.len());
    Ok(())
}

/// Format timestamp as ISO 8601
fn format_timestamp(timestamp_ms: u64) -> String {
    let secs = timestamp_ms / 1000;
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0);

    if let Some(dt) = dt {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        timestamp_ms.to_string()
    }
}

/// Format confidence enum as string
fn format_confidence(confidence: &super::integration::Confidence) -> &'static str {
    match confidence {
        super::integration::Confidence::High => "HIGH",
        super::integration::Confidence::Medium => "MEDIUM",
        super::integration::Confidence::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // TEST-ID: 1.8.1-UNIT-001
    // AC: AC-1 (CSV Input Validation)
    // PRIORITY: P0 (Smoke - must pass)
    #[test]
    fn test_load_addresses_valid_p2pkh() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Test P2PKH addresses").unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        writeln!(temp_file, "1Pji2xSZnKDLqKCp9pYNy7xRYxsKZfHLCx").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    // TEST-ID: 1.8.1-UNIT-002
    // AC: AC-1 (CSV Input Validation)
    // PRIORITY: P0
    #[test]
    fn test_load_addresses_mixed_valid_invalid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file, "invalid_address_123").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 2); // Only valid ones
    }

    // TEST-ID: 1.8.1-UNIT-003
    // AC: AC-1 (CSV Input Validation)
    // PRIORITY: P1
    #[test]
    fn test_load_addresses_comments_and_empty() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Comment line").unwrap();
        writeln!(temp_file, "").unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file, "").unwrap();
        writeln!(temp_file, "# Another comment").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 2);
    }

    // TEST-ID: 1.8.1-UNIT-004
    // AC: AC-1 (CSV Input Validation)
    // PRIORITY: P1
    #[test]
    fn test_load_addresses_file_not_found() {
        let result = load_addresses_from_csv(Path::new("/nonexistent/file.csv"));
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("Failed to open CSV file"));
    }

    // TEST-ID: 1.8.1-UNIT-005
    // AC: AC-1 (CSV Input Validation)
    // PRIORITY: P1
    #[test]
    fn test_load_addresses_whitespace_only() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa   ").unwrap();
        writeln!(temp_file, "  ").unwrap();
        writeln!(temp_file, "\t\t").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_format_confidence() {
        use super::super::integration::Confidence;
        assert_eq!(format_confidence(&Confidence::High), "HIGH");
        assert_eq!(format_confidence(&Confidence::Medium), "MEDIUM");
        assert_eq!(format_confidence(&Confidence::Low), "LOW");
    }

    // TEST-ID: 1.8.1-UNIT-006
    // AC: AC-2 (CSV Output Format)
    // PRIORITY: P0
    #[test]
    fn test_output_results_header() {
        use super::super::fingerprints::BrowserConfig;
        use super::super::integration::{Confidence, VulnerabilityFinding};
        let results: Vec<VulnerabilityFinding> = vec![];
        let mut output = Vec::new();
        
        output_results_to_writer(&results, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        
        assert!(output_str.starts_with("Address,Status,Confidence,BrowserConfig,Timestamp,DerivationPath"));
    }

    // TEST-ID: 1.8.1-UNIT-007
    // AC: AC-2 (CSV Output Format)
    // PRIORITY: P0
    #[test]
    fn test_output_results_single_finding() {
        use super::super::fingerprints::BrowserConfig;
        use super::super::integration::{Confidence, VulnerabilityFinding};
        
        let finding = VulnerabilityFinding {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            confidence: Confidence::High,
            browser_config: BrowserConfig {
                user_agent: "Chrome/25".to_string(),
                platform: "Win32".to_string(),
                screen_width: 1366,
                screen_height: 768,
                ..Default::default()
            },
            timestamp: 1365000000000,
            derivation_path: "m/0'/0/0".to_string(),
        };
        
        let mut output = Vec::new();
        output_results_to_writer(&[finding], &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        
        assert!(output_str.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(output_str.contains("VULNERABLE"));
        assert!(output_str.contains("HIGH"));
        assert!(output_str.contains("Chrome/25/Win32/1366x768"));
    }

    // TEST-ID: 1.8.1-UNIT-008
    // AC: AC-2 (CSV Output Format)
    // PRIORITY: P1
    #[test]
    fn test_output_results_multiple_findings() {
        use super::super::fingerprints::BrowserConfig;
        use super::super::integration::{Confidence, VulnerabilityFinding};
        
        let findings = vec![
            VulnerabilityFinding {
                address: "1Address1".to_string(),
                confidence: Confidence::High,
                browser_config: BrowserConfig::default(),
                timestamp: 1000000000,
                derivation_path: "m/0'/0/0".to_string(),
            },
            VulnerabilityFinding {
                address: "1Address2".to_string(),
                confidence: Confidence::Medium,
                browser_config: BrowserConfig::default(),
                timestamp: 2000000000,
                derivation_path: "m/0'/0/1".to_string(),
            },
        ];
        
        let mut output = Vec::new();
        output_results_to_writer(&findings, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 findings
        assert!(output_str.contains("1Address1"));
        assert!(output_str.contains("1Address2"));
    }

    // TEST-ID: 1.8.1-UNIT-009
    // AC: AC-2 (CSV Output Format)
    // PRIORITY: P1
    #[test]
    fn test_output_results_empty() {
        use super::super::integration::VulnerabilityFinding;
        let results: Vec<VulnerabilityFinding> = vec![];
        let mut output = Vec::new();
        
        output_results_to_writer(&results, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }

    // TEST-ID: 1.8.1-UNIT-010
    // AC: AC-3 (Timestamp Formatting)
    // PRIORITY: P0
    #[test]
    fn test_format_timestamp_iso8601() {
        let timestamp_ms = 1365000000000; // 2013-04-03T14:40:00Z
        let formatted = format_timestamp(timestamp_ms);
        assert_eq!(formatted, "2013-04-03T14:40:00Z");
    }

    // TEST-ID: 1.8.1-UNIT-011
    // AC: AC-3 (Timestamp Formatting)
    // PRIORITY: P1
    #[test]
    fn test_format_timestamp_epoch_zero() {
        let timestamp_ms = 0;
        let formatted = format_timestamp(timestamp_ms);
        assert_eq!(formatted, "1970-01-01T00:00:00Z");
    }

    // TEST-ID: 1.8.1-UNIT-012
    // AC: AC-3 (Timestamp Formatting)
    // PRIORITY: P1
    #[test]
    fn test_format_timestamp_invalid() {
        // Timestamp far in the future (invalid)
        let timestamp_ms = u64::MAX;
        let formatted = format_timestamp(timestamp_ms);
        // Should return raw number as string
        assert_eq!(formatted, u64::MAX.to_string());
    }

    // TEST-ID: 1.9-UNIT-012
    // AC: AC-4 (CLI Mode Flag)
    // PRIORITY: P0
    #[test]
    fn test_cli_mode_flag() {
        use super::super::config::ScanMode;
        
        // Verify ScanMode variants are accessible
        assert_eq!(ScanMode::Quick.interval_ms(), 126_000_000);
        assert_eq!(ScanMode::Standard.interval_ms(), 3_600_000);
        assert_eq!(ScanMode::Deep.interval_ms(), 60_000);
        assert_eq!(ScanMode::Exhaustive.interval_ms(), 1_000);
    }
}

