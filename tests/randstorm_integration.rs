use anyhow::Result;
use temporal_planetarium_lib::scans::randstorm::{
    config::{ScanConfig, ScanMode},
    integration::RandstormScanner,
    prng::MathRandomEngine,
    synthetic_wallet::SyntheticWalletGenerator,
};

#[test]
fn test_synthetic_wallet_detection_full_pipeline() -> Result<()> {
    // 1. Generate a synthetic vulnerable wallet (Chrome V8)
    // Timestamp: 2013-04-15 12:00:00 UTC
    let target_timestamp = 1366027200000;
    
    let generator = SyntheticWalletGenerator::new();
    let wallet = generator.generate_wallet_v8(target_timestamp)?;
    
    println!("Generated Synthetic Wallet:");
    println!("  Address: {}", wallet.address);
    println!("  Timestamp: {}", wallet.timestamp_ms);

    // 2. Configure Scanner with Heuristic Search (Spiral)
    // Set target timestamp to the wallet's timestamp
    // Window +/- 1 hour (3,600,000 ms)
    let mut config = ScanConfig::default();
    config.scan_mode = ScanMode::Standard;
    config.use_gpu = false; // Force CPU
    config.target_timestamp = Some(target_timestamp);
    config.timestamp_window = Some(3_600_000); 
    
    // 3. Initialize Scanner
    let mut scanner = RandstormScanner::with_config(config, MathRandomEngine::V8Mwc1616)?;

    // 4. Run Scan
    println!("\nStarting Scan...");
    // Phase::One scans top 100 browser configs (Chrome V8 is high priority)
    let result = scanner.scan(&wallet.address, temporal_planetarium_lib::scans::randstorm::fingerprints::Phase::One)?;

    // 5. Verify Detection
    assert!(result.is_some(), "Scanner failed to detect synthetic wallet");
    
    let finding = result.unwrap();
    println!("\nDetection Successful!");
    println!("  Found Address: {}", finding.address);
    println!("  Confidence: {:?}", finding.confidence);
    println!("  Timestamp Found: {}", finding.timestamp);
    println!("  Browser: {}", finding.browser_config.user_agent);

    // Verify metadata
    assert_eq!(finding.address, wallet.address);
    assert_eq!(finding.timestamp, target_timestamp, "Timestamp mismatch");
    assert!(finding.browser_config.user_agent.contains("Chrome") || finding.browser_config.user_agent.contains("Chromium"));

    Ok(())
}
