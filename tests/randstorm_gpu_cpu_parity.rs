//! GPU-CPU Parity Tests for Randstorm Scanner
//!
//! TEST-ID: 1.6-INTEGRATION-001
//! AC: Story 1.6 AC-5 "CPU-GPU parity test passes"
//! PRIORITY: P0 (Critical - must pass)
//!
//! Verifies that GPU and CPU implementations produce identical results.

#[cfg(test)]
mod randstorm_parity_tests {
    use entropy_lab_rs::scans::randstorm::{
        config::ScannerConfig,
        fingerprint::BrowserFingerprint,
        integration::RandstormScanner,
    };

    #[test]
    #[ignore] // Only run when GPU is available
    fn test_gpu_cpu_parity_identical_fingerprints() {
        // TEST-ID: 1.6-PARITY-001
        // AC: Story 1.6 AC-5
        // Verify GPU and CPU produce identical results for same fingerprints

        let fingerprints = vec![
            BrowserFingerprint::new()
                .with_timestamp(1365000000000) // 2013-04-03
                .with_user_agent("Mozilla/5.0 (Windows NT 6.1) Chrome/25.0.1364.172")
                .with_screen(1366, 768)
                .with_timezone(-480)
                .with_language("en-US")
                .with_platform("Win32"),
        ];

        let target_addresses = vec![
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        ];

        // Run GPU scan
        let config_gpu = ScannerConfig::default().with_gpu(true);
        let mut scanner_gpu = RandstormScanner::new(config_gpu).unwrap();
        let results_gpu = scanner_gpu.scan(&fingerprints, &target_addresses).unwrap();

        // Run CPU scan
        let config_cpu = ScannerConfig::default().with_gpu(false);
        let mut scanner_cpu = RandstormScanner::new(config_cpu).unwrap();
        let results_cpu = scanner_cpu.scan(&fingerprints, &target_addresses).unwrap();

        // Verify identical results
        assert_eq!(
            results_gpu.len(),
            results_cpu.len(),
            "GPU and CPU must find same number of matches"
        );

        // If matches found, verify details are identical
        for (gpu_match, cpu_match) in results_gpu.iter().zip(results_cpu.iter()) {
            assert_eq!(
                gpu_match.address, cpu_match.address,
                "GPU and CPU must match same addresses"
            );
            assert_eq!(
                gpu_match.fingerprint_id, cpu_match.fingerprint_id,
                "GPU and CPU must identify same fingerprints"
            );
        }
    }

    #[test]
    fn test_cpu_fallback_when_gpu_unavailable() {
        // TEST-ID: 1.6-PARITY-002
        // AC: Story 1.7 AC-1 "Auto-fallback when GPU unavailable"
        // Verify CPU fallback works when GPU feature disabled

        let fingerprints = vec![BrowserFingerprint::new()];
        let target_addresses = vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string()];

        let config = ScannerConfig::default(); // Auto-detect GPU
        let scanner = RandstormScanner::new(config);

        // Should succeed even without GPU
        assert!(
            scanner.is_ok(),
            "Scanner should initialize with CPU fallback"
        );
    }
}
