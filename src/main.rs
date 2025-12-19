use anyhow::Result;
use clap::{Parser, Subcommand};
use entropy_lab_rs::scans;
use tracing::info;

#[derive(Parser)]
#[command(name = "entropy-lab")]
#[command(about = "Research tool for wallet vulnerabilities", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch GUI interface for interactive scanning
    #[cfg(feature = "gui")]
    Gui,
    /// Reproduce Cake Wallet 2024 Vulnerability
    CakeWallet {
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Scan only the 8,717 confirmed vulnerable Cake Wallet seeds
    CakeWalletTargeted,
    /// Find seed from Cake Wallet address (GPU) - checks prefix "100" and 40 addresses
    CakeWalletCrack {
        #[arg(long)]
        target: String,
    },
    /// Reverse-engineer Cake Wallet seeds using Dart PRNG (time-based)
    CakeWalletDartPrng,
    /// Reproduce Trust Wallet 2023 Vulnerability
    TrustWallet {
        #[arg(long)]
        target: Option<String>,
    },
    /// Reproduce Mobile Sensor Entropy Vulnerability
    MobileSensor {
        #[arg(long)]
        target: Option<String>,
    },
    /// Reproduce Libbitcoin "Milk Sad" Vulnerability
    MilkSad {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        start_timestamp: Option<u32>,
        #[arg(long)]
        end_timestamp: Option<u32>,
        #[arg(long, default_value = "false")]
        multipath: bool,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long)]
        rpc_user: Option<String>,
        #[arg(long)]
        rpc_pass: Option<String>,
    },
    /// Reproduce Malicious Browser Extension Logic
    MaliciousExtension,
    /// Verify CSV against funded addresses
    VerifyCsv {
        #[arg(long)]
        input: String,
        #[arg(long)]
        addresses: String,
    },
    /// Scan Cake Wallet vulnerability with RPC balance checking
    /// Requires RPC credentials. Set via: --rpc-url, --rpc-user, --rpc-pass
    /// Or use environment variables: RPC_URL, RPC_USER, RPC_PASS
    CakeWalletRpc {
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        #[arg(long)]
        rpc_user: String,
        #[arg(long)]
        rpc_pass: String,
    },
    /// Scan Android SecureRandom vulnerability (duplicate R values)
    /// Requires RPC credentials. Set via: --rpc-url, --rpc-user, --rpc-pass
    /// Or use environment variables: RPC_URL, RPC_USER, RPC_PASS
    AndroidSecureRandom {
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        #[arg(long)]
        rpc_user: String,
        #[arg(long)]
        rpc_pass: String,
        #[arg(long, default_value = "302000")]
        start_block: u64,
        #[arg(long, default_value = "330000")]
        end_block: u64,
    },
    /// Reproduce Profanity Vanity Address Vulnerability
    Profanity {
        #[arg(long)]
        target: Option<String>,
    },
    /// Build a Bloom Filter from a list of addresses
    BuildBloom {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long, default_value = "1000000000")]
        expected_items: usize,
        #[arg(long, default_value = "0.0001")]
        fp_rate: f64,
    },
    /// Scan for bip3x (PCG-XSH-RR) vulnerability
    Bip3x,
    /// Scan for EC-New (Direct PRNG) vulnerability
    EcNew {
        #[arg(long)]
        target: String,
        #[arg(long)]
        start: Option<u32>,
        #[arg(long)]
        end: Option<u32>,
    },
    /// Scan for Trust Wallet iOS LCG (minstd_rand0) vulnerability
    TrustWalletLcg {
        #[arg(long)]
        target: String,
        #[arg(long)]
        start: Option<u32>,
        #[arg(long)]
        end: Option<u32>,
    },
    /// Randstorm vulnerability scanner - detect wallets with weak browser PRNG entropy
    ///
    /// Scans Bitcoin addresses for the Randstorm vulnerability (CVE-2024-XXXX), which affected
    /// cryptocurrency wallets generated in browsers between 2011-2015 due to weak Math.random()
    /// entropy. This scanner tests browser fingerprint combinations to identify vulnerable wallets.
    ///
    /// Examples:
    ///   # Scan addresses from CSV file (Phase 1: top 100 configs)
    ///   entropy-lab-rs randstorm-scan --target-addresses addresses.csv
    ///
    ///   # Force CPU-only mode (no GPU)
    ///   entropy-lab-rs randstorm-scan --target-addresses addresses.csv --cpu
    ///
    ///   # Save results to file
    ///   entropy-lab-rs randstorm-scan --target-addresses addrs.csv --output results.csv
    ///
    ///   # Phase 2 scan (top 500 browser configs)
    ///   entropy-lab-rs randstorm-scan --target-addresses addrs.csv --phase 2
    RandstormScan {
        /// Target Bitcoin addresses CSV file (one address per line)
        #[arg(long, required = true)]
        target_addresses: std::path::PathBuf,
        /// Optional start timestamp (ms since epoch) for direct sweep mode
        #[arg(long)]
        start_ms: Option<u64>,
        /// Optional end timestamp (ms since epoch) for direct sweep mode
        #[arg(long)]
        end_ms: Option<u64>,
        /// Interval between timestamps in milliseconds (direct sweep mode)
        #[arg(long, default_value = "100")]
        interval_ms: u64,

        /// Scanner phase: 1=top 100 configs, 2=top 500, 3=all configs
        #[arg(long, default_value = "1")]
        phase: u8,

        /// Scan mode: quick (1K timestamps), standard (35K), deep (2.1M), exhaustive (126M)
        #[arg(long, default_value = "standard")]
        mode: String,

        /// Force GPU acceleration (fails if unavailable)
        #[arg(long, conflicts_with = "cpu")]
        gpu: bool,

        /// Force CPU fallback (disables GPU)
        #[arg(long, conflicts_with = "gpu")]
        cpu: bool,

        /// Output CSV file (default: stdout)
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Math.random engine: v8|drand48|java|xorshift128plus
        #[arg(long, default_value = "v8")]
        randstorm_engine: String,

        /// Override Math.random seed (engine-specific, usually 48 bits)
        #[arg(long)]
        randstorm_seed_override: Option<u64>,

        /// Brute-force seed bits (adds 2^bits seeds per timestamp; max 28)
        #[arg(long)]
        randstorm_seed_bruteforce_bits: Option<u8>,

        /// Also test uncompressed pubkeys when deriving P2PKH
        #[arg(long)]
        randstorm_include_uncompressed: bool,
    },
}

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8332";

/// Helper function to get RPC credentials with environment variable fallback
fn get_rpc_credentials(
    url: String,
    user: String,
    pass: String,
) -> Result<(String, String, String)> {
    let final_url = if url == DEFAULT_RPC_URL {
        std::env::var("RPC_URL").unwrap_or(url)
    } else {
        url
    };

    let final_user = if user.is_empty() {
        std::env::var("RPC_USER").map_err(|_| {
            anyhow::anyhow!(
                "RPC_USER must be provided via --rpc-user flag or RPC_USER environment variable"
            )
        })?
    } else {
        user
    };

    let final_pass = if pass.is_empty() {
        std::env::var("RPC_PASS").map_err(|_| {
            anyhow::anyhow!(
                "RPC_PASS must be provided via --rpc-pass flag or RPC_PASS environment variable"
            )
        })?
    } else {
        pass
    };

    Ok((final_url, final_user, final_pass))
}

fn main() -> Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "gui")]
        Commands::Gui => {
            info!("Launching GUI interface...");
            entropy_lab_rs::gui::run_gui()?;
        }
        Commands::CakeWallet { limit } => {
            info!("Running Cake Wallet Vulnerability Reproduction...");
            scans::cake_wallet::run(limit)?;
        }
        Commands::CakeWalletTargeted => {
            info!("Running Cake Wallet TARGETED Scan (8,717 confirmed vulnerable seeds)...");
            scans::cake_wallet_targeted::run_targeted()?;
        }
        Commands::CakeWalletCrack { target } => {
            info!("Running Cake Wallet GPU Cracker...");
            scans::cake_wallet_crack::run_crack(&target)?;
        }
        Commands::CakeWalletDartPrng => {
            info!("Running Cake Wallet Dart PRNG Scanner (time-based reconstruction)...");
            scans::cake_wallet_dart_prng::run()?;
        }
        Commands::TrustWallet { target } => {
            info!("Running Trust Wallet Vulnerability Reproduction...");
            scans::trust_wallet::run(target)?;
        }
        Commands::MobileSensor { target } => {
            info!("Running Mobile Sensor Entropy Reproduction...");
            scans::mobile_sensor::run(target)?;
        }
        Commands::MilkSad {
            target,
            start_timestamp,
            end_timestamp,
            multipath,
            rpc_url,
            rpc_user,
            rpc_pass,
        } => {
            info!("Running Libbitcoin 'Milk Sad' Vulnerability Reproduction...");

            // Resolve RPC credentials if provided
            let rpc_config =
                if let (Some(url), Some(user), Some(pass)) = (rpc_url, rpc_user, rpc_pass) {
                    Some(get_rpc_credentials(url, user, pass)?)
                } else {
                    // If specific flags not provided, try generic env vars?
                    // get_rpc_credentials handles env vars if we pass empty strings, but here they are Options.
                    // Let's rely on user explicit flags strictly for now or explicit env fallback logic if I adapt get_rpc_credentials logic.
                    None
                };

            // Wait, get_rpc_credentials consumes simple strings.
            // Let's just pass Options to milk_sad.run?
            // Existing run() takes nothing. run_with_target takes target string.
            // We need to refactor milk_sad::run to be more flexible.

            scans::milk_sad::run_scan(
                target,
                start_timestamp,
                end_timestamp,
                multipath,
                rpc_config,
            )?;
        }
        Commands::MaliciousExtension => {
            info!("Running Malicious Extension Reproduction...");
            scans::malicious_extension::run()?;
        }
        Commands::Profanity { target } => {
            info!("Running Profanity Vanity Address Vulnerability Reproduction...");
            scans::profanity::run(target)?;
        }
        Commands::VerifyCsv { input, addresses } => {
            info!("Running CSV Verification...");
            scans::verify_csv::run(&input, &addresses)?;
        }
        Commands::CakeWalletRpc {
            rpc_url,
            rpc_user,
            rpc_pass,
        } => {
            info!("Running Cake Wallet RPC Scanner...");
            let (url, user, pass) = get_rpc_credentials(rpc_url, rpc_user, rpc_pass)?;
            scans::cake_wallet_rpc::run(&url, &user, &pass)?;
        }
        Commands::AndroidSecureRandom {
            rpc_url,
            rpc_user,
            rpc_pass,
            start_block,
            end_block,
        } => {
            info!("Running Android SecureRandom Scanner...");
            let (url, user, pass) = get_rpc_credentials(rpc_url, rpc_user, rpc_pass)?;
            scans::android_securerandom::run(&url, &user, &pass, start_block, end_block)?;
        }
        Commands::BuildBloom {
            input,
            output,
            expected_items,
            fp_rate,
        } => {
            info!("Building Bloom Filter...");
            entropy_lab_rs::utils::bloom_filter::build_from_file(
                &input,
                &output,
                expected_items,
                fp_rate,
            )?;
        }
        Commands::Bip3x => {
            scans::bip3x::run()?;
        }
        Commands::EcNew { target, start, end } => {
            scans::ec_new::run(&target, start, end)?;
        }
        Commands::TrustWalletLcg { target, start, end } => {
            let start_ts = start.unwrap_or(1293840000); // 2011
            let end_ts = end.unwrap_or(1735689600); // 2025
            scans::trust_wallet_lcg::run(&target, start_ts, end_ts)?;
        }
        Commands::RandstormScan {
            target_addresses,
            start_ms,
            end_ms,
            interval_ms,
            phase,
            mode,
            gpu,
            cpu,
            output,
            randstorm_engine,
            randstorm_seed_override,
            randstorm_seed_bruteforce_bits,
            randstorm_include_uncompressed,
        } => {
            scans::randstorm::cli::run_scan(
                &target_addresses,
                start_ms,
                end_ms,
                interval_ms,
                phase,
                &mode,
                gpu,
                cpu,
                output.as_deref(),
                &randstorm_engine,
                randstorm_seed_override,
                randstorm_seed_bruteforce_bits,
                randstorm_include_uncompressed,
            )?;
        }
    }

    Ok(())
}
