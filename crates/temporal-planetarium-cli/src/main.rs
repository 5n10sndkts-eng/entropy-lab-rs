use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use temporal_planetarium_lib::scans;
use tracing::info;

mod commands;

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
        #[arg(long)]
        db_path: Option<std::path::PathBuf>,
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

        /// GPU Backend: auto|wgpu|opencl|cpu
        #[arg(long)]
        backend: Option<String>,

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

        /// Run complexity estimator and exit
        #[arg(long)]
        estimate: bool,

        /// Attempt to recover MWC1616 state from provided 32-bit outputs (comma-separated hex/int)
        #[arg(long)]
        z3_solve: Option<String>,

        /// Path coverage: 'legacy' (m/0/0 only) or 'all' (BIP44/49/84/86)
        #[arg(long, default_value = "legacy")]
        path_coverage: String,
 
        /// Database file path to pull targets from
        #[arg(long)]
        db: Option<std::path::PathBuf>,
 
        /// Vulnerability class to query from database
        #[arg(long)]
        class: Option<String>,
    },
    /// Import targets from CSV into the database
    DbImport {
        /// CSV file containing addresses
        #[arg(long)]
        csv: std::path::PathBuf,
        /// Vulnerability class (e.g., randstorm, milk_sad)
        #[arg(long)]
        class: String,
        /// Database file path (default: targets.db)
        #[arg(long, default_value = "targets.db")]
        db: std::path::PathBuf,
    },
    /// Query targets from the database
    DbQuery {
        /// Vulnerability class to query
        #[arg(long)]
        class: String,
        /// Max number of targets to return
        #[arg(long, default_value = "10")]
        limit: usize,
        /// Database file path (default: targets.db)
        #[arg(long, default_value = "targets.db")]
        db: std::path::PathBuf,
    },
    /// Recover private key from ECDSA nonce reuse
    NonceReuseRecovery {
        /// Message hash 1 (hex)
        #[arg(long)]
        z1: String,
        /// Message hash 2 (hex)
        #[arg(long)]
        z2: String,
        /// Shared signature R-value (hex)
        #[arg(long)]
        r: String,
        /// Signature S-value 1 (hex)
        #[arg(long)]
        s1: String,
        /// Signature S-value 2 (hex)
        #[arg(long)]
        s2: String,
        /// Output file for encrypted private key (REQUIRED for security)
        #[arg(long)]
        output: std::path::PathBuf,
        /// Encryption passphrase (or set NONCE_CRAWLER_PASSPHRASE env var)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Validate bit-parity between CPU Golden Reference and GPU backends
    RandstormValidate {
        /// Backend to validate against: wgpu|opencl
        #[arg(long, default_value = "wgpu")]
        backend: String,
        /// Number of iterations (seeds) to validate
        #[arg(long, default_value = "1000")]
        count: u64,
        /// Browser engine: v8|spidermonkey
        #[arg(long, default_value = "v8")]
        engine: String,
    },
    /// Scan blockchain for ECDSA nonce reuse vulnerabilities
    ///
    /// Scans blocks for signatures that reuse the same R-value, which allows
    /// private key recovery. Detected collisions and recovered keys are stored
    /// in the database with AES-256-GCM encryption.
    ///
    /// Requires a Bitcoin Core node with RPC access.
    ///
    /// **Security:** Set NONCE_CRAWLER_PASSPHRASE environment variable for production use.
    /// Default passphrase is for development/testing only.
    NonceReuseCrawler {
        /// RPC URL (e.g., http://127.0.0.1:8332)
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc_url: String,
        /// RPC username
        #[arg(long)]
        rpc_user: String,
        /// RPC password
        #[arg(long)]
        rpc_pass: String,
        /// Database file path (default: nonce_reuse.db)
        #[arg(long, default_value = "nonce_reuse.db")]
        db: std::path::PathBuf,
        /// Start block height (optional, defaults to latest-999)
        #[arg(long)]
        start_block: Option<u64>,
        /// End block height (optional, defaults to latest)
        #[arg(long)]
        end_block: Option<u64>,
        /// Scan last N blocks (alternative to --start-block)
        #[arg(long)]
        last_n_blocks: Option<u64>,
        /// Resume from checkpoint
        #[arg(long)]
        resume: bool,
        /// Encryption passphrase for private keys (default: MadMad13221!@)
        #[arg(long, env = "NONCE_CRAWLER_PASSPHRASE")]
        passphrase: Option<String>,
        /// Rate limit delay between blocks in milliseconds (default: 50)
        #[arg(long, default_value = "50")]
        rate_limit_ms: u64,
    },
    /// List recovered private keys from nonce reuse database
    ///
    /// Decrypts and displays recovered private keys. Requires the correct
    /// encryption passphrase.
    ///
    /// **Security:** Provide passphrase via NONCE_CRAWLER_PASSPHRASE environment variable.
    ListRecoveredKeys {
        /// Database file path (default: nonce_reuse.db)
        #[arg(long, default_value = "nonce_reuse.db")]
        db: std::path::PathBuf,
        /// Encryption passphrase (default: MadMad13221!@)
        #[arg(long, env = "NONCE_CRAWLER_PASSPHRASE")]
        passphrase: Option<String>,
        /// Output format: table|json|csv
        #[arg(long, default_value = "table")]
        format: String,
        /// Show decrypted private keys
        #[arg(long)]
        show_keys: bool,
    },
    /// Import brainwallet dictionary and generate addresses
    ///
    /// **Security:** Set BRAINWALLET_ENCRYPTION_PASSPHRASE environment variable for production use.
    /// Default passphrase is for development/testing only.
    BrainwalletImport {
        /// Path to wordlist file (supports .txt, .txt.gz)
        #[arg(long)]
        wordlist: std::path::PathBuf,
        /// Database path for storing results
        #[arg(long, default_value = "targets.db")]
        db_path: std::path::PathBuf,
        /// Hash type: sha256-1x, sha256-1000x, sha3-256
        #[arg(long, default_value = "sha256-1x")]
        hash_type: String,
        /// Address type: p2pkh-uncompressed, p2pkh-compressed, p2shwpkh, p2wpkh
        #[arg(long, default_value = "p2pkh-compressed")]
        address_type: String,
        /// Dry run - don't write to database
        #[arg(long)]
        dry_run: bool,
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
            temporal_planetarium_lib::gui::run_gui()?;
        }
        Commands::CakeWallet { limit } => {
            info!("Running Cake Wallet Vulnerability Reproduction...");
            scans::cake_wallet::run_standard(limit)?;
        }
        Commands::CakeWalletTargeted => {
            info!("Running Cake Wallet TARGETED Scan (8,717 confirmed vulnerable seeds)...");
            scans::cake_wallet::run_targeted()?;
        }
        Commands::CakeWalletCrack { target } => {
            info!("Running Cake Wallet GPU Cracker...");
            scans::cake_wallet::run_crack(&target)?;
        }
        Commands::CakeWalletDartPrng => {
            info!("Running Cake Wallet Dart PRNG Scanner (time-based reconstruction)...");
            scans::cake_wallet::run_prng()?;
        }
        Commands::TrustWallet { target } => {
            info!("Running Trust Wallet Vulnerability Reproduction...");
            scans::trust_wallet::run_standard(target)?;
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
            db_path,
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
                db_path,
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
            scans::cake_wallet::run_rpc(&url, &user, &pass)?;
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
            temporal_planetarium_lib::utils::bloom_filter::build_from_file(
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
            scans::trust_wallet::run_lcg(&target, start_ts, end_ts)?;
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
            backend,
            output,
            randstorm_engine,
            randstorm_seed_override,
            randstorm_seed_bruteforce_bits,
            randstorm_include_uncompressed,
            estimate,
            z3_solve,
            path_coverage,
            db,
            class,
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
                backend.as_deref(),
                &randstorm_engine,
                randstorm_seed_override,
                randstorm_seed_bruteforce_bits,
                randstorm_include_uncompressed,
                estimate,
                z3_solve.as_deref(),
                &path_coverage,
                db.as_deref(),
                class.as_deref(),
            )?;
        }
        Commands::RandstormValidate { backend, count, engine } => {
            scans::randstorm::cli::run_validate_parity(&backend, count, &engine)?;
        }
        Commands::DbImport { csv, class, db } => {
            info!("Importing targets from {:?} into {} class...", csv, class);
            let target_db = temporal_planetarium_lib::utils::db::TargetDatabase::new(db)?;
            let file = std::fs::File::open(csv)?;
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(file);
            let mut count = 0;
            for result in reader.records() {
                let record = result?;
                let address = record.get(0).context("Missing address or passphrase in CSV row")?.to_string();
                
                if class == "brainwallet" {
                    // Store as intelligence
                    target_db.add_intelligence("passphrase", &address, None, Some("brainwallet"))?;
                    
                    // Auto-derive and add to targets using heuristics
                    if let Ok(derived_targets) = temporal_planetarium_lib::scans::randstorm::heuristics::generate_heuristic_targets(&address) {
                        for (derived_addr, variation) in derived_targets {
                            let target = temporal_planetarium_lib::utils::db::Target {
                                address: derived_addr,
                                vuln_class: class.clone(),
                                first_seen_timestamp: None,
                                metadata_json: Some(format!("{{\"passphrase\": \"{}\", \"variation_of\": \"{}\"}}", variation, address)),
                                status: "pending".to_string(),
                                ..Default::default()
                            };
                            target_db.upsert_target(&target)?;
                        }
                    }
                } else {
                    let target = temporal_planetarium_lib::utils::db::Target {
                        address,
                        vuln_class: class.clone(),
                        first_seen_timestamp: None,
                        metadata_json: None,
                        status: "pending".to_string(),
                        ..Default::default()
                    };
                    target_db.upsert_target(&target)?;
                }
                count += 1;
            }
            info!("Successfully imported {} targets.", count);
        }
        Commands::DbQuery { class, limit, db } => {
            info!("Querying top {} targets for {}...", limit, class);
            let target_db = temporal_planetarium_lib::utils::db::TargetDatabase::new(db)?;
            let results = target_db.query_by_class(&class, limit)?;
            for t in results {
                println!("{}", t.address);
            }
        }
        Commands::NonceReuseRecovery { z1, z2, r, s1, s2, output, passphrase } => {
            use temporal_planetarium_lib::utils::encryption::{encrypt_private_key, DEFAULT_ENCRYPTION_PASSPHRASE};

            info!("Running ECDSA Nonce Reuse Recovery...");
            let z1_bytes = hex::decode(z1)?.try_into().map_err(|_| anyhow::anyhow!("z1 must be 32 bytes"))?;
            let z2_bytes = hex::decode(z2)?.try_into().map_err(|_| anyhow::anyhow!("z2 must be 32 bytes"))?;
            let r_bytes = hex::decode(r)?.try_into().map_err(|_| anyhow::anyhow!("r must be 32 bytes"))?;
            let s1_bytes = hex::decode(s1)?.try_into().map_err(|_| anyhow::anyhow!("s1 must be 32 bytes"))?;
            let s2_bytes = hex::decode(s2)?.try_into().map_err(|_| anyhow::anyhow!("s2 must be 32 bytes"))?;

            // Get passphrase from arg, env, or default
            let pass = passphrase
                .or_else(|| std::env::var("NONCE_CRAWLER_PASSPHRASE").ok())
                .unwrap_or_else(|| {
                    tracing::warn!("⚠️  Using default encryption passphrase. Set --passphrase or NONCE_CRAWLER_PASSPHRASE for production use.");
                    DEFAULT_ENCRYPTION_PASSPHRASE.to_string()
                });

            match temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse(
                &z1_bytes, &z2_bytes, &r_bytes, &s1_bytes, &s2_bytes
            ) {
                Ok(sk) => {
                    info!("✅ SUCCESS! Private key recovered!");

                    // Convert to WIF and encrypt immediately
                    let wif = bitcoin::PrivateKey::new(sk, bitcoin::Network::Bitcoin).to_wif();
                    let encrypted = encrypt_private_key(&wif, &pass)?;

                    // Derive address for identification
                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    let pubkey = sk.public_key(&secp);
                    let address = bitcoin::Address::p2pkh(
                        bitcoin::CompressedPublicKey(pubkey),
                        bitcoin::Network::Bitcoin
                    );

                    // Write encrypted key to file as JSON
                    let output_data = serde_json::json!({
                        "address": address.to_string(),
                        "network": "mainnet",
                        "encrypted_wif": hex::encode(&encrypted.ciphertext),
                        "nonce": hex::encode(&encrypted.nonce),
                        "salt": hex::encode(&encrypted.salt),
                        "encryption": "AES-256-GCM",
                        "kdf": "PBKDF2-HMAC-SHA256",
                        "kdf_iterations": 100000,
                        "recovered_from": "nonce_reuse",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "warning": "PRIVATE KEY - Handle with extreme care. Decrypt with list-recovered-keys command."
                    });

                    std::fs::write(&output, serde_json::to_string_pretty(&output_data)?)?;

                    // Clear sensitive data from memory (WIF string)
                    // Note: Rust strings are immutable, so we can't zeroize in-place
                    // The `sk` SecretKey will be dropped and memory freed
                    drop(wif);

                    println!("🔐 Private key recovered and encrypted!");
                    println!("📍 Address: {}", address);
                    println!("💾 Saved to: {}", output.display());
                    println!("");
                    println!("⚠️  SECURITY: Private key is encrypted with AES-256-GCM.");
                    println!("   To decrypt, use: entropy-lab list-recovered-keys --show-keys");
                }
                Err(e) => {
                    anyhow::bail!("Recovery failed: {}", e);
                }
            }
        }
        Commands::NonceReuseCrawler {
            rpc_url,
            rpc_user,
            rpc_pass,
            db,
            start_block,
            end_block,
            last_n_blocks,
            resume,
            passphrase,
            rate_limit_ms,
        } => {
            use temporal_planetarium_lib::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE;

            let pass = passphrase.unwrap_or_else(|| DEFAULT_ENCRYPTION_PASSPHRASE.to_string());
            commands::nonce_crawler::run(
                rpc_url,
                rpc_user,
                rpc_pass,
                db,
                start_block,
                end_block,
                last_n_blocks,
                resume,
                pass,
                Some(rate_limit_ms),
            )?;
        }
        Commands::ListRecoveredKeys {
            db,
            passphrase,
            format,
            show_keys,
        } => {
            use temporal_planetarium_lib::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE;

            let pass = passphrase.unwrap_or_else(|| DEFAULT_ENCRYPTION_PASSPHRASE.to_string());
            let output_format = format.parse::<commands::list_keys::OutputFormat>()?;
            commands::list_keys::run(db, pass, output_format, show_keys)?;
        }
        Commands::BrainwalletImport {
            wordlist,
            db_path,
            hash_type,
            address_type,
            dry_run,
        } => {
            commands::brainwallet_import::run(wordlist, db_path, hash_type, address_type, dry_run)?;
        }
    }

    Ok(())
}
