use clap::{Parser, Subcommand};
use anyhow::Result;
use entropy_lab_rs::scans;

#[derive(Parser)]
#[command(name = "entropy-lab")]
#[command(about = "Research tool for wallet vulnerabilities", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Reproduce Cake Wallet 2024 Vulnerability
    CakeWallet,
    /// Scan only the 8,717 confirmed vulnerable Cake Wallet seeds
    CakeWalletTargeted,
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
    CakeWalletRpc {
        #[arg(long, env = "RPC_URL", default_value = "http://localhost:8332")]
        rpc_url: String,
        #[arg(long, env = "RPC_USER", default_value = "bitcoinrpc")]
        rpc_user: String,
        #[arg(long, env = "RPC_PASS", required = true)]
        rpc_pass: String,
    },
    /// Scan Android SecureRandom vulnerability (duplicate R values)
    AndroidSecureRandom {
        #[arg(long, env = "RPC_URL", default_value = "http://localhost:8332")]
        rpc_url: String,
        #[arg(long, env = "RPC_USER", default_value = "bitcoinrpc")]
        rpc_user: String,
        #[arg(long, env = "RPC_PASS", required = true)]
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
}


fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CakeWallet => {
            println!("Running Cake Wallet Vulnerability Reproduction...");
            scans::cake_wallet::run()?;
        }
        Commands::CakeWalletTargeted => {
            println!("Running Cake Wallet TARGETED Scan (8,717 confirmed vulnerable seeds)...");
            scans::cake_wallet_targeted::run_targeted()?;
        }
        Commands::CakeWalletDartPrng => {
            println!("Running Cake Wallet Dart PRNG Scanner (time-based reconstruction)...");
            scans::cake_wallet_dart_prng::run()?;
        }
        Commands::TrustWallet { target } => {
            println!("Running Trust Wallet Vulnerability Reproduction...");
            scans::trust_wallet::run(target)?;
        }
        Commands::MobileSensor { target } => {
            println!("Running Mobile Sensor Entropy Reproduction...");
            scans::mobile_sensor::run(target)?;
        }
        Commands::MilkSad { target, start_timestamp, end_timestamp, multipath } => {
            println!("Running Libbitcoin 'Milk Sad' Vulnerability Reproduction...");
            if let Some(t) = target {
                scans::milk_sad::run_with_target(t, start_timestamp, end_timestamp, multipath)?;
            } else {
                scans::milk_sad::run()?;
            }
        }
        Commands::MaliciousExtension => {
            println!("Running Malicious Extension Reproduction...");
            scans::malicious_extension::run()?;
        }
        Commands::Profanity { target } => {
            println!("Running Profanity Vanity Address Vulnerability Reproduction...");
            scans::profanity::run(target)?;
        }
        Commands::VerifyCsv { input, addresses } => {
            println!("Running CSV Verification...");
            scans::verify_csv::run(&input, &addresses)?;
        }
        Commands::CakeWalletRpc { rpc_url, rpc_user, rpc_pass } => {
            println!("Running Cake Wallet RPC Scanner...");
            scans::cake_wallet_rpc::run(&rpc_url, &rpc_user, &rpc_pass)?;
        }
        Commands::AndroidSecureRandom { rpc_url, rpc_user, rpc_pass, start_block, end_block } => {
            println!("Running Android SecureRandom Scanner...");
            scans::android_securerandom::run(&rpc_url, &rpc_user, &rpc_pass, start_block, end_block)?;
        }
    }



    Ok(())
}

