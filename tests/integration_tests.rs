use std::process::Command;
use assert_cmd::prelude::*;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    // This test ensures the binary compiles and runs, and prints help
    let mut cmd = Command::cargo_bin("entropy-lab-rs").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Research tool for wallet vulnerabilities"));
}

#[test]
fn test_cli_no_args() {
    // Running without args should fail (clap requires subcommand) or print help
    let mut cmd = Command::cargo_bin("entropy-lab-rs").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage: entropy-lab-rs <COMMAND>"));
}

#[test]
fn test_cake_wallet_cpu_scan_integration() {
    // Run a small scan (only 10 seeds) to verify it doesn't panic and produces output
    // Note: We are testing the library function directly here, not the CLI command.
    // This requires 'entropy-lab-rs' to be a library crate exposing 'scans'.
    let result = entropy_lab_rs::scans::cake_wallet::run(Some(10));
    assert!(result.is_ok(), "Cake Wallet CPU scan failed");
}
