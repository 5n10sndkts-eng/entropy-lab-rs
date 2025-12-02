# Entropy Lab RS

A research tool for analyzing wallet vulnerabilities and weak entropy sources in cryptocurrency systems.

## Overview

This project implements reproducible demonstrations of various cryptocurrency wallet vulnerabilities, focusing on weak random number generation and predictable entropy sources. It is intended for security research and educational purposes only.

## Features

### Vulnerability Scanners

- **Cake Wallet (2024)**: Reproduce the weak PRNG vulnerability
- **Trust Wallet (2023)**: MT19937 predictable seed vulnerability
- **Android SecureRandom**: Duplicate R value detection and key recovery
- **Libbitcoin "Milk Sad"**: Time-based entropy weakness
- **Mobile Sensor Entropy**: Low-entropy sensor-based key generation
- **Profanity**: Vanity address generator vulnerability
- **Malicious Extension**: Browser extension attack patterns

### GPU Acceleration

Selected scanners support GPU acceleration using OpenCL for high-performance scanning.

## Requirements

- Rust 1.70+ (2021 edition)
- For GPU features: OpenCL drivers and compatible GPU

## Installation

```bash
git clone https://github.com/5n10sndkts-eng/entropy-lab-rs.git
cd entropy-lab-rs
cargo build --release
```

## Usage

### Basic Commands

```bash
# Run Cake Wallet vulnerability scan
cargo run --release -- cake-wallet

# Run Trust Wallet scanner
cargo run --release -- trust-wallet

# Run Android SecureRandom scanner with custom RPC
cargo run --release -- android-secure-random \
  --rpc-url http://localhost:8332 \
  --rpc-user bitcoinrpc \
  --rpc-pass <your-password> \
  --start-block 302000 \
  --end-block 330000

# Run Milk Sad scanner with custom parameters
cargo run --release -- milk-sad \
  --target <target-address> \
  --start-timestamp 1577836800 \
  --end-timestamp 1609459200
```

### Environment Variables

For RPC-based scanners (Cake Wallet RPC, Android SecureRandom), you can configure credentials via environment variables:

```bash
export RPC_URL="http://localhost:8332"
export RPC_USER="bitcoinrpc"
export RPC_PASS="your-secure-password"

cargo run --release -- cake-wallet-rpc
```

## Configuration

### RPC Connection

Some scanners require a Bitcoin Core RPC connection to check balances or scan the blockchain:

- `--rpc-url`: Bitcoin Core RPC endpoint (default: `http://localhost:8332`)
- `--rpc-user`: RPC username (default: `bitcoinrpc`)
- `--rpc-pass`: RPC password (required, no default for security)

### GPU Settings

GPU-accelerated scanners are automatically enabled if OpenCL is available. Configuration is handled in the scanner modules.

## Project Structure

```
entropy-lab-rs/
├── src/
│   ├── main.rs          # CLI interface
│   ├── lib.rs           # Library entry point
│   ├── bin/             # Binary executables
│   └── scans/           # Vulnerability scanner implementations
│       ├── android_securerandom.rs
│       ├── cake_wallet.rs
│       ├── trust_wallet.rs
│       ├── milk_sad.rs
│       └── ...
├── tests/               # Integration tests
├── Cargo.toml          # Dependencies and configuration
└── README.md           # This file
```

## Development

### Building

```bash
cargo build
```

### Testing

```bash
# Run tests (note: requires OpenCL for GPU tests)
cargo test

# Run specific test
cargo test test_bip39_validation
```

### Linting

```bash
cargo clippy -- -D warnings
```

## Security Considerations

⚠️ **Important**: This tool is for research and educational purposes only.

- **Never use on mainnet with real funds** without understanding the implications
- Store RPC credentials securely using environment variables
- Do not commit credentials to version control
- Be aware of rate limits when scanning blockchain data

## Known Limitations

- Android SecureRandom scanner requires completed implementation of ECDSA private key recovery
- GPU features require OpenCL drivers and compatible hardware
- Some scanners may produce false positives and require manual verification

## Contributing

Contributions are welcome! Please ensure:

1. Code compiles without warnings
2. Tests pass (where applicable)
3. Security best practices are followed
4. No credentials are committed

## License

This project is for research purposes. Please see LICENSE file for details.

## Disclaimer

This software is provided for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

## References

- [Cake Wallet Vulnerability Report](https://example.com)
- [Trust Wallet MT19937 Analysis](https://example.com)
- [Libbitcoin "Milk Sad" Disclosure](https://example.com)
- [Android SecureRandom Issues](https://example.com)

## Support

For issues, questions, or contributions, please open an issue on GitHub.
