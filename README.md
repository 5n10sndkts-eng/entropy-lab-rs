# Entropy Lab RS

A research tool for identifying and analyzing cryptocurrency wallet vulnerabilities related to weak entropy generation.

## Overview

Entropy Lab RS is a Rust-based security research tool that scans for various known wallet vulnerabilities by reproducing weak random number generation patterns. This tool is designed for security researchers, white-hat hackers, and blockchain security professionals to identify vulnerable wallets and understand entropy weaknesses.

## Features

This tool includes scanners for the following known vulnerabilities:

### Implemented Scanners

1. **Cake Wallet (2024)** - Scans for the Cake Wallet entropy vulnerability
2. **Trust Wallet (2023)** - Reproduces Trust Wallet MT19937 weakness
3. **Mobile Sensor Entropy** - Tests mobile sensor-based entropy vulnerabilities
4. **Libbitcoin "Milk Sad"** - Scans for the Milk Sad vulnerability (CVE-2023-39910)
5. **Malicious Browser Extension** - Simulates malicious extension entropy manipulation
6. **Android SecureRandom** - Detects duplicate R values in ECDSA signatures
7. **Profanity** - Scans for Profanity vanity address vulnerabilities
8. **Cake Wallet Dart PRNG** - Time-based Dart PRNG vulnerability scanner

### Features

- GPU acceleration support via OpenCL for high-performance scanning
- RPC integration for balance checking
- CSV verification against funded addresses
- Parallel processing with Rayon
- Multiple derivation path support
- Bloom filter optimization for large-scale scanning

## Prerequisites

- Rust 1.70 or later
- OpenCL drivers (for GPU acceleration features)
- Bitcoin RPC node (optional, for balance checking features)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/5n10sndkts-eng/entropy-lab-rs.git
cd entropy-lab-rs
```

2. Build the project:
```bash
cargo build --release
```

Note: If you encounter OpenCL linking errors and don't need GPU features, you can comment out the `ocl` dependency in `Cargo.toml`.

## Usage

The tool provides multiple subcommands for different vulnerability scanners:

### Basic Usage

```bash
# Scan for Cake Wallet vulnerability
cargo run --release -- cake-wallet

# Scan for Trust Wallet vulnerability
cargo run --release -- trust-wallet

# Scan for Milk Sad vulnerability with specific time range
cargo run --release -- milk-sad --start-timestamp 1609459200 --end-timestamp 1640995200
```

### RPC-Based Scanning

For RPC-based scanning (balance checking), you must provide Bitcoin RPC credentials. You can provide them via environment variables or command-line arguments:

**Method 1: Environment Variables (Recommended for security)**
```bash
export RPC_URL="http://127.0.0.1:8332"
export RPC_USER="your_rpc_username"
export RPC_PASS="your_rpc_password"

cargo run --release -- cake-wallet-rpc
```

**Method 2: Command-line Arguments**
```bash
cargo run --release -- cake-wallet-rpc \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user your_username \
  --rpc-pass your_password
```

**Note**: Command-line arguments take precedence over environment variables. For security, environment variables are preferred to avoid exposing credentials in command history.

### Android SecureRandom Scanner

Scan for duplicate R values in Bitcoin blockchain (requires RPC):

```bash
export RPC_URL="http://127.0.0.1:8332"
export RPC_USER="your_rpc_username"
export RPC_PASS="your_rpc_password"

cargo run --release -- android-securerandom \
  --start-block 302000 \
  --end-block 330000
```

### CSV Verification

Verify a CSV of addresses against known funded addresses:

```bash
cargo run --release -- verify-csv \
  --input addresses.csv \
  --addresses funded_addresses.txt
```

## Configuration

### Environment Variables

The following environment variables are supported:

- `RPC_URL` - Bitcoin RPC endpoint (default: `http://127.0.0.1:8332`)
- `RPC_USER` - Bitcoin RPC username (required for RPC features)
- `RPC_PASS` - Bitcoin RPC password (required for RPC features)

### Security Best Practices

**Important**: Never commit RPC credentials to source code. Always use:
- Environment variables
- Configuration files (added to .gitignore)
- Secret management systems

## Development

### Running Tests

```bash
cargo test
```

### Code Quality

```bash
# Check for compilation errors
cargo check

# Run clippy for linting
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Project Structure

```
entropy-lab-rs/
├── src/
│   ├── main.rs              # CLI interface
│   ├── lib.rs               # Library exports
│   └── scans/               # Scanner implementations
│       ├── mod.rs
│       ├── cake_wallet.rs
│       ├── trust_wallet.rs
│       ├── milk_sad.rs
│       ├── android_securerandom.rs
│       └── ...
├── tests/                   # Integration tests
├── Cargo.toml              # Dependencies
└── README.md               # This file
```

## Known Limitations

1. **Android SecureRandom Scanner**: Implements private key recovery from duplicate R values (nonce reuse). Recovery requires access to previous transactions via RPC to compute the sighash. If previous transactions are not available or pruned, recovery will fail but duplicate R values will still be detected.

2. **GPU Features**: Requires OpenCL installation. If not available, the tool will fail at link time. Consider making OpenCL optional via feature flags for systems without GPU support.

3. **Performance**: Some scanners can be computationally intensive. Consider using the `--release` flag for production scanning.

## Security & Ethics

This tool is intended for:
- Security research and vulnerability assessment
- Educational purposes
- White-hat security testing with proper authorization
- Identifying and responsibly disclosing vulnerabilities

**Do not use this tool for:**
- Unauthorized access to cryptocurrency wallets
- Theft or unauthorized transfer of funds
- Any illegal activities

Always follow responsible disclosure practices and local laws.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `cargo fmt` and `cargo clippy`
5. Submit a pull request

## GPU Performance Optimizations

This project includes extensive OpenCL optimizations for maximum GPU performance:

### Key Optimizations
- **Device-Aware Work Group Sizing**: Dynamically adapts to GPU architecture (NVIDIA, AMD, Intel)
- **Pinned Memory**: Faster CPU-GPU data transfers using page-locked memory
- **Aggressive Compiler Optimizations**: Fast math and instruction fusion
- **Memory Coalescing**: Optimized access patterns for maximum bandwidth
- **Compute Unit Occupancy**: Intelligent batch sizing for full GPU utilization

### Performance Gains
Combined optimizations provide **2-4x performance improvement** over naive implementations.

See [OPENCL_OPTIMIZATIONS.md](OPENCL_OPTIMIZATIONS.md) for detailed technical documentation.

### Benchmarking

Run the GPU benchmark suite:
```bash
cargo run --release --bin benchmark_gpu
```

This measures throughput for:
- BIP39 address generation
- Cake Wallet hash searching
- Mobile sensor entropy cracking
- Profanity address searching

## Roadmap

- [x] Complete Android SecureRandom private key recovery implementation
- [ ] Add comprehensive integration tests
- [ ] Make OpenCL dependency optional via feature flags
- [ ] Add structured logging (replace println! with proper logging)
- [ ] Improve error handling (reduce unwrap() usage)
- [ ] Create detailed documentation for each scanner

## License

This project is provided for educational and research purposes. Please review the license file for terms and conditions.

## Acknowledgments

This research builds upon publicly disclosed vulnerabilities:
- Trust Wallet MT19937 weakness (2023)
- Cake Wallet entropy vulnerability (2024)
- Libbitcoin Milk Sad (CVE-2023-39910)
- Android SecureRandom Bitcoin vulnerability
- Profanity vanity address vulnerability

## Disclaimer

This tool is for research and educational purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before security testing.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing documentation in `/docs` (if available)
- Check audit reports in the repository

## References

- [Milk Sad Vulnerability Disclosure](https://milksad.info/)
- [Android SecureRandom Bitcoin Vulnerability](https://bitcoin.org/en/alert/2013-08-11-android)
- [Trust Wallet Security Advisories](https://github.com/trustwallet/wallet-core/security/advisories)
