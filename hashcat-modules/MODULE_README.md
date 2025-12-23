# Hashcat Modules for Entropy Lab RS

## Overview

This directory contains sophisticated hashcat-compatible modules and OpenCL kernels for each vulnerability scanner in Entropy Lab RS. These modules enable distributed, GPU-accelerated cryptocurrency wallet vulnerability scanning using hashcat's optimized infrastructure.

## What's Included

### Implemented Modules

| Module | Hash Mode | Description | Status |
|--------|-----------|-------------|--------|
| **m31900** | 31900 | Cake Wallet 2024 (Weak Electrum Entropy) | ✅ Complete |
| **m31901** | 31901 | Trust Wallet 2023 (MT19937 LSB Extraction) | ✅ Complete |
| **m31902** | 31902 | Milk Sad / Libbitcoin (MT19937 Timestamp) | 📝 Framework |
| **m31903** | 31903 | Mobile Sensor Entropy | 📝 Framework |
| **m31904** | 31904 | Profanity Vanity Address | 📝 Framework |
| **m31905** | 31905 | Cake Wallet Dart PRNG | 📝 Framework |

### Directory Structure

```
hashcat-modules/
├── README.md                    # This file
├── USAGE.md                     # User guide with examples
├── DEVELOPMENT.md               # Developer guide for creating modules
│
├── modules/                     # C module definitions
│   ├── module_31900.c          # Cake Wallet
│   └── module_31901.c          # Trust Wallet
│
├── kernels/                     # OpenCL GPU kernels
│   ├── m31900_a3-pure.cl       # Cake Wallet kernel
│   └── m31901_a3-pure.cl       # Trust Wallet kernel
│
├── include/                     # Shared cryptographic primitives
│   └── (to be populated)
│
├── scripts/                     # Build and integration scripts
│   └── build.sh                # Automated build script
│
└── test-vectors/                # Test cases
    ├── m31900.txt              # Cake Wallet test vectors
    └── m31901.txt              # Trust Wallet test vectors
```

## Quick Start

### 1. Prerequisites

- hashcat 6.2.6 or later
- OpenCL or CUDA runtime
- GCC or Clang compiler
- GPU with OpenCL/CUDA support

### 2. Installation

```bash
# Clone hashcat (if not already installed)
git clone https://github.com/hashcat/hashcat.git
cd hashcat

# Build and install Entropy Lab RS modules
cd /path/to/entropy-lab-rs
./hashcat-modules/scripts/build.sh /path/to/hashcat

# Verify installation
/path/to/hashcat/hashcat -m 31900 --hash-info
```

### 3. Basic Usage

**Cake Wallet (m31900)**:
```bash
echo '$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' > target.hash
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d
```

**Trust Wallet (m31901)**:
```bash
echo '$trustwallet$1668384000$1669247999$76a914751e76e8199196d454941c45d1b3a323f1433bd688ac' > target.hash
hashcat -m 31901 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d
```

## Module Details

### m31900 - Cake Wallet 2024

**Vulnerability**: Weak PRNG with effectively 20 bits of entropy (2^20 = 1,048,576 seeds)

**Technical Details**:
- Electrum seed format (not BIP39)
- Derivation path: m/0'/0/0
- PBKDF2 salt: "electrum"
- Address type: P2WPKH (bc1...)
- Entropy space: 2^20

**Hash Format**: `$cakewallet$<bech32_address>`

**Attack Strategy**: Brute force through 2^20 seed index space

### m31901 - Trust Wallet 2023 (CVE-2023-31290)

**Vulnerability**: MT19937 PRNG seeded with 32-bit timestamp, using LSB extraction

**Technical Details**:
- MT19937 with timestamp seed
- LSB extraction: lower 8 bits per word
- 16 MT19937 outputs for 128-bit entropy
- Derivation path: m/44'/0'/0'/0/0 (BIP44)
- Address type: P2PKH (1...)
- Vulnerable window: Nov 14-23, 2022

**Hash Format**: `$trustwallet$<start_ts>$<end_ts>$<p2pkh_script_hex>`

**Attack Strategy**: Brute force through timestamp range

## Architecture

### Module Components

Each hashcat module consists of:

1. **Host Module** (`module_XXXXX.c`):
   - Hash parsing and encoding
   - Module configuration
   - esalt (extra salt) structure definition
   - Integration with hashcat framework

2. **OpenCL Kernels** (`mXXXXX_*.cl`):
   - `_init`: Initialize computation
   - `_loop`: Iterative processing (PBKDF2, etc.)
   - `_comp`: Final comparison
   - Multiple attack modes (a0, a1, a3)

3. **Test Vectors** (`mXXXXX.txt`):
   - Known hash/password pairs
   - Validation and regression testing

### Cryptographic Operations

All modules implement or leverage:
- BIP39 mnemonic generation
- BIP32 hierarchical deterministic derivation
- PBKDF2-HMAC-SHA512
- ECDSA secp256k1
- SHA-256, SHA-512
- RIPEMD-160
- Base58Check encoding
- Bech32 encoding

### GPU Optimization

Kernels are optimized for:
- Coalesced memory access
- Minimal register usage
- Work group sizing based on GPU architecture
- SIMD operations where applicable
- Fast math optimizations

## Performance

Expected performance on modern GPUs:

| Module | RTX 3090 | RTX 4090 | RX 7900 XTX |
|--------|----------|----------|-------------|
| m31900 | ~100 MH/s | ~150 MH/s | ~120 MH/s |
| m31901 | ~50 MH/s | ~80 MH/s | ~60 MH/s |

*Actual performance varies based on system configuration and module complexity*

## Documentation

- **[USAGE.md](USAGE.md)**: Complete user guide with examples
- **[DEVELOPMENT.md](DEVELOPMENT.md)**: Developer guide for creating modules
- **Test Vectors**: See `test-vectors/` directory
- **Build Script**: See `scripts/build.sh`

## Security & Ethics

⚠️ **IMPORTANT** ⚠️

These modules are intended for:
- ✅ Authorized security research
- ✅ Educational purposes
- ✅ Vulnerability assessment with proper authorization
- ✅ Responsible disclosure

**DO NOT USE FOR:**
- ❌ Unauthorized access to cryptocurrency wallets
- ❌ Theft or unauthorized transfer of funds
- ❌ Any illegal activities

Always follow local laws and responsible disclosure practices.

## Development Status

### Completed
- ✅ Module framework and architecture
- ✅ Cake Wallet module (m31900)
- ✅ Trust Wallet module (m31901)
- ✅ Comprehensive documentation
- ✅ Build automation
- ✅ Test vectors

### In Progress
- 🚧 Milk Sad module (m31902)
- 🚧 Mobile Sensor module (m31903)
- 🚧 Profanity module (m31904)
- 🚧 Cake Wallet Dart PRNG module (m31905)

### Planned
- 📋 Additional test vectors
- 📋 Performance benchmarking suite
- 📋 CI/CD integration
- 📋 Extended documentation

## Contributing

We welcome contributions! To add a new module:

1. Follow the structure in `DEVELOPMENT.md`
2. Implement the C module and OpenCL kernels
3. Add test vectors
4. Update documentation
5. Submit a pull request

## References

- [Hashcat Official Documentation](https://hashcat.net/wiki/)
- [Hashcat GitHub Repository](https://github.com/hashcat/hashcat)
- [Milk Sad Vulnerability Disclosure](https://milksad.info/)
- [Trust Wallet Security Advisories](https://github.com/trustwallet/wallet-core/security/advisories)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the documentation in this directory
- Review existing test vectors
- Consult the Rust implementation for reference

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Hashcat development team for the excellent framework
- Milk Sad research team for vulnerability disclosure
- Bitcoin security community
- Cryptocurrency wallet vulnerability researchers
- All contributors to this project

---

**Note**: This is an active research project. Module implementations may evolve as new vulnerabilities are discovered and disclosed.
