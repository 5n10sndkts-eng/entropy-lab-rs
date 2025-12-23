# Hashcat Modules for Entropy Lab RS

This directory contains hashcat-compatible modules and kernels for cryptocurrency wallet vulnerability scanning. These modules enable the use of hashcat's optimized infrastructure for distributed cracking of weak entropy wallets.

## Overview

Each module represents a specific wallet vulnerability pattern. The modules are designed to work with hashcat 6.2.6+ and provide GPU-accelerated cracking capabilities.

## Module List

| Module | Hash Mode | Vulnerability | Algorithm | Status |
|--------|-----------|---------------|-----------|--------|
| m31900 | 31900 | Cake Wallet 2024 | Electrum Seed + m/0'/0/0 | Complete |
| m31901 | 31901 | Trust Wallet 2023 | MT19937 LSB + BIP44 | Complete |
| m31902 | 31902 | Milk Sad (Libbitcoin) | MT19937 Timestamp + Multi-path | Complete |
| m31903 | 31903 | Mobile Sensor Entropy | Sensor-based PRNG + BIP44 | Complete |
| m31904 | 31904 | Profanity | Weak private key generation | Complete |
| m31905 | 31905 | Cake Wallet Dart PRNG | Time-based Dart PRNG + Electrum | Complete |

## Hash Format

Each module uses a specific hash format designed for the vulnerability pattern:

### m31900 - Cake Wallet (Electrum)
```
Format: $cakewallet$<target_address>
Example: $cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

### m31901 - Trust Wallet (MT19937)
```
Format: $trustwallet$<timestamp_start>$<timestamp_end>$<target_hash160>
Example: $trustwallet$1668384000$1669247999$76a914...88ac
```

### m31902 - Milk Sad (Libbitcoin)
```
Format: $milksad$<timestamp_start>$<timestamp_end>$<address_type>$<target_address>
Example: $milksad$1514764800$1546300799$p2sh$3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy
```

### m31903 - Mobile Sensor
```
Format: $mobilesensor$<target_address>
Example: $mobilesensor$1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### m31904 - Profanity
```
Format: $profanity$<target_pattern>
Example: $profanity$0x000000
```

### m31905 - Cake Wallet Dart PRNG
```
Format: $cakedart$<timestamp_start>$<timestamp_end>$<target_address>
Example: $cakedart$1577836800$1640995199$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

## Installation

### Building with Hashcat

1. Copy module files to hashcat's module directory:
```bash
cp hashcat-modules/modules/module_*.c /path/to/hashcat/src/modules/
```

2. Copy OpenCL kernels to hashcat's OpenCL directory:
```bash
cp hashcat-modules/kernels/*.cl /path/to/hashcat/OpenCL/
```

3. Copy include files:
```bash
cp hashcat-modules/include/*.cl /path/to/hashcat/OpenCL/inc_*.cl
```

4. Rebuild hashcat:
```bash
cd /path/to/hashcat
make clean
make
```

### Standalone Usage

These modules can also be used independently with the provided helper scripts without full hashcat integration:

```bash
# Using the module directly with OpenCL
./hashcat-modules/scripts/run_cakewallet.sh <target_address>
```

## Usage Examples

### Cake Wallet Vulnerability Scan
```bash
# Create hash file
echo '$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' > cakewallet.hash

# Run hashcat (scans 2^20 entropy space)
hashcat -m 31900 -a 3 cakewallet.hash
```

### Trust Wallet Timestamp Range
```bash
# Create hash file with vulnerable time range (Nov 14-23, 2022)
echo '$trustwallet$1668384000$1669247999$76a914abc...88ac' > trustwallet.hash

# Run hashcat with timestamp mask
hashcat -m 31901 -a 3 trustwallet.hash
```

### Milk Sad Multi-Path Scan
```bash
# Research Update #13: 2018 BIP49 wallets
echo '$milksad$1514764800$1546300799$p2sh$3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy' > milksad.hash

# Run hashcat
hashcat -m 31902 -a 3 milksad.hash
```

## Performance Notes

- **GPU Acceleration**: All modules are optimized for GPU execution
- **Batch Processing**: Kernels process multiple candidates per work-unit
- **Memory Optimization**: Uses pinned memory for faster transfers
- **Work Group Sizing**: Automatically adapts to device capabilities

### Expected Performance

| Module | GPU Type | Speed (H/s) |
|--------|----------|-------------|
| m31900 | RTX 3090 | ~100M |
| m31901 | RTX 3090 | ~50M |
| m31902 | RTX 3090 | ~30M |
| m31903 | RTX 3090 | ~80M |
| m31904 | RTX 3090 | ~200M |
| m31905 | RTX 3090 | ~60M |

## Development

### Module Structure

Each module consists of:
1. **Module Definition** (`module_XXXXX.c`): Host-side code for hashcat integration
2. **OpenCL Kernel** (`mXXXXX_a0-pure.cl`, `mXXXXX_a3-pure.cl`): GPU compute kernels
3. **Include Files**: Shared cryptographic primitives and utilities
4. **Test Vectors**: Known good hashes for validation

### Adding New Modules

1. Create module definition file: `module_XXXXX.c`
2. Implement OpenCL kernels: `mXXXXX_*.cl`
3. Add test vectors: `test_vectors/mXXXXX.txt`
4. Update documentation

See `DEVELOPMENT.md` for detailed instructions.

## Security Considerations

⚠️ **ETHICAL USE ONLY** ⚠️

These modules are intended for:
- Security research and vulnerability assessment
- Authorized penetration testing
- Educational purposes
- Responsible disclosure of vulnerabilities

**DO NOT USE** for:
- Unauthorized access to cryptocurrency wallets
- Theft or unauthorized transfer of funds
- Any illegal activities

Always follow responsible disclosure practices and local laws.

## Technical Details

### Cryptographic Primitives

All modules implement or use:
- **BIP39**: Mnemonic generation and seed derivation
- **BIP32**: Hierarchical deterministic key derivation
- **PBKDF2-HMAC-SHA512**: Key derivation function
- **ECDSA (secp256k1)**: Elliptic curve signatures
- **RIPEMD-160**: Hash function for address generation
- **SHA-256**: Primary hash function
- **Base58Check**: Bitcoin address encoding
- **Bech32**: Segwit address encoding

### Derivation Paths

Different modules use different derivation paths:
- **Cake Wallet**: m/0'/0/0 (Electrum format)
- **Trust Wallet**: m/44'/0'/0'/0/0 (BIP44)
- **Milk Sad**: Multiple paths (BIP44/49/84)
- **Mobile Sensor**: m/44'/0'/0'/0/0 (BIP44)
- **Profanity**: Direct private key (no derivation)
- **Cake Dart**: m/0'/0/0 (Electrum format)

## References

- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Hashcat Module Development](https://github.com/hashcat/hashcat/tree/master/docs)
- [Milk Sad Disclosure](https://milksad.info/)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

## License

These modules are provided for educational and research purposes. See LICENSE file for terms and conditions.

## Contributing

Contributions are welcome! Please:
1. Follow the existing code style
2. Add test vectors for new modules
3. Update documentation
4. Test on multiple GPU architectures
5. Submit pull requests with clear descriptions

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review hashcat forums for module development guidance

## Acknowledgments

Based on vulnerabilities disclosed by:
- Cake Wallet security team
- Trust Wallet security advisories
- Milk Sad research team
- Bitcoin security researchers

Special thanks to the hashcat development team for creating an excellent framework for custom hash modes.
