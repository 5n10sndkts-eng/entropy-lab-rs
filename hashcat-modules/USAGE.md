# Hashcat Integration Guide

Complete guide for using Entropy Lab RS modules with hashcat for distributed cryptocurrency wallet vulnerability scanning.

## Quick Start

### 1. Clone and Build

```bash
# Clone this repository
git clone https://github.com/5n10sndkts-eng/entropy-lab-rs.git
cd entropy-lab-rs

# Clone hashcat
cd /tmp
git clone https://github.com/hashcat/hashcat.git
cd hashcat

# Build and install modules
cd /path/to/entropy-lab-rs
./hashcat-modules/scripts/build.sh /tmp/hashcat
```

### 2. Test Installation

```bash
# Verify modules are installed
/tmp/hashcat/hashcat -m 31900 --hash-info
/tmp/hashcat/hashcat -m 31901 --hash-info

# Run benchmarks
/tmp/hashcat/hashcat -m 31900 -b
/tmp/hashcat/hashcat -m 31901 -b
```

### 3. Run Your First Scan

```bash
# Cake Wallet: Scan 2^20 entropy space
echo '$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' > target.hash
/tmp/hashcat/hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d

# Trust Wallet: Scan timestamp range
echo '$trustwallet$1668384000$1669247999$76a914751e76e8199196d454941c45d1b3a323f1433bd688ac' > target.hash
/tmp/hashcat/hashcat -m 31901 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d
```

## Module Reference

### m31900 - Cake Wallet 2024

**Vulnerability**: Weak PRNG with 20-bit entropy
**Hash Format**: `$cakewallet$<bech32_address>`
**Password Format**: Seed index (0-1048575)

**Example**:
```bash
echo '$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' > target.hash
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d
```

**Technical Details**:
- Entropy: 128-bit from 32-bit seed index
- Seed Format: Electrum (not BIP39)
- Derivation: m/0'/0/0
- Address: P2WPKH (bc1...)
- PBKDF2: Salt "electrum"

### m31901 - Trust Wallet 2023 (CVE-2023-31290)

**Vulnerability**: MT19937 LSB extraction
**Hash Format**: `$trustwallet$<start_ts>$<end_ts>$<p2pkh_script>`
**Password Format**: Unix timestamp

**Example**:
```bash
echo '$trustwallet$1668384000$1669247999$76a914751e76e8199196d454941c45d1b3a323f1433bd688ac' > target.hash
hashcat -m 31901 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d
```

**Technical Details**:
- PRNG: MT19937 with timestamp seed
- Extraction: LSB (Least Significant Byte)
- Entropy: 128-bit (16 MT19937 words)
- Derivation: m/44'/0'/0'/0/0 (BIP44)
- Address: P2PKH (1...)
- Vulnerable Window: Nov 14-23, 2022

### m31902 - Milk Sad / Libbitcoin (CVE-2023-39910)

**Vulnerability**: MT19937 MSB extraction with timestamp seed
**Hash Format**: `$milksad$<start_ts>$<end_ts>$<addr_type>$<address>`
**Password Format**: Unix timestamp

**Status**: Module definition available, kernel in progress

**Technical Details**:
- PRNG: MT19937 with timestamp seed
- Extraction: MSB (Most Significant Byte)  
- Entropy: 128/192/256-bit support
- Derivation: Multi-path (BIP44/49/84)
- Addresses: P2PKH, P2SH, P2WPKH
- Time Range: 2011-2023

### m31903 - Mobile Sensor Entropy

**Vulnerability**: Weak sensor-based PRNG
**Hash Format**: `$mobilesensor$<address>`
**Password Format**: Sensor data seed

**Status**: Module definition available, kernel in progress

### m31904 - Profanity

**Vulnerability**: Weak private key generation
**Hash Format**: `$profanity$<pattern>`
**Password Format**: Private key seed

**Status**: Module definition available, kernel in progress

### m31905 - Cake Wallet Dart PRNG

**Vulnerability**: Time-based Dart PRNG
**Hash Format**: `$cakedart$<start_ts>$<end_ts>$<address>`
**Password Format**: Timestamp

**Status**: Module definition available, kernel in progress

## Attack Modes

### Mode 0: Straight (Dictionary)

Use a wordlist:
```bash
hashcat -m 31900 -a 0 target.hash wordlist.txt
```

### Mode 3: Brute Force (Mask)

Use character masks:
```bash
# Numeric only (recommended for timestamp/index attacks)
hashcat -m 31901 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d

# Alphanumeric
hashcat -m 31900 -a 3 target.hash ?a?a?a?a?a?a

# Custom charset
hashcat -m 31900 -a 3 target.hash -1 0123456789 ?1?1?1?1?1?1?1
```

Mask placeholders:
- `?d` = digits (0-9)
- `?l` = lowercase (a-z)
- `?u` = uppercase (A-Z)
- `?a` = all printable
- `?b` = all bytes (0x00-0xff)

### Mode 6: Hybrid Wordlist + Mask

Combine wordlist with mask:
```bash
hashcat -m 31900 -a 6 target.hash wordlist.txt ?d?d?d
```

### Mode 7: Hybrid Mask + Wordlist

```bash
hashcat -m 31900 -a 7 target.hash ?d?d?d wordlist.txt
```

## Performance Optimization

### GPU Selection

```bash
# List devices
hashcat -I

# Use specific GPU
hashcat -m 31900 -d 1 target.hash wordlist.txt

# Use multiple GPUs
hashcat -m 31900 -d 1,2,3 target.hash wordlist.txt
```

### Workload Tuning

```bash
# Low (desktop use)
hashcat -m 31900 -w 1 target.hash wordlist.txt

# Medium (balanced)
hashcat -m 31900 -w 2 target.hash wordlist.txt

# High (dedicated)
hashcat -m 31900 -w 3 target.hash wordlist.txt

# Nightmare (maximum)
hashcat -m 31900 -w 4 target.hash wordlist.txt
```

### Performance Tips

1. **Use appropriate mask length**:
```bash
# Good: Exact length
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d

# Bad: Too long (wasteful)
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d
```

2. **Optimize batch size**:
```bash
hashcat -m 31900 -n 512 target.hash wordlist.txt
```

3. **Use session management**:
```bash
# Start session
hashcat -m 31900 --session myscan target.hash wordlist.txt

# Restore session
hashcat --session myscan --restore
```

4. **Monitor progress**:
```bash
# Enable status timer
hashcat -m 31900 --status --status-timer=10 target.hash wordlist.txt
```

## Distributed Cracking

### Using Multiple Machines

Machine 1:
```bash
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d -s 0 -l 5000000
```

Machine 2:
```bash
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d -s 5000000 -l 5000000
```

### Cloud/Cluster Setup

Use hashcat server mode:
```bash
# Server
hashcat --server --port 9999

# Client
hashcat --client-mode --server-host 192.168.1.100 --server-port 9999
```

## Troubleshooting

### Module Not Found

```bash
# Verify installation
hashcat -m 31900 --hash-info
```

If not found, rebuild:
```bash
cd entropy-lab-rs
./hashcat-modules/scripts/build.sh /path/to/hashcat
```

### Performance Issues

1. Check GPU temperature and throttling
2. Update GPU drivers
3. Reduce workload (`-w 2`)
4. Check for other GPU-intensive processes

### Kernel Compilation Errors

```bash
# Check OpenCL support
clinfo

# Reinstall OpenCL drivers
# NVIDIA: Install CUDA toolkit
# AMD: Install ROCm or OpenCL runtime
```

### Hash Parse Errors

Verify hash format:
```bash
# Cake Wallet
$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Trust Wallet
$trustwallet$1668384000$1669247999$76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
```

## Security Considerations

⚠️ **IMPORTANT** ⚠️

These modules are for:
- ✅ Authorized security research
- ✅ Educational purposes
- ✅ Vulnerability assessment with permission
- ✅ Responsible disclosure

**DO NOT USE FOR:**
- ❌ Unauthorized wallet access
- ❌ Theft of cryptocurrency
- ❌ Any illegal activities

Always follow:
- Local laws and regulations
- Responsible disclosure practices
- Ethical hacking guidelines

## Support and Resources

### Documentation
- [Module Development Guide](DEVELOPMENT.md)
- [Test Vectors](test-vectors/)
- [Hashcat Wiki](https://hashcat.net/wiki/)

### Community
- [Hashcat Forums](https://hashcat.net/forum/)
- [GitHub Issues](https://github.com/5n10sndkts-eng/entropy-lab-rs/issues)

### References
- [Milk Sad Disclosure](https://milksad.info/)
- [Trust Wallet Advisory](https://github.com/trustwallet/wallet-core/security/advisories)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Hashcat development team
- Milk Sad research team
- Bitcoin security community
- Cryptocurrency wallet vulnerability researchers
