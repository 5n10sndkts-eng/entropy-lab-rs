# Milksad.info Gap Analysis Report

**Date:** 2025-12-06  
**Source:** https://milksad.info/disclosure.html and related research updates  
**Comparison:** entropy-lab-rs implementation vs. milksad.info documentation

## Executive Summary

This document identifies gaps between our entropy-lab-rs implementation and the actual vulnerabilities documented at milksad.info. The analysis covers Trust Wallet, Cake Wallet, Libbitcoin (Milk Sad), and related vulnerabilities.

---

## 🔴 CRITICAL GAPS (Scanner Functionality Broken/Missing)

### 1. ✅ Trust Wallet: Wrong Bit Extraction - FIXED
**Status:** FIXED in commit e38d7da

**Issue:** Trust Wallet uses LSB (Least Significant Byte) extraction, not MSB  
**Milksad.info documentation:**
```c
// Trust Wallet code (from Ledger Donjon writeup)
return rng() & 0x000000ff;  // Takes LEAST significant 8 bits
```

**Our previous code:** Used MSB extraction like Milk Sad (WRONG)  
**Impact:** Scanner would NEVER find ANY Trust Wallet vulnerable wallets  
**Fix Applied:** Changed `cl/trust_wallet_crack.cl` to use LSB-first byte order

---

### 2. ❌ Trust Wallet: Multiple Vulnerability Variants Not Implemented

**Milksad.info documentation:** Two different Trust Wallet vulnerabilities exist:
- **CVE-2023-31290:** Browser extension using `std::random_device{}()` seeded with MT19937 (32-bit timestamp) - WebAssembly platform
- **CVE-2024-23660:** iOS app using `minstd_rand0` (LCG PRNG) seeded with device timestamp

**Our current implementation:**
- Only covers CVE-2023-31290 (MT19937 with timestamp)
- Does NOT cover CVE-2024-23660 (minstd_rand0 LCG)

**Gap Details:**
- **minstd_rand0 parameters:** 
  - Modulus: m = 2^31 - 1 (2147483647)
  - Multiplier: a = 16807
  - This is a Linear Congruential Generator: `X(n+1) = (a * X(n)) mod m`
- **Attack vector:** Different PRNG = completely different keyspace
- **Timestamp range:** July 2023 exploits documented

**Impact:** Missing entire class of vulnerable iOS Trust Wallet users

**Required Implementation:**
```rust
// Pseudocode for minstd_rand0
fn minstd_rand0(seed: u32) -> impl Iterator<Item = u32> {
    let mut state = seed;
    std::iter::from_fn(move || {
        state = (state as u64 * 16807 % 2147483647) as u32;
        Some(state)
    })
}
```

---

### 3. ❌ Cake Wallet: Electrum Seed Version Prefix Validation Missing

**Milksad.info documentation:**
- Cake Wallet uses Electrum seed format (not BIP39)
- Only seeds where `HMAC-SHA512("Seed version", mnemonic).startsWith("100")` are valid
- This is a **1 in 4096** (2^12) probability filter
- Must iterate and regenerate mnemonics until prefix matches

**Our current implementation:**
```rust
// src/scans/cake_wallet.rs and cake_wallet_dart_prng.rs
// May generate mnemonic without checking Electrum prefix validity
```

**Gap Details:**
- Electrum v2 Segwit seeds require first 3 bits of HMAC-SHA512 to be "100" (binary)
- Generation process must:
  1. Generate candidate mnemonic from entropy
  2. Compute `HMAC-SHA512(key="Seed version", message=mnemonic_ascii)`
  3. Check if first 3 bits == "100"
  4. If not, increment entropy and try again
  5. On average, 4096 attempts needed per valid seed

**Impact:** 
- May generate invalid seeds that Cake Wallet never actually used
- Search space is 4096x larger than documented
- False positives or missing real vulnerable wallets

**Required Implementation:**
```rust
fn validate_electrum_segwit_prefix(mnemonic: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    
    let mut mac = HmacSha512::new_from_slice(b"Seed version").unwrap();
    mac.update(mnemonic.as_bytes());
    let result = mac.finalize().into_bytes();
    
    // Check first 3 bits == "100" (binary)
    let first_byte = result[0];
    let first_three_bits = (first_byte >> 5) & 0b111;
    first_three_bits == 0b100  // 4 in decimal
}
```

---

### 4. ❌ Cake Wallet: Dart PRNG Algorithm Details

**Milksad.info documentation:**
- Dart `Random()` (not `Random.secure()`) uses specific LCG algorithm
- Falls back to microsecond timestamp OR seed=0 on some platforms
- Seed source: `OS::GetCurrentTimeMicros()` - 64-bit on some platforms
- Timestamp range: 2020-2021 (specific microsecond precision)

**Our current implementation:**
```rust
// src/scans/cake_wallet_dart_prng.rs
// Uses 32-bit entropy index as seed
```

**Gap Details:**
- Dart Random() internal state is 64-bit
- Microsecond timestamps provide different granularity than second timestamps
- May miss real Cake Wallet seeds if timestamp handling differs

**Impact:** Keyspace mismatch = missing vulnerable wallets

---

## 🟠 HIGH PRIORITY GAPS

### 5. ❌ Multi-Path Derivation Not Implemented

**Milksad.info requirement:** Check ALL standard paths for each seed

| BIP  | Path              | Address Type | Prefix | Extended Key |
|------|-------------------|--------------|--------|--------------|
| BIP44| m/44'/0'/0'/0/i   | P2PKH        | 1xxx   | xpub/xprv    |
| BIP49| m/49'/0'/0'/0/i   | P2SH-WPKH    | 3xxx   | ypub/yprv    |
| BIP84| m/84'/0'/0'/0/i   | P2WPKH       | bc1q   | zpub/zprv    |

**Our current implementation:**
- Trust Wallet: Only checks BIP44 path (m/44'/0'/0'/0/0)
- Milk Sad: Only checks single path per scan

**Gap:** Users may have funds in different address types not being scanned

**Required:** Implement multi-path derivation in GPU kernels or parallel CPU scans

---

### 6. ❌ Cake Wallet: Address Type Incorrect

**Milksad.info Update #10:**
- Address format: **Segwit P2WPKH bc1q addresses ONLY**
- Path format: `m/0'/{c}/{a}` where c=change(0/1), a=subaccount
- NOT standard BIP44/49/84 paths

**Our code:** May output P2PKH addresses

**Gap:** Wrong address type = no matches even with correct entropy

---

### 7. ❌ Cake Wallet: Change Addresses Not Scanned

**Milksad.info:**
- Must scan both receive AND change addresses:
  - `m/0'/0/a` - Receive addresses
  - `m/0'/1/a` - Change addresses
- Found 12,999 unique sub-accounts (high address index values)

**Our implementation:** Only scans receive addresses (c=0)

**Impact:** Missing ~50% of potential vulnerable wallets with funds in change addresses

---

### 8. ❌ Uncompressed Public Key Support Missing

**Milksad.info Update #2:**
- Some wallets use 65-byte uncompressed public keys
- Example: `bx ec-to-public --uncompressed`
- Both compressed (33-byte) and uncompressed (65-byte) must be checked

**Our implementation:** Only generates compressed 33-byte pubkeys

**Impact:** Missing wallets that used uncompressed keys

---

### 9. ❌ Address Index Range Limited

**Milksad.info:**
- Must scan first 20 addresses minimum (BIP44 gap limit)
- Cake Wallet: 12,999 unique sub-accounts found in practice
- Some users generated many addresses before receiving funds

**Our implementation:** Only checks index 0 (first address)

**Gap:** Missing ~95%+ of addresses per seed

**Required:** Loop through address indices 0-19 (minimum), ideally 0-100 or higher for Cake Wallet

---

### 10. ❌ ec-new Key Range Not Implemented

**Milksad.info:**
- Some users generated keys directly: PRNG → secp256k1 private key (no BIP39)
- Command: `bx ec-new` generates raw private key
- No mnemonic, no derivation path

**Our implementation:** Only covers mnemonic-based derivation

**Impact:** Missing direct-key-generation vulnerability class

---

### 11. ❌ bip3x Library (PCG PRNG) Not Covered

**Milksad.info Update #4:**
- Another vulnerable JavaScript library
- Uses PCG-XSH-RR PRNG (64-bit state)
- Different algorithm than MT19937
- Found in some wallet implementations

**Our implementation:** Not implemented

**Impact:** Missing entire vulnerability class

---

### 12. ❌ minstd_rand LCG PRNG Not Implemented

**Milksad.info Update #12:**
- Found wallets from `minstd_rand0` and `minstd_rand` variants
- Parameters:
  - `minstd_rand0`: m=2^31-1, a=16807
  - `minstd_rand`: m=2^31-1, a=48271
- Used by iOS Trust Wallet (CVE-2024-23660)

**Status:** Critical Gap #2 (see above)

---

## 🟡 MEDIUM PRIORITY GAPS

### 13. ❌ Seed Length Variants Missing

**Milksad.info:** bx supports multiple entropy sizes:
- 12 words = 128 bit
- 18 words = 192 bit (DEFAULT in bx)
- 24 words = 256 bit

**Our implementation:** Only 128-bit (12 words)

**Gap:** Missing 18-word and 24-word vulnerable wallets

---

### 14. ❌ Taproot (P2TR) Not Supported

**Milksad.info Update #12:**
- Taproot addresses now being searched
- BIP86 path: `m/86'/0'/0'/0/i`
- Address prefix: bc1p (vs bc1q for P2WPKH)

**Our implementation:** No BIP86/Taproot support

---

### 15. ❌ Bloom Filter Not Implemented

**Milksad.info Update #3:**
- Essential for efficient scanning at scale
- Dataset from loyce.club (all known funded addresses)
- Low false-positive filter
- Avoids expensive RPC overhead

**Our implementation:** Direct RPC or CSV checking

**Impact:** Slow scanning, high RPC load, not scalable

---

### 16. ⚠️ Cake Wallet Hash Count Discrepancy

**Milksad.info Update #10:** 8,757 unique weak wallets  
**Our file (`cakewallet_vulnerable_hashes.txt`):** 8,717 hashes  
**Difference:** 40 wallets missing

**Required:** Update hash list from latest milksad.info data

---

### 17. ⚠️ Wrong Timestamp Range for Trust Wallet

**Milksad.info:**
- Published vulnerability timeframe: Nov 14-23, 2022
- BUT: Attacks documented as early as December 2022
- Some researchers suggest checking back to October 2022

**Our implementation:**
```rust
let start_ts = 1668384000u32; // Nov 14 2022 00:00:00 UTC
let end_ts = 1669247999u32;   // Nov 23 2022 23:59:59 UTC
```

**Concern:** Range may be too narrow, missing earlier vulnerable wallets

---

### 18. ❌ Vanity Address Range Not Covered

**Milksad.info Update #12:**
- Found vanity addresses from minstd_rand: `1Love...`, `1Shao...`
- These indicate intentional generation with specific prefixes
- Different search pattern than standard scanning

**Our implementation:** No vanity-specific scanning

---

## 🟢 LOWER PRIORITY GAPS

### 19. ⚠️ Profanity Vanity Generator Incomplete

**Status:** 
- OpenCL kernel exists (`cl/batch_profanity.cl`)
- Rust scanner is stub/incomplete

**Gap:** Not production-ready

---

### 20. ⚠️ Android SecureRandom Context

**Our implementation:** Block range scanning  
**Potential improvement:** If known duplicate R values exist, use those for targeted scanning

---

## Summary Table

| Category | Issue | Status | Impact |
|----------|-------|--------|--------|
| Critical | Trust Wallet LSB Extraction | ✅ FIXED | High |
| Critical | Trust Wallet iOS minstd_rand0 | ❌ Missing | High |
| Critical | Cake Wallet Electrum Prefix | ❌ Missing | High |
| Critical | Cake Wallet Dart PRNG Details | ❌ Missing | Medium |
| High | Multi-Path Derivation | ❌ Missing | High |
| High | Cake Wallet P2WPKH Only | ❌ Wrong | High |
| High | Change Address Scanning | ❌ Missing | Medium |
| High | Uncompressed Keys | ❌ Missing | Medium |
| High | Address Index Range | ❌ Limited | High |
| High | ec-new Direct Keys | ❌ Missing | Medium |
| High | bip3x PCG PRNG | ❌ Missing | Low |
| High | minstd_rand LCG | ❌ Missing | High |
| Medium | 18/24-word Seeds | ❌ Missing | Medium |
| Medium | Taproot/BIP86 | ❌ Missing | Low |
| Medium | Bloom Filter | ❌ Missing | High (scale) |
| Medium | Hash Count | ⚠️ 40 Missing | Low |
| Medium | Timestamp Range | ⚠️ Narrow | Medium |
| Medium | Vanity Addresses | ❌ Missing | Low |
| Low | Profanity Scanner | ⚠️ Incomplete | Low |
| Low | Android R-value | ⚠️ Could improve | Low |

---

## Recommended Priority Order

1. **Critical #2:** Implement Trust Wallet iOS minstd_rand0 LCG scanner
2. **Critical #3:** Add Electrum seed version prefix validation for Cake Wallet
3. **High #5:** Implement multi-path derivation (BIP44/49/84)
4. **High #9:** Extend address index scanning (0-19 minimum, 0-100+ for Cake)
5. **High #6-7:** Fix Cake Wallet address type and add change address scanning
6. **High #12:** Implement general minstd_rand LCG scanner
7. **Medium #15:** Add bloom filter support for scalability
8. **Medium #13:** Support 18 and 24-word seeds
9. **Critical #4:** Refine Cake Wallet Dart PRNG timestamp handling

---

## References

- Main disclosure: https://milksad.info/disclosure.html
- Trust Wallet CVE-2023-31290: https://nvd.nist.gov/vuln/detail/CVE-2023-31290
- Trust Wallet CVE-2024-23660: https://nvd.nist.gov/vuln/detail/CVE-2024-23660
- Cake Wallet analysis: https://milksad.info/posts/research-update-9/
- Research updates: https://milksad.info/posts/
- Data repository: https://git.distrust.co/milksad/data
- Bloom filter dataset: http://alladdresses.loyce.club/
