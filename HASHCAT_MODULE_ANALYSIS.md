# Hashcat Module and Address Format Analysis

## Executive Summary

This document analyzes the entropy-lab-rs vulnerability scanners to determine:
1. **Address format coverage** - Which Bitcoin address formats each scanner supports
2. **Hashcat module requirements** - What custom hashcat modules would be needed
3. **OpenCL kernel accuracy** - Whether our GPU kernels use correct address formats

## Scanner-by-Scanner Analysis

### 1. Cake Wallet Scanner

**Scanner File:** `src/scans/cake_wallet.rs`  
**OpenCL Kernel:** `cl/cake_wallet_crack.cl`

**Address Formats:**
- ✅ **P2WPKH (Native SegWit)** - bc1q... addresses (Electrum default)
- ❌ **P2PKH (Legacy)** - Not supported
- ❌ **P2SH-P2WPKH (Nested SegWit)** - Not supported

**Derivation Path:** `m/0'/0/0` (Electrum-style, not standard BIP44)

**Kernel Implementation:**
```c
// cl/cake_wallet_crack.cl:172
// Generate Hash160 for P2WPKH (bc1q address)
identifier_for_public_key(&address_pub, hash160);
```

**Assessment:** ✅ **CORRECT** - Cake Wallet uses Electrum seeds which default to P2WPKH addresses. The kernel correctly generates P2WPKH addresses.

**Hashcat Module Needed:**
- **Format:** Electrum seed → BIP32 → P2WPKH address at m/0'/0/0
- **Input:** 132-bit entropy (12-word Electrum mnemonic with version prefix validation)
- **Output:** bc1q addresses
- **Mode Suggestion:** Custom module for Electrum P2WPKH at m/0'/0/0

---

### 2. Cake Wallet Dart PRNG Scanner

**Scanner File:** `src/scans/cake_wallet_dart_prng.rs`  
**OpenCL Kernel:** Uses `batch_address_electrum.cl`

**Address Formats:**
- ✅ **P2WPKH (Native SegWit)** - bc1q... addresses
- ❌ **P2PKH (Legacy)** - Not supported by default

**Derivation Path:** `m/0'/0/0` (Electrum-style)

**Assessment:** ✅ **CORRECT** - Matches Cake Wallet Electrum implementation

**Hashcat Module Needed:**
- Similar to Cake Wallet scanner above
- **Additional:** Time-based PRNG state recovery (Dart Random)

---

### 3. Trust Wallet Scanner

**Scanner File:** `src/scans/trust_wallet.rs`  
**OpenCL Kernel:** `cl/trust_wallet_crack.cl`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ❌ **P2WPKH (Native SegWit)** - Not supported
- ❌ **P2SH-P2WPKH (Nested SegWit)** - Not supported

**Derivation Path:** `m/44'/0'/0'/0/0` (BIP44 standard)

**Kernel Implementation:**
```c
// cl/trust_wallet_crack.cl:62
identifier_for_public_key(&address_pub, hash160);
// This generates Hash160 for P2PKH
```

**Assessment:** ⚠️ **INCOMPLETE** - Trust Wallet supports multiple address types. The scanner only checks P2PKH (Legacy) addresses but Trust Wallet also supports SegWit addresses.

**Hashcat Module Needed:**
- **Format:** MT19937 (LSB extraction) → BIP39 → BIP32 → P2PKH at m/44'/0'/0'/0/0
- **Input:** 32-bit timestamp seed
- **Output:** P2PKH addresses (1...)
- **Mode Suggestion:** Custom module for MT19937-LSB → BIP44 P2PKH

**Missing Support:**
- P2WPKH addresses (bc1q...) at m/84'/0'/0'/0/0
- P2SH-P2WPKH addresses (3...) at m/49'/0'/0'/0/0

---

### 4. Trust Wallet LCG Scanner

**Scanner File:** `src/scans/trust_wallet_lcg.rs`  
**OpenCL Kernel:** `cl/minstd_rand.cl`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ❌ **P2WPKH (Native SegWit)** - Not supported
- ❌ **P2SH-P2WPKH (Nested SegWit)** - Not supported

**Derivation Path:** `m/44'/0'/0'/0/0` (BIP44 standard)

**Assessment:** ⚠️ **INCOMPLETE** - Same issue as Trust Wallet scanner above

**Hashcat Module Needed:**
- **Format:** minstd_rand0 LCG → BIP39 → BIP32 → P2PKH at m/44'/0'/0'/0/0
- **Input:** 32-bit seed/timestamp
- **Output:** P2PKH addresses (1...)
- **CVE:** CVE-2024-23660 (Trust Wallet iOS)

---

### 5. Milk Sad Scanner

**Scanner File:** `src/scans/milk_sad.rs`  
**OpenCL Kernel:** `cl/milk_sad_crack.cl`, `cl/milk_sad_crack_multi30.cl`, `cl/milk_sad_crack_multipath.cl`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses (BIP44)
- ✅ **P2SH-P2WPKH (Nested SegWit)** - 3... addresses (BIP49)
- ✅ **P2WPKH (Native SegWit)** - bc1q... addresses (BIP84)

**Derivation Paths:**
- `m/44'/0'/0'/0/0` - BIP44 Legacy
- `m/49'/0'/0'/0/0` - BIP49 Nested SegWit
- `m/84'/0'/0'/0/0` - BIP84 Native SegWit

**Entropy Sizes:**
- 128-bit (12 words)
- 192-bit (18 words)
- 256-bit (24 words) ← **Research Update #13**

**Kernel Implementation:**
```c
// cl/milk_sad_crack.cl:54
identifier_for_public_key(&address_pub, hash160);
// Generates Hash160 only - address type determined by purpose
```

**Assessment:** ⚠️ **PARTIAL** - The base kernel only generates Hash160 (suitable for P2PKH). The multi-path kernels should support all three address types, but this needs verification.

**Current Implementation:**
- The kernel generates Hash160 which is compatible with P2PKH addresses
- P2SH-P2WPKH requires additional hashing: Hash160(witness_script)
- P2WPKH uses Hash160 directly in bech32 encoding

**Hashcat Module Needed:**
- **Format:** MT19937 (MSB extraction) → BIP39 → BIP32 → Multiple address types
- **Input:** 32-bit timestamp seed
- **Output:** P2PKH (BIP44), P2SH-P2WPKH (BIP49), P2WPKH (BIP84)
- **Entropy:** 128/192/256-bit (12/18/24 words)
- **Mode Suggestion:** Custom module with multi-path support

**Missing Support:**
- BIP49 (P2SH-P2WPKH) address generation in base kernel
- BIP84 (P2WPKH) bech32 encoding in base kernel
- The multi-path kernel should handle this but needs verification

---

### 6. Mobile Sensor Scanner

**Scanner File:** `src/scans/mobile_sensor.rs`  
**OpenCL Kernel:** `cl/mobile_sensor_crack.cl`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ❌ **P2WPKH (Native SegWit)** - Not checked
- ❌ **P2SH-P2WPKH (Nested SegWit)** - Not checked

**Assessment:** ⚠️ **LIMITED** - Only validates P2PKH addresses

**Hashcat Module Needed:**
- **Format:** Sensor entropy → BIP39 → BIP32 → P2PKH
- **Input:** Combined sensor readings (accelerometer, gyroscope, magnetometer)
- **Output:** P2PKH addresses
- **Note:** This is highly specialized - probably not suitable for standard hashcat

---

### 7. Profanity Scanner

**Scanner File:** `src/scans/profanity.rs`  
**OpenCL Kernel:** `cl/batch_profanity.cl`

**Address Formats:**
- ✅ **Ethereum addresses** - 0x... addresses
- ❌ **Bitcoin addresses** - Not applicable

**Assessment:** ✅ **CORRECT** - Profanity is for Ethereum vanity addresses, not Bitcoin

**Hashcat Module Needed:**
- **Format:** Weak PRNG → Direct EC keypair → Ethereum address
- **Note:** Ethereum-specific, not Bitcoin

---

### 8. Android SecureRandom Scanner

**Scanner File:** `src/scans/android_securerandom.rs`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ❌ Others not applicable (private key recovery from duplicate R values)

**Assessment:** ✅ **CORRECT** - This scanner recovers private keys from ECDSA signature nonce reuse, not from weak entropy generation

**Hashcat Module Needed:**
- **Not applicable** - This is signature analysis, not brute force

---

### 9. Brainwallet Scanner

**Scanner File:** `src/scans/brainwallet.rs`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ✅ **P2WPKH (Native SegWit)** - bc1q... addresses
- ❌ **P2SH-P2WPKH (Nested SegWit)** - Not supported

**Assessment:** ✅ **GOOD** - Supports both legacy and modern SegWit

**Hashcat Module Needed:**
- **Format:** Passphrase → SHA256 → Private key → P2PKH/P2WPKH
- **Input:** Text passphrase
- **Output:** P2PKH and P2WPKH addresses
- **Note:** This is similar to existing hashcat brain wallet modules

---

### 10. Passphrase Recovery Scanner

**Scanner File:** `src/scans/passphrase_recovery.rs`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - m/44'/0'/0'/0/0
- ✅ **P2SH-P2WPKH (Nested SegWit)** - m/49'/0'/0'/0/0
- ✅ **P2WPKH (Native SegWit)** - m/84'/0'/0'/0/0

**Assessment:** ✅ **COMPLETE** - Supports all three major address types

**Hashcat Module Needed:**
- **Format:** BIP39 mnemonic + passphrase → BIP32 → Multiple paths
- **Input:** Known mnemonic, unknown passphrase
- **Output:** Multiple address types
- **Note:** Similar to standard BIP39 recovery tools

---

### 11. BIP3x Scanner

**Scanner File:** `src/scans/bip3x.rs`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ❌ **Others** - Not supported

**Assessment:** ⚠️ **LIMITED** - Only P2PKH

**Hashcat Module Needed:**
- **Format:** PCG PRNG → BIP39 → BIP32 → P2PKH
- **Input:** PCG seed state
- **Output:** P2PKH addresses

---

### 12. Direct Key Scanner

**Scanner File:** `src/scans/direct_key.rs`

**Address Formats:**
- ✅ **P2PKH (Legacy)** - 1... addresses
- ✅ **P2WPKH (Native SegWit)** - bc1q... addresses

**Assessment:** ✅ **GOOD** - Supports both major formats

**Hashcat Module Needed:**
- **Format:** Raw private key → Public key → P2PKH/P2WPKH
- **Input:** Private key hex/WIF
- **Output:** Multiple address formats
- **Note:** Useful for WIF private key recovery with known partial keys

---

## Summary Matrix

| Scanner | P2PKH (1...) | P2SH (3...) | P2WPKH (bc1q...) | Status | Priority |
|---------|--------------|-------------|------------------|--------|----------|
| Cake Wallet | ❌ | ❌ | ✅ | Partial | Medium |
| Cake Wallet Dart PRNG | ❌ | ❌ | ✅ | Partial | Medium |
| Trust Wallet | ✅ | ❌ | ❌ | Incomplete | **HIGH** |
| Trust Wallet LCG | ✅ | ❌ | ❌ | Incomplete | **HIGH** |
| Milk Sad | ✅ | ⚠️ | ⚠️ | Needs Verification | **CRITICAL** |
| Mobile Sensor | ✅ | ❌ | ❌ | Limited | Low |
| Profanity | N/A (ETH) | N/A (ETH) | N/A (ETH) | Correct | N/A |
| Android SecureRandom | ✅ | N/A | N/A | Correct | N/A |
| Brainwallet | ✅ | ❌ | ✅ | Good | Low |
| Passphrase Recovery | ✅ | ✅ | ✅ | Complete | Low |
| BIP3x | ✅ | ❌ | ❌ | Limited | Low |
| Direct Key | ✅ | ❌ | ✅ | Good | Low |

**Legend:**
- ✅ = Fully supported
- ⚠️ = Partially supported or needs verification
- ❌ = Not supported
- N/A = Not applicable

## Critical Findings

### 1. Milk Sad Kernel Address Format Issues

**Issue:** The base `milk_sad_crack.cl` kernel only generates Hash160, which is suitable for P2PKH addresses. However, Research Update #13 specifically mentions:
- **224,000+ wallets** use **BIP49 P2SH-P2WPKH** addresses (prefix '3')
- Address derivation path: `m/49'/0'/0'/0/0`

**Current Implementation:**
```c
// cl/milk_sad_crack.cl generates only Hash160
identifier_for_public_key(&address_pub, hash160);
```

**Required for P2SH-P2WPKH:**
```c
// P2SH-P2WPKH requires:
// 1. Create witness program: OP_0 <20-byte-pubkey-hash>
// 2. Hash the witness program with Hash160
// 3. Add version byte 0x05 for P2SH addresses (prefix '3')
```

**Impact:** The kernel may be missing the majority of Update #13 vulnerable wallets because it doesn't properly generate P2SH-P2WPKH addresses.

**Priority:** **CRITICAL** - This affects the scanner's ability to find the largest known cluster of vulnerable wallets.

---

### 2. Trust Wallet Limited Address Type Coverage

**Issue:** Trust Wallet scanner only checks P2PKH addresses but Trust Wallet supports:
- Legacy (P2PKH) at m/44'/0'/0'/0/0
- Nested SegWit (P2SH-P2WPKH) at m/49'/0'/0'/0/0  
- Native SegWit (P2WPKH) at m/84'/0'/0'/0/0

**Impact:** Missing vulnerable wallets that use SegWit address formats.

**Priority:** **HIGH** - Modern Trust Wallet users likely use SegWit addresses.

---

### 3. Cake Wallet Address Format Correctness

**Status:** ✅ **VERIFIED CORRECT**

The Cake Wallet implementation correctly uses:
- Electrum seed format (not BIP39)
- Derivation path m/0'/0/0 (Electrum-style)
- P2WPKH addresses (bc1q...) which is Electrum's default

This matches the documented Cake Wallet vulnerability.

---

## Hashcat Module Recommendations

### Priority 1: Milk Sad P2SH-P2WPKH Module

**Required for:** Research Update #13 (224k+ wallets)

**Module Specification:**
- **Hashcat Mode:** Custom (suggest 30500)
- **Hash Format:** `$milksad-p2sh$<timestamp>$<target_address>`
- **Algorithm:**
  1. MT19937 PRNG seeded with timestamp
  2. MSB extraction (256-bit)
  3. BIP39 mnemonic generation (24 words)
  4. BIP32 seed derivation
  5. Derivation to m/49'/0'/0'/0/0
  6. P2SH-P2WPKH address generation
- **Verification:** Match against target address starting with '3'

**Kernel Changes Needed:**
1. Update `milk_sad_crack.cl` to support P2SH address generation
2. Add witness program creation: `OP_0 <20-byte-hash>`
3. Add witness program hashing: `Hash160(witness_program)`
4. Add P2SH encoding with version byte 0x05

---

### Priority 2: Trust Wallet Multi-Address Module

**Required for:** Complete Trust Wallet vulnerability coverage

**Module Specification:**
- **Hashcat Mode:** Custom (suggest 30501)
- **Hash Format:** `$trustwallet$<timestamp>$<address_type>$<target_address>`
- **Address Types:**
  - 0 = P2PKH (m/44'/0'/0'/0/0)
  - 1 = P2SH-P2WPKH (m/49'/0'/0'/0/0)
  - 2 = P2WPKH (m/84'/0'/0'/0/0)

**Kernel Changes Needed:**
1. Add address type parameter to `trust_wallet_crack.cl`
2. Implement P2SH-P2WPKH address generation
3. Implement P2WPKH (bech32) address generation
4. Support all three derivation paths

---

### Priority 3: Cake Wallet Electrum Module

**Required for:** Proper Cake Wallet hash cracking

**Module Specification:**
- **Hashcat Mode:** Custom (suggest 30502)
- **Hash Format:** `$cakewallet$<entropy_value>$<target_address>`
- **Algorithm:**
  1. Generate 132-bit entropy from seed
  2. Create Electrum mnemonic (12 words)
  3. Validate Electrum version prefix ("100")
  4. Electrum seed → BIP32 seed (PBKDF2 with "electrum" salt)
  5. Derive m/0'/0/0
  6. Generate P2WPKH address

**Kernel Changes Needed:**
1. Already mostly correct in `cake_wallet_crack.cl`
2. Verify Electrum prefix validation
3. Ensure P2WPKH generation is complete

---

### Priority 4: Trust Wallet LCG Module

**Required for:** CVE-2024-23660 (iOS vulnerability)

**Module Specification:**
- **Hashcat Mode:** Custom (suggest 30503)
- **Hash Format:** `$trustwallet-lcg$<seed>$<target_address>`
- **Algorithm:**
  1. minstd_rand0 LCG with seed
  2. LSB extraction for entropy
  3. BIP39 mnemonic
  4. BIP32 derivation to m/44'/0'/0'/0/0
  5. P2PKH address generation

**Kernel Changes Needed:**
1. Already exists in `minstd_rand.cl`
2. Add multi-address type support (same as Priority 2)

---

## Address Format Validation

### P2PKH (Legacy) Address Generation - VERIFIED ✅

**Process:**
1. Public Key (33 or 65 bytes)
2. SHA256(pubkey)
3. RIPEMD160(sha256) = Hash160 (20 bytes)
4. Add version byte 0x00
5. Compute checksum: SHA256(SHA256(version + hash160))
6. Take first 4 bytes of checksum
7. Concatenate: version + hash160 + checksum
8. Base58 encode

**Validation:**
```c
// This is correctly implemented in cl/address.cl
void identifier_for_public_key(extended_public_key_t *pub, uchar *identifier) {
    // SHA256 + RIPEMD160
}
```

✅ **Status:** All kernels using `identifier_for_public_key` correctly generate P2PKH Hash160.

---

### P2SH-P2WPKH (Nested SegWit) Address Generation - MISSING ❌

**Process:**
1. Public Key (33 bytes compressed)
2. SHA256(pubkey)
3. RIPEMD160(sha256) = pubkey_hash (20 bytes)
4. Create witness program: `0x0014<pubkey_hash>` (22 bytes)
   - 0x00 = witness version 0
   - 0x14 = 20 bytes length
   - pubkey_hash = 20-byte hash
5. Hash160(witness_program) = redeem_script_hash (20 bytes)
6. Add version byte 0x05 (for P2SH)
7. Compute checksum
8. Base58 encode

**Current Implementation:**
```c
// cl/milk_sad_crack.cl - INCOMPLETE
identifier_for_public_key(&address_pub, hash160);
// This generates pubkey_hash but doesn't create witness program
// or hash it for P2SH
```

❌ **Status:** NOT IMPLEMENTED in GPU kernels. This is a **CRITICAL GAP** for Research Update #13.

**Required Implementation:**
```c
// Pseudo-code for P2SH-P2WPKH
uchar pubkey_hash[20];
identifier_for_public_key(&address_pub, pubkey_hash);

// Create witness program
uchar witness_program[22];
witness_program[0] = 0x00; // OP_0
witness_program[1] = 0x14; // Push 20 bytes
memcpy(witness_program + 2, pubkey_hash, 20);

// Hash the witness program
uchar redeem_script_hash[20];
hash160(witness_program, 22, redeem_script_hash);

// Now redeem_script_hash can be used with version 0x05 for P2SH address
```

---

### P2WPKH (Native SegWit) Address Generation - PARTIAL ⚠️

**Process:**
1. Public Key (33 bytes compressed)
2. SHA256(pubkey)
3. RIPEMD160(sha256) = pubkey_hash (20 bytes)
4. Bech32 encode with:
   - HRP: "bc" for mainnet
   - Version: 0
   - Data: pubkey_hash

**Current Implementation:**
```c
// cl/cake_wallet_crack.cl generates Hash160
identifier_for_public_key(&address_pub, hash160);
// But doesn't perform bech32 encoding
```

⚠️ **Status:** Hash160 is correct, but bech32 encoding must be done on CPU side.

**Note:** Bech32 encoding is complex and typically done on the CPU after GPU kernel returns the Hash160.

---

## Recommended Actions

### Immediate (Critical Priority)

1. **Fix Milk Sad P2SH-P2WPKH Support**
   - [ ] Implement P2SH-P2WPKH address generation in `milk_sad_crack.cl`
   - [ ] Add witness program creation
   - [ ] Add witness program hashing
   - [ ] Test against known Update #13 addresses
   - [ ] Verify all 224k+ wallets can be found

2. **Verify Multi-Path Kernel**
   - [ ] Audit `milk_sad_crack_multipath.cl`
   - [ ] Ensure it correctly handles BIP44/49/84 paths
   - [ ] Test each address type separately

### High Priority

3. **Expand Trust Wallet Address Support**
   - [ ] Add P2SH-P2WPKH to `trust_wallet_crack.cl`
   - [ ] Add P2WPKH to `trust_wallet_crack.cl`
   - [ ] Update scanner to check all address types

4. **Create Hashcat Module Documentation**
   - [ ] Document input format for each vulnerability
   - [ ] Provide example hashes
   - [ ] Create module specification documents

### Medium Priority

5. **Develop Actual Hashcat Modules**
   - [ ] Create C implementation for Milk Sad P2SH module
   - [ ] Create C implementation for Trust Wallet multi-address module
   - [ ] Test with real hashcat binary
   - [ ] Submit PR to hashcat repository (optional)

### Low Priority

6. **Expand Other Scanner Address Support**
   - [ ] Add SegWit to BIP3x scanner
   - [ ] Add P2SH to Brainwallet scanner
   - [ ] Consider multi-path for all scanners

---

## Testing Recommendations

### 1. Address Generation Tests

Create comprehensive tests for each address type:

```rust
#[test]
fn test_p2pkh_address_generation() {
    // Test known keypair → P2PKH address
}

#[test]
fn test_p2sh_p2wpkh_address_generation() {
    // Test known keypair → P2SH-P2WPKH address
    // Critical for Research Update #13
}

#[test]
fn test_p2wpkh_address_generation() {
    // Test known keypair → P2WPKH address
}
```

### 2. Cross-Validation Tests

```rust
#[test]
fn test_gpu_cpu_address_parity() {
    // Ensure GPU kernel generates same addresses as CPU code
}

#[test]
fn test_update_13_known_wallet() {
    // Test against a known Update #13 address
    // Should find the timestamp that generated it
}
```

### 3. Hashcat Module Tests

```bash
# Example test for custom hashcat module
hashcat -m 30500 -a 3 '$milksad-p2sh$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U' ?d?d?d?d?d?d?d?d
```

---

## Conclusion

**Key Findings:**
1. ✅ Cake Wallet address format is **CORRECT** (P2WPKH with Electrum)
2. ❌ Milk Sad P2SH-P2WPKH support is **MISSING** - **CRITICAL** for Update #13
3. ⚠️ Trust Wallet coverage is **INCOMPLETE** - missing SegWit addresses
4. ❌ No hashcat modules exist - they need to be created

**Next Steps:**
1. **Fix Milk Sad P2SH-P2WPKH** - Highest priority
2. **Verify multi-path kernel** - Ensure it works correctly
3. **Expand Trust Wallet** - Add SegWit address support
4. **Create hashcat modules** - For external integration

**Impact:**
- Current implementation may miss **majority** of Update #13 wallets
- Trust Wallet scanner may miss modern SegWit users
- No way to integrate with standard hashcat tooling

