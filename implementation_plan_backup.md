# Deep Audit: Issues Preventing Real Hits

This plan documents all critical issues found in the vulnerability scanners that could prevent finding real vulnerable wallets.

## User Review Required

> [!WARNING]
> **Critical Issues Found**: Multiple issues across all scanners could prevent detection of real vulnerable wallets
> - Entropy extraction mismatches between CPU and GPU
> - Missing RPC/balance validation integration
> - Potential cryptographic implementation errors
> - Unused GPU acceleration in some scanners

> [!IMPORTANT]
> **Verification Strategy**: All fixes require testing with known test vectors
> - Need user to provide known vulnerable addresses for each vulnerability type (if available)
> - Will create synthetic test cases for each scanner
> - Will verify CPU vs GPU parity for all implementations

## Proposed Changes

### Critical Issues by Category

#### Category 1: Entropy Extraction & RNG (HIGH SEVERITY)

##### [milk_sad.rs](file:///Users/moe/temporal-planetarium/src/scans/milk_sad.rs)

**Issue**: MT19937 entropy extraction method may not match reference implementation

**Evidence**:
```rust
// In milk_sad.rs:149-162
fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = [0u8; 16];
    for i in 0..4 {
        let val = rng.next_u32();
        entropy[i * 4] = ((val >> 24) & 0xFF) as u8;      // MSB extraction
        entropy[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        entropy[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        entropy[i * 4 + 3] = (val & 0xFF) as u8;
    }
    entropy
}
```

**GPU Implementation**:
```c
// In milk_sad_crack.cl:17-27
mt19937_extract_128(timestamp, entropy_words);
for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
        entropy[i*4 + j] = (entropy_words[i] >> (24 - j*8)) & 0xFF;  // Same MSB method
    }
}
```

**Potential Problem**: The Libbitcoin "Milk Sad" vulnerability used MSB extraction of MT19937 output. We need to verify this matches the actual vulnerable implementation.

**Fix**: Create test vector comparing against known Milk Sad vulnerable address and verify entropy extraction matches

---

#### [trust_wallet.rs](file:///Users/moe/temporal-planetarium/src/scans/trust_wallet.rs)

**Issue**: Trust Wallet scanner is GPU-only with no fallback, and uses same MT19937 implementation as Milk Sad

**Evidence**: Same entropy extraction in `trust_wallet_crack.cl` lines 18-27

**Potential Problem**: If MT19937 extraction is wrong, both scanners  will fail

**Fix**: Verify with known Trust Wallet vulnerable instance (November 2022 timeframe)

---

#### [cake_wallet.rs](file:///Users/moe/temporal-planetarium/src/scans/cake_wallet.rs)

**Issue**: CPU implementation uses Electrum seed derivation, GPU version needs verification

**Evidence**:
```rust
// CPU path (lines 88-150)
let seed_val = electrum::mnemonic_to_seed(&mnemonic_str);  // Electrum!
let path = DerivationPath::from_str("m/0'/0/0")?;          // Electrum path
```

```c
// GPU path in batch_address.cl (lines 93-104)
if (purpose == 0) {
    salt[0] = 101; // "electrum" salt
    ...
}
// And derivation (lines 141-145)
if (purpose == 0) {
    // Cake Wallet: m/0'/0/0
    hardened_private_child_from_private(&master_private, &target_key, 0);
    normal_private_child_from_private(&target_key, &target_key, 0);
    normal_private_child_from_private(&target_key, &target_key, 0);
}
```

**Verification Needed**: Confirm GPU Electrum implementation matches CPU

---

##### [cake_wallet_targeted.rs](file:///Users/moe/temporal-planetarium/src/scans/cake_wallet_targeted.rs)

**Issue**: Scanner initializes GPU solver but NEVER USES IT

**Evidence**:
```rust
// Line 52
let solver = GpuSolver::new()?;
// ...but then just returns Ok(()) at line 67 without using solver!
```

**Impact**: CRITICAL - This scanner claims to check 8,717 confirmed vulnerable seeds but does nothing!

**Fix**: Implement actual scanning logic using the GPU solver

---

#### Category 2: Missing Balance Validation (HIGH SEVERITY)

**Issue**: Most scanners generate addresses but never check if they have balances

**Affected Scanners**:
- `milk_sad.rs` - Only verifies found timestamp matches target address, no balance check
- `trust_wallet.rs` - Same issue
- `cake_wallet.rs` - Just generates addresses, no checking
- `cake_wallet_dart_prng.rs` - Same issue  
- `mobile_sensor.rs` - Generates hashes only
- `profanity.rs` - No actual scanning implementation

**Current Behavior**:
```rust
// milk_sad.rs lines 88-119
// It ONLY works if you provide a target address!
if derived_address == target {
    info!("CRACKED SUCCESSFUL!");
    // No balance checking!
}
```

**Missing**: Integration with `compute_cake_hash` or similar methods that could check against known vulnerable address sets

**Fix**: 
1. For target-based scans: Current implementation is OK for finding specific addresses
2. For bulk scanning: Need to integrate bloom filters or RPC balance checking
3. Android SecureRandom has RPC integration but doesn't check balances after key recovery

---

#### Category 3: Android SecureRandom (MEDIUM-HIGH SEVERITY)

##### [android_securerandom.rs](file:///Users/moe/temporal-planetarium/src/scans/android_securerandom.rs)

**Issue 1**: Private key recovery logic exists but no balance validation

**Evidence** (lines 461-478):
```rust
Ok(private_key) => {
    warn!("✅ PRIVATE KEY RECOVERED!");
    warn!("Private Key (hex): {}", hex::encode(private_key.secret_bytes()));
    
    // Verifies public key derivation
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &private_key);
    
    // Writes to file
    // BUT: Never checks if this address has a balance!
}
```

**Issue 2**: No address derivation from recovered private key

**Missing Logic**:
```rust
// Should add:
let compressed_pubkey = bitcoin::CompressedPublicKey(public_key);
let address = Address::p2pkh(compressed_pubkey, Network::Bitcoin);
// Then check balance via RPC
let balance = rpc.get_received_by_address(&address, Some(0))?;
if balance > 0 {
    // REAL HIT!
}
```

**Fix**: Add address derivation and balance checking after key recovery

---

#### Category 4: GPU/CPU Parity (MEDIUM SEVERITY)

**Issue**: No verification that GPU and CPU implementations produce identical results

**Test Gaps**:
- No test comparing GPU vs CPU output for same entropy in `milk_sad`
- No test comparing GPU vs CPU for Cake Wallet Electrum derivation
- No test for MT19937 GPU implementation vs Rust `rand_mt` crate

**Existing Tests** (from `tests/` directory):
```bash
tests/integration_tests.rs - Basic CLI tests only
tests/test_bip39_validation.rs - BIP39 validation only  
tests/test_mt19937_vectors.rs - Has MT19937 test vectors!
```

**Fix**: Add GPU/CPU parity tests using existing test vectors

---

#### Category 5: Incomplete Implementations (LOW-MEDIUM SEVERITY)

##### [malicious_extension.rs](file:///Users/moe/temporal-planetarium/src/scans/malicious_extension.rs)

**Issue**: Stub implementation only, doesn't actually scan

**Evidence** (lines 14-23):
```rust
pub fn run() -> Result<()> {
    info!("Malicious Extension Reproduction...");
    info!("Simulating weakened crypto generation...");
    // Just prints "Scan complete!" - no actual logic!
    Ok(())
}
```

---

##### [profanity.rs](file:///Users/moe/temporal-planetarium/src/scans/profanity.rs)

**Issue**: Has GPU kernel but minimal Rust implementation

**Evidence** (lines 16-27):
```rust
pub fn run(target: Option<String>) -> Result<()> {
    info!("Profanity Vanity Address Vulnerability...");
    info!("This is a demonstration...");
    // Just prints example - GPU solver not actually called!
    Ok(())
}
```

**Fix**: Implement actual scanning logic calling GPU solver

---

#### Category 6: Code Quality Issues (LOW SEVERITY)

**Compilation Warnings** (non-blocking but should fix):
```
warning: unused import: `Device` (gpu_solver.rs)
warning: unused variable: `solver` (cake_wallet_targeted.rs) - CRITICAL!
warning: fields `max_compute_units` and `local_mem_size` are never read
warning: method `calculate_optimal_batch_size` is never used
```

**Impact**: The unused `solver` warning in `cake_wallet_targeted.rs` is actually a critical bug indicator

---

### Summary Table

| Scanner | Severity | Primary Issue | Has Tests |  
|---------|----------|---------------|-----------|
| Milk Sad | HIGH | MT19937 vs libbitcoin parity unverified | Partial |
| Trust Wallet | HIGH | Same MT19937 issue | No |
| Cake Wallet | HIGH | Electrum GPU/CPU parity unverified | No |
| Cake Wallet Targeted | CRITICAL | GPU solver initialized but never used! | No |
| Cake Wallet DART PRNG | MEDIUM | No verification vs actual Dart PRNG | No |
| Android SecureRandom | MEDIUM-HIGH | No balance checking after key recovery | No |
| Mobile Sensor | MEDIUM | Hash-only, no address generation | No |
| Profanity | LOW | Stub implementation | No |
| Malicious Extension | LOW | Stub implementation | No |

---

## Verification Plan

### 1. MT19937 Test Vector Verification

**File**: [tests/test_mt19937_vectors.rs](file:///Users/moe/temporal-planetarium/tests/test_mt19937_vectors.rs)

**Command**:
```bash
cargo test --features gpu test_mt19937
```

**Expected**: Verify MT19937 implementation matches known reference outputs

---

### 2. Create GPU/CPU Parity Tests

**New Test File**: `tests/test_gpu_cpu_parity.rs`

**Tests to Add**:
```rust
#[test]
fn test_milk_sad_gpu_cpu_parity() {
    // Given known timestamp
    let timestamp = 1500000000u32;
    
    // CPU implementation
    let cpu_entropy = milk_sad::generate_milk_sad_entropy(timestamp);
    let cpu_address = milk_sad::generate_address_from_entropy(&cpu_entropy, 0);
    
    // GPU implementation  
    let gpu_solver = GpuSolver::new().unwrap();
    let gpu_results = gpu_solver.compute_milk_sad_crack(timestamp, timestamp+1, &extract_hash160(&cpu_address)).unwrap();
    
    assert_eq!(gpu_results.len(), 1);
    assert_eq!(gpu_results[0], timestamp as u64);
}

#[test]
fn test_cake_wallet_electrum_parity() {
    // Test entropy 0x00000000 0x00000000 0x00000000 0x00000000
    // Verify GPU and CPU produce same address for Cake Wallet (purpose=0)
}

#[test]
fn test_trust_wallet_parity() {
    // Similar to Milk Sad but for Trust Wallet timeframe
}
```

**Command**:
```bash
cargo test --features gpu test_.*_parity
```

---

### 3. Known Vulnerability Test Cases

**User Input Needed**: Please provide if available:
- [ ] Known Milk Sad vulnerable address + timestamp
- [ ] Known Trust Wallet vulnerable address + timestamp (Nov 2022)
- [ ] Known Cake Wallet vulnerable address + entropy/mnemonic
- [ ] Android SecureRandom duplicate R value transaction IDs

**If available**, create `tests/test_known_vulnerabilities.rs`:
```rust
#[test]
fn test_milk_sad_known_case() {
    // Use actual vulnerable address from Milk Sad incident
    let target = "1..."; // Real address
    let expected_timestamp = ...; // Known timestamp
    
    // Verify scanner finds it
}
```

---

### 4. Balance Checking Integration Test

**Manual Test** (requires synced Bitcoin node):

```bash
# Start Bitcoin Core with RPC enabled
# Set environment variables
export RPC_URL="http://127.0.0.1:8332"
export RPC_USER="your_user"
export RPC_PASS="your_pass"

# Test Android SecureRandom scanner
cargo run --features gpu --release -- android-secure-random \
    --start-block 302000 \
    --end-block 302100

# Verify:
# 1. Scanner runs without errors
# 2. If duplicate R found, check android_securerandom_recovered_keys.txt
# 3. Verify addresses are derived
# 4. (AFTER FIX) Verify balance checking works
```

---

### 5. Cake Wallet Targeted Fix Verification

**After implementing fix**:

```bash
# This should actually scan the 8,717 hashes
cargo run --features gpu --release -- cake-wallet-targeted

# Verify:
# - GPU solver is actually used
# - Progress is shown
# - Addresses/hashes are generated
# - If hits found, they match known vulnerable set
```

---

### 6. Full Integration Test

**After all fixes**:

Create `tests/integration_test_full_pipeline.rs`:

```rust
#[test]
#[ignore] // Run manually with: cargo test --features gpu -- --ignored
fn test_full_milk_sad_pipeline() {
    // 1. Generate test entropy with known timestamp
    // 2. Derive expected address
    // 3. Run scanner with target address
    // 4. Verify it finds the correct timestamp
    // 5. Verify entropy/mnemonic matches
}
```

**Command**:
```bash
cargo test --features gpu -- --ignored --nocapture
```

---

### 7. Automated Verification Script

**Create**: `verify_all.sh`

```bash
#!/bin/bash
set -e

echo "Running all verification tests..."

echo "1. Compiling with GPU features..."
cargo check --features gpu

echo "2. Running MT19937 tests..."
cargo test --features gpu test_mt19937

echo "3. Running GPU/CPU parity tests..."
cargo test --features gpu test_.*_parity

echo "4. Running BIP39 validation tests..."
cargo test test_bip39

echo "5. Checking for compilation warnings..."
cargo clippy --features gpu -- -D warnings

echo "✅ All verifications passed!"
```

**Command**:
```bash
chmod +x verify_all.sh
./verify_all.sh
```

---

## Implementation Order

1. **Phase 1: Fix Critical Bugs** (HIGH PRIORITY)
   - Fix `cake_wallet_targeted.rs` - implement actual scanning
   - Add balance checking to `android_securerandom.rs`
   
2. **Phase 2: Verify Cryptographic Correctness** (HIGH PRIORITY)
   - Create GPU/CPU parity tests
   - Verify MT19937 implementations
   - Verify Electrum seed derivation
   
3. **Phase 3: Add Missing Integrations** (MEDIUM PRIORITY)
   - Add balance checking framework
   - Integrate bloom filters or address sets for bulk scanning
   
4. **Phase 4: Complete Implementations** (LOW PRIORITY)
   - Implement `profanity.rs` actual logic
   - Implement `malicious_extension.rs` if needed
   
5. **Phase 5: Code Quality** (LOW PRIORITY)
   - Fix all compilation warnings
   - Add documentation
   - Optimize performance
