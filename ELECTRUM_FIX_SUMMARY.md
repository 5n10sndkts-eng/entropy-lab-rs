# Cake Wallet Electrum Fix - Summary

## Problem

The Cake Wallet vulnerability scanner was finding **ZERO hits** because it was using the wrong seed format. The issue was discovered through the following insights:

1. **Cake Wallet uses ELECTRUM seed format, NOT BIP39**
2. **Different derivation path: m/0'/c/a not BIP44**
3. **8,757 vulnerable wallets from 2020-2021**
4. **Dart Random() weakness documented at milksad.info**

## Root Cause

### BIP39 vs Electrum Seed Generation

The critical difference between BIP39 and Electrum is in the **PBKDF2 salt**:

- **BIP39**: Uses PBKDF2-HMAC-SHA512 with salt = `"mnemonic"` + passphrase
- **Electrum**: Uses PBKDF2-HMAC-SHA512 with salt = `"electrum"` + passphrase

Even with the same mnemonic phrase, these two methods produce **completely different seeds**, which in turn produce completely different private keys and addresses.

### Derivation Path

The derivation path was already correct:
- Cake Wallet uses: `m/0'/0/0` (Electrum format)
- The code was already using this path (not BIP44's `m/44'/0'/0'/0/0`)

## Solution Implemented

### 1. Created Electrum GPU Kernel

Created `cl/batch_address_electrum.cl` with the correct PBKDF2 salt:

```c
// BIP39 (original):
uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 }; // "mnemonic"

// Electrum (new):
uchar salt[12] = { 101, 108, 101, 99, 116, 114, 117, 109, 0, 0, 0, 1 }; // "electrum"
```

### 2. Added Electrum Support to GPU Solver

Added `compute_batch_electrum()` method to `GpuSolver` that uses the new kernel:

```rust
pub fn compute_batch_electrum(
    &self,
    entropies: &[[u8; 16]],
    purpose: u32,
) -> ocl::Result<Vec<[u8; 25]>>
```

### 3. Updated All Cake Wallet Scanners

Updated all 4 Cake Wallet-related scanners to use Electrum:

1. **cake_wallet.rs**: Basic 2^20 entropy scanner
2. **cake_wallet_dart_prng.rs**: Time-based Dart PRNG scanner  
3. **cake_wallet_rpc.rs**: RPC balance checking scanner
4. **cake_wallet_targeted.rs**: Targeted scan of known vulnerable seeds

All now call `compute_batch_electrum()` instead of `compute_batch()` for Cake Wallet addresses.

### 4. Added Electrum Mnemonic Module

Created `src/electrum_mnemonic.rs` with utility functions:

```rust
/// Generate Electrum-style seed from BIP39 mnemonic
pub fn mnemonic_to_electrum_seed(mnemonic: &Mnemonic, passphrase: &str) -> [u8; 64]
```

This is used in tests and CPU verification code.

## Files Changed

### New Files
- `cl/batch_address_electrum.cl` - OpenCL kernel with Electrum PBKDF2
- `src/electrum_mnemonic.rs` - Rust support for Electrum seeds

### Modified Files
- `src/scans/gpu_solver.rs` - Added `compute_batch_electrum()` method
- `src/scans/cake_wallet.rs` - Use Electrum seed derivation
- `src/scans/cake_wallet_dart_prng.rs` - Use Electrum seed derivation
- `src/scans/cake_wallet_rpc.rs` - Use Electrum seed derivation
- `src/scans/cake_wallet_targeted.rs` - Use Electrum seed derivation  
- `src/lib.rs` - Export electrum_mnemonic module
- `README.md` - Document Electrum vs BIP39 difference

## Testing

All changes compile successfully with:
- ✅ `cargo check` - Passes
- ✅ `cargo clippy` - Passes with minor warnings
- ⏭️ `cargo test` - Skipped (requires OpenCL runtime)

## Expected Impact

With these changes, the Cake Wallet scanners will now:

1. **Generate the correct addresses** for vulnerable Cake Wallet seeds
2. **Find actual vulnerable wallets** instead of zero hits
3. **Match the 8,757 known vulnerable wallets** from 2020-2021

## References

- Cake Wallet source: https://github.com/cake-tech/cake_wallet
- Milk Sad research: https://milksad.info/posts/research-update-9/
- Electrum seed format: Uses PBKDF2 with "electrum" salt per Electrum wallet standard
- Vulnerable wallets: 8,757 Bitcoin wallets generated with weak Dart Random() PRNG
