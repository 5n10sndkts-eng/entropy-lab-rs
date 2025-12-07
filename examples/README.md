# Examples Directory

This directory contains standalone example programs and utilities that demonstrate specific functionality or provide alternative implementations.

## Files

### validate_cpu.rs
CPU reference implementation for address validation. This can be compiled standalone to verify address generation without the full crate.

### gpu_bip39_validator.rs
Standalone GPU BIP39 validation utility. Demonstrates GPU-accelerated BIP39 mnemonic validation.

### bip39_solver_main.rs / bip39_solver_Cargo.toml
Alternative BIP39 solver implementation with its own Cargo configuration. This is a separate project that can be built independently.

## Building Examples

These examples are not automatically built with the main project. To build them:

### validate_cpu.rs
```bash
rustc --edition 2021 validate_cpu.rs -o validate_cpu
```

### bip39_solver
```bash
# Copy the Cargo.toml
cp bip39_solver_Cargo.toml ../Cargo.toml.bip39_solver
cp bip39_solver_main.rs ../src/main.rs.bip39_solver
# Then build with appropriate setup
```

## Purpose

These examples serve as:
- Reference implementations for testing
- Standalone tools for specific tasks
- Alternative approaches to solving similar problems
- Learning resources for understanding the algorithms
