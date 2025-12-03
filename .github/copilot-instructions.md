# GitHub Copilot Instructions for Entropy Lab RS

## Repository Overview

Entropy Lab RS is a Rust-based security research tool designed to identify and analyze cryptocurrency wallet vulnerabilities related to weak entropy generation. This tool is intended for security researchers, white-hat hackers, and blockchain security professionals.

## Project Structure

```
entropy-lab-rs/
├── src/
│   ├── main.rs              # CLI interface with clap
│   ├── lib.rs               # Library exports
│   ├── scans/               # Scanner implementations for various vulnerabilities
│   │   ├── cake_wallet.rs
│   │   ├── trust_wallet.rs
│   │   ├── milk_sad.rs
│   │   ├── android_securerandom.rs
│   │   ├── profanity.rs
│   │   ├── mobile_sensor.rs
│   │   ├── malicious_extension.rs
│   │   └── gpu_solver.rs    # OpenCL GPU acceleration
│   └── bin/                 # Additional binaries (benchmarks, test vector generation)
├── tests/                   # Integration tests
├── .github/workflows/       # CI/CD pipelines
└── docs/                    # Additional documentation
```

## Technology Stack

- **Language**: Rust (edition 2021, minimum version 1.70)
- **GPU Acceleration**: OpenCL (via `ocl` crate)
- **CLI Framework**: clap v4.5 with derive macros
- **Cryptography**: secp256k1, bitcoin, bip39, sha2, hmac, pbkdf2, ripemd
- **RPC Integration**: bitcoincore-rpc for blockchain interactions
- **Performance**: Rayon for parallel processing, bloom filters for optimization

## Code Style and Quality

### Formatting
- Use `cargo fmt` for all Rust code (enforced in CI)
- Follow standard Rust naming conventions (snake_case for functions/variables, CamelCase for types)

### Linting
- Run `cargo clippy -- -D warnings` before committing
- Address all clippy warnings (CI uses `-W clippy::all`)
- Prefer using `Result` and `?` operator over `unwrap()`/`expect()`

### Error Handling
- Use `anyhow::Result` for error propagation
- Provide descriptive error messages
- Avoid panics in production code paths
- Use `expect()` only for internal consistency checks with clear messages

### Comments
- Add doc comments (`///`) for all public APIs
- Document security implications of sensitive operations
- Explain complex cryptographic or mathematical operations
- Include examples in doc comments where helpful

## Security Best Practices

### Critical Security Rules
1. **Never commit credentials**: Use environment variables or `.env` files (gitignored)
2. **Never log or store private keys**: Handle sensitive data in memory only
3. **Validate all external inputs**: Especially user-provided data and RPC responses
4. **Use constant-time operations**: For cryptographic comparisons
5. **Follow responsible disclosure**: This is a research tool for authorized testing only

### Environment Variables
The project uses these environment variables for sensitive configuration:
- `RPC_URL`: Bitcoin RPC endpoint
- `RPC_USER`: Bitcoin RPC username
- `RPC_PASS`: Bitcoin RPC password

Always use `clap`'s `env` attribute for environment variable support in CLI arguments.

### Credential Handling
```rust
// Good: Using environment variables with clap
#[arg(long, env = "RPC_USER")]
rpc_user: String,

// Bad: Hardcoded credentials
let user = "hardcoded_username"; // NEVER DO THIS
```

## Building and Testing

### Build Commands
```bash
# Check compilation
cargo check

# Build for development
cargo build

# Build optimized release
cargo build --release
```

### Testing
```bash
# Run unit and integration tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

**Note**: GPU tests may fail in CI environments without OpenCL. Use `continue-on-error: true` for GPU-dependent tests.

### OpenCL Dependencies
- OpenCL is required for GPU acceleration features
- On Ubuntu/Debian: `sudo apt-get install ocl-icd-opencl-dev`
- Tests may be skipped if OpenCL is unavailable
- Consider making OpenCL optional via feature flags for broader compatibility

## Common Patterns

### Scanner Implementation
When adding new vulnerability scanners:
1. Create a new file in `src/scans/`
2. Implement the scanner logic with proper error handling
3. Add CLI subcommand in `src/main.rs`
4. Export from `src/scans/mod.rs`
5. Add integration tests if applicable
6. Document the vulnerability being scanned
7. Include references to CVEs or security advisories

### GPU Optimization
- Use pinned memory for CPU-GPU transfers
- Calculate optimal work group sizes based on device capabilities
- Implement device-aware batch sizing
- See `OPENCL_OPTIMIZATIONS.md` for detailed guidance

### CLI Design
- Use clap's derive macros for argument parsing
- Provide sensible defaults where possible
- Support both CLI args and environment variables for configuration
- Include helpful descriptions and examples in `--help` output

## CI/CD Pipeline

The project uses GitHub Actions with these checks:
- **Check**: `cargo check` for compilation errors
- **Test**: `cargo test` (with OpenCL setup)
- **Format**: `cargo fmt --check` (must pass)
- **Clippy**: `cargo clippy` (warnings reported)
- **Security Audit**: `cargo audit` (advisories reported)
- **Build**: Release build with artifact upload

All PRs must pass the CI pipeline before merging.

## Documentation Standards

### Code Documentation
- Document all public functions, structs, and enums
- Include usage examples in module-level documentation
- Document security implications and edge cases
- Reference relevant CVEs or security advisories

### Project Documentation
- Update `README.md` when adding features
- Maintain `SECURITY.md` for security-related changes
- Follow `CONTRIBUTING.md` guidelines
- Document configuration options and environment variables

## Performance Considerations

- Use `--release` flag for performance testing
- Profile with `cargo bench` or `perf` for optimization
- Consider GPU acceleration for computationally intensive operations
- Use Rayon for CPU parallelization where appropriate
- Implement bloom filters for large-scale data filtering

## Ethical Guidelines

This tool is for **authorized security research only**:
- ✅ Security research and education
- ✅ White-hat testing with proper authorization
- ✅ Responsible vulnerability disclosure
- ❌ Unauthorized wallet access
- ❌ Theft or unauthorized fund transfers
- ❌ Any illegal activities

Always follow local laws and responsible disclosure practices.

## When Contributing

1. Check existing issues and PRs to avoid duplicate work
2. Create a feature branch from `main` or `develop`
3. Write tests for new functionality
4. Run full test suite and linters locally
5. Update documentation as needed
6. Reference related issues in PR description
7. Be prepared to address code review feedback

## Useful Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [secp256k1 Documentation](https://docs.rs/secp256k1/)
- [Bitcoin Developer Reference](https://developer.bitcoin.org/reference/)
- [OpenCL Programming Guide](https://www.khronos.org/opencl/)

## Questions or Issues?

- Check existing documentation in the repository
- Review security audit reports (AUDIT_*.md files)
- Open an issue with the appropriate label
- Follow the issue template if provided
