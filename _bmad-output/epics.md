---
stepsCompleted: ['step-01-validate-prerequisites', 'step-02-design-epics']
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/specs/epics-phase-1-mvp.md"
  - "_bmad-output/specs/epics-phase-13.md"
  - "_bmad-output/implementation-artifacts/epics.md"
  - "_bmad-output/randstorm-tech-spec.md"
  - "_bmad-output/phase-13-tech-spec.md"
---

# temporal-planetarium - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for temporal-planetarium, decomposing the requirements from the PRD, Architecture, existing epics, and tech specs into implementable stories for the Randstorm/BitcoinJS Scanner feature.

**Project Scope:** GPU-accelerated vulnerability scanner for Bitcoin wallets generated between 2011-2015 using weak JavaScript PRNGs.

**Phase Coverage:**
- Phase 1 MVP: Chrome V8 PRNG, Top 100 fingerprints, P2PKH addresses, basic GPU acceleration
- Phase 13: Vulnerability Intelligence, Milk Sad, Nonce Reuse, WGPU modernization
- Future: Firefox/Safari/IE PRNGs, Multi-path derivation, Professional reporting

## Requirements Inventory

### Functional Requirements

**FR-1: JavaScript PRNG Reconstruction** (Priority: P0 - Critical MVP Blocker, Phase: 1)
- FR-1.1: Chrome V8 PRNG (MWC1616) Implementation - exact constants (18000, 30903), deterministic seeding
- FR-1.2: Firefox SpiderMonkey PRNG Implementation (Phase 2) - LCG variant
- FR-1.3: Safari JavaScriptCore PRNG (Xorshift128+) (Phase 2)
- FR-1.4: IE Chakra PRNG (Mersenne Twister variant) (Phase 2)

**FR-2: Browser Fingerprint Database** (Priority: P0 - Critical MVP Blocker, Phase: 1)
- FR-2.1: Browser Configuration Schema - user_agent, screen_width, screen_height, color_depth, timezone_offset, language, platform, market_share_estimate, year_range
- FR-2.2: Top 100 Configurations (Phase 1) - Chrome 20-40, Firefox 10-30, Safari 5-8, US/EU timezones
- FR-2.3: Extended 500 Configurations (Phase 2) - additional versions, mobile, global timezones
- FR-2.4: Configuration Prioritization - sorted by market_share_estimate descending

**FR-3: Derivation Path Support** (Priority: P0 - Critical, Phase: 1 simple, 2 multi-path)
- FR-3.1: Pre-BIP32 Direct Derivation (Phase 1) - direct private key to P2PKH
- FR-3.2: BIP32 Simple Paths (Phase 2) - m/0, m/0/0
- FR-3.3: BIP44 Standard Path (Phase 2) - m/44'/0'/0'/0/0
- FR-3.4: SegWit Paths (Phase 2) - BIP49, BIP84
- FR-3.5: Extended Index Support (Phase 3) - indices 0-100

**FR-4: GPU Acceleration via OpenCL** (Priority: P0 - Critical, Phase: 1)
- FR-4.1: Basic OpenCL Kernel - parallel PRNG, secp256k1, address generation
- FR-4.2: Device-Aware Work Group Sizing - auto-configure for NVIDIA/AMD/Intel
- FR-4.3: Batch Processing - 1M+ seeds per invocation, pinned memory
- FR-4.4: GPU Optimization (Phase 2) - device-specific tuning, constant memory
- FR-4.5: Multi-GPU Support (Phase 3) - distributed workload
- FR-4.6: CPU Fallback - automatic when GPU unavailable

**FR-5: Validation Framework & Test Suite** (Priority: P0 - Critical Pre-Release Blocker, Phase: 1)
- FR-5.1: 2023 Randstorm Test Vectors - 100% match on disclosed examples
- FR-5.2: Integration Tests - PRNG, fingerprints, derivation paths
- FR-5.3: Performance Benchmarks - GPU speedup, scan completion time
- FR-5.4: Regression Tests - existing 18 scanners unaffected
- FR-5.5: False Positive/Negative Validation - <1% FP, <5% FN

**FR-6: CLI Interface** (Priority: P0 - Critical, Phase: 1)
- FR-6.1: Subcommand Structure - `entropy-lab randstorm-scan [OPTIONS]`
- FR-6.2: Required Arguments - `--target-addresses <FILE>` or `--scan-range`
- FR-6.3: Optional Arguments - --phase, --gpu, --cpu, --output, --threads, --batch-size
- FR-6.4: Progress Reporting - real-time bar, ETA, seeds/second
- FR-6.5: Results Output - CSV format with Address, Status, Confidence, Config, Timestamp
- FR-6.6: Error Handling - clear messages, CSV validation, GPU warnings

**FR-7: Responsible Disclosure Framework** (Priority: P0 - Critical Legal/Ethical, Phase: 1)
- FR-7.1: Disclosure Protocol Documentation - 90-day window, exchange coordination
- FR-7.2: Findings Report Format - address, risk level, recommendations
- FR-7.3: Private Key Handling - scanner identifies only, no export to user
- FR-7.4: Ethical Use Guidelines - prominent disclaimer, white-hat only, legal warnings
- FR-7.5: Coordination Support - template emails for notifications

**FR-8: CSV Import/Export** (Priority: P1 - High, Phase: 2)
- FR-8.1: Input CSV Format - Address, Notes columns
- FR-8.2: Output CSV Format - standard results format
- FR-8.3: Batch Scanning - 10,000+ addresses efficiently
- FR-8.4: Export Options - CSV, JSON, PDF (Phase 3)

**FR-9: Checkpoint/Resume Support** (Priority: P2 - Medium, Phase: 3)
- FR-9.1: Checkpoint File Format - JSON with scan progress
- FR-9.2: Auto-checkpoint - every 5 minutes, on SIGTERM/SIGINT
- FR-9.3: Resume Command - `--resume <checkpoint_file>`

**FR-13: Phase 13 Vulnerability Intelligence** (Priority: P0, Phase: 13)
- FR-13.1: Persistent Storage Backend - SQLite/PostgreSQL for target addresses
- FR-13.2: Milk Sad Integration - bx 3.x weak seed identification
- FR-13.3: ECDSA Nonce Reuse Forensics - signature-based key recovery
- FR-13.4: Brainwallet Passphrase Dictionary - phrase ingestion and address generation
- FR-13.5: WGPU Port - core kernels to WGSL for Metal/Vulkan/DX12

### Non-Functional Requirements

**NFR-1: Performance** (Priority: P0 - Critical)
- NFR-1.1: GPU Acceleration - 10x minimum (Phase 1), 50-100x target (Phase 2)
- NFR-1.2: Scan Completion Time - <30 min/wallet (Phase 1), <10 min (Phase 2), <5 min (Phase 3)
- NFR-1.3: Throughput - 100M-1B seeds/sec (Phase 1), 1B-10B (Phase 2), 10B+ (Phase 3)
- NFR-1.4: Resource Usage - <8GB RAM, <4GB VRAM, <1GB disk
- NFR-1.5: Scalability - >80% efficiency per additional GPU

**NFR-2: Accuracy & Reliability** (Priority: P0 - Critical)
- NFR-2.1: False Negative Rate - <5% target, <10% maximum
- NFR-2.2: False Positive Rate - <1% target, <2% maximum
- NFR-2.3: Test Vector Validation - 100% match on disclosure examples
- NFR-2.4: Reproducibility - identical results across runs
- NFR-2.5: Error Handling - no crashes, graceful degradation

**NFR-3: Security & Ethics** (Priority: P0 - Critical)
- NFR-3.1: No Private Key Exposure - GPU local memory only, secure clearing
- NFR-3.2: White-Hat Only - no fund transfer capability
- NFR-3.3: Data Privacy - local execution only, no telemetry
- NFR-3.4: Code Security - Rust memory safety, security audit

**NFR-4: Usability** (Priority: P1 - High)
- NFR-4.1: CLI Clarity - clear help, intuitive naming
- NFR-4.2: Progress Transparency - real-time updates, ETA
- NFR-4.3: Documentation - README, tech docs, examples
- NFR-4.4: Error Messages - clear, actionable

**NFR-5: Maintainability** (Priority: P1 - High)
- NFR-5.1: Code Quality - Rust 2021, cargo fmt, clippy
- NFR-5.2: Testing - >80% coverage
- NFR-5.3: Modularity - scanner patterns, reusable components
- NFR-5.4: Documentation - doc comments, architecture docs

**NFR-6: Portability** (Priority: P1 - High)
- NFR-6.1: Platform Support - Linux, macOS, Windows
- NFR-6.2: GPU Compatibility - NVIDIA, AMD, Intel, CPU fallback
- NFR-6.3: Dependency Management - minimal external deps

**NFR-7: Compliance & Legal** (Priority: P0 - Critical)
- NFR-7.1: Open Source Licensing - compatible with project license
- NFR-7.2: Responsible Disclosure Compliance - 90-day window
- NFR-7.3: Legal Review - counsel review before release

**NFR-13: Phase 13 Performance** (Priority: P0, Phase: 13)
- NFR-13.1: Target Address Lookup - <10ms for 1,000,000+ targets
- NFR-13.2: Target Indexing - support 1,000,000+ addresses
- NFR-13.3: WGPU Performance - >30,000 keys/sec on Apple Metal

### Additional Requirements

**From Architecture:**
- Unified Shader Bridge: Standardized trait between OpenCL and WGPU with 100% logic parity
- Fixed-Point Bitwise Integers Only: No floats/doubles in scanner kernels (prevent driver divergence)
- Dual-Execution Cross-Check: GPU hits auto-verified by CPU Golden Reference
- Bit-Perfect CI Lock: 100% bit-parity between CPU/GPU required in CI
- Endianness & Alignment Standard: All shared structs must be `#[repr(C)]` with u32 fields
- Double-Buffered GPU Synchronization: Staging buffers with explicit fences
- Zero-Copy DMZ: Specific memory regions for Rust/GPU buffer mapping via bytemuck
- Progress-Aware Scanner Trait: Interface for real-time ETA reporting

**From PRD Implementation Guidance:**
- File Structure: `src/scans/randstorm.rs`, `cl/randstorm_crack.cl`
- GPU Integration Pattern: Follow `compute_trust_wallet_crack()` in `gpu_solver.rs`
- Timestamp Search: ±24h window, 172,800 timestamps × 100 fingerprints = 17.28M combinations
- Security: Private keys in GPU `__local` memory only, CPU uses `zeroize` crate

**From Tech Specs:**
- MWC1616 Algorithm: s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16), s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
- ARC4 Pool: 256 Math.random() calls to initialize pool
- Database Backend: rusqlite for Phase 13 target intelligence
- WGSL Port: MWC1616 + SHA256 + RIPEMD160 for WGPU

**Testing Strategy (from PRD):**
- 3-Tier Risk Classification: Critical (PRNG, GPU/CPU parity, key non-materialization), High (address derivation, fingerprint loading), Medium (CSV validation, progress reporting)
- Test Pyramid: 100+ unit, 20 integration, 5 E2E tests
- CI Pipeline: Pre-commit hooks, PR checks, merge to main, weekly/release
- Quality Gates: Pre-merge (all tests pass), Pre-release (GPU tests, security audit, performance benchmarks)

### FR Coverage Map

| FR # | Epic | Description |
|------|------|-------------|
| FR-1.1 | Epic 1 | Chrome V8 PRNG (MWC1616) |
| FR-3.1 | Epic 1 | Pre-BIP32 Direct Derivation (merged) |
| FR-4.1 | Epic 1 | Basic OpenCL Kernel |
| FR-4.2 | Epic 1 | Device-Aware Work Groups |
| FR-4.3 | Epic 1 | Batch Processing |
| FR-4.6 | Epic 1 | CPU Fallback |
| FR-2.1 | Epic 2 | Browser Configuration Schema |
| FR-2.2 | Epic 2 | Top 100 Configurations |
| FR-2.4 | Epic 2 | Configuration Prioritization |
| FR-6.1 | Epic 3 | CLI Subcommand Structure |
| FR-6.2 | Epic 3 | Required Arguments |
| FR-6.3 | Epic 3 | Optional Arguments |
| FR-6.4 | Epic 3 | Progress Reporting |
| FR-6.5 | Epic 3 | Results Output (+ coverage disclaimer) |
| FR-6.6 | Epic 3 | Error Handling |
| FR-5.1 | Epic 4 | Randstorm Test Vectors |
| FR-5.2 | Epic 4 | Integration Tests |
| FR-5.3 | Epic 4 | Performance Benchmarks |
| FR-5.4 | Epic 4 | Regression Tests |
| FR-5.5 | Epic 4 | FP/FN Validation |
| FR-7.1 | Epic 5 | Disclosure Protocol |
| FR-7.2 | Epic 5 | Findings Report Format |
| FR-7.3 | Epic 5 | Private Key Handling (architectural constraint) |
| FR-7.4 | Epic 5 | Ethical Use Guidelines |
| FR-7.5 | Epic 5 | Coordination Support |
| FR-13.1 | Epic 6 | Target Database Backend |
| FR-13.2 | Epic 6 | Milk Sad Integration |
| FR-13.3 | Epic 6 | Nonce Reuse Forensics |
| FR-13.4 | Epic 6 | Brainwallet Pipeline |
| FR-13.5 | Epic 7 | WGPU Port (with OpenCL parity requirement) |

**Coverage:** 30/30 Phase 1+13 FRs mapped (100%)

## Epic List

**Pre-mortem Analysis Applied:** Epic structure refined to prevent sequencing issues, validation gaps, ethics afterthoughts, and WGPU divergence risks.

---

### Epic 1: Core Scanning Engine

**User Outcome:** Security researchers can scan Bitcoin addresses for Chrome V8 PRNG vulnerabilities using GPU acceleration with CPU fallback, producing verified address matches.

**FRs Covered:** FR-1.1, FR-3.1, FR-4.1, FR-4.2, FR-4.3, FR-4.6

**Value Delivered:**
- MWC1616 PRNG reconstruction (exact Chrome V8 constants)
- P2PKH address derivation from PRNG entropy (merged from old Epic 3)
- GPU-accelerated scanning (10x+ speedup)
- Automatic CPU fallback when GPU unavailable
- Data contract for Phase 13 compatibility (scan result output format)

**Architectural Constraints (from Epic 5):**
- Private keys in GPU `__local` memory only
- CPU path uses `zeroize` crate for sensitive buffers
- No private key logging or export

**Hardening Stories (from Red Team analysis):**
- **Story: Define Scan Result Data Contract v1.0**
  - AC: JSON schema published for scan results
  - AC: Breaking changes require major version bump
  - AC: Epic 3 and Epic 6 depend on contract, not implementation
- **Story: Implement PrivateKey Newtype with Zeroize**
  - AC: `PrivateKey` type has no `Display`, `Debug`, or `Serialize` impl
  - AC: CI grep scan rejects any logging call with "privkey" in scope
  - AC: Integration test verifies no private key appears in any log output

**User Feedback Stories (from Focus Group):**
- **Story: Performance SLA Definition** (HIGH priority)
  - AC: Document target throughput: X keys/second on reference hardware
  - AC: Benchmark included in CI with regression detection
  - AC: CLI displays actual keys/sec during scan
  - AC: README includes "Expected scan time for 100 addresses: Y minutes"
- **Story: Fast Mode for High-Probability Configs** (LOW priority)
  - AC: `--fast` flag scans only top 20 fingerprints (highest market share)
  - AC: Output includes warning: "Fast mode - reduced coverage"
  - AC: Estimated 3-5x speedup vs full scan

**Standalone:** Yes - complete scan-to-address pipeline

---

### Epic 2: Browser Fingerprint Intelligence

**User Outcome:** Security researchers can target scans using prioritized browser fingerprint database, testing most likely configurations first for maximum efficiency.

**FRs Covered:** FR-2.1, FR-2.2, FR-2.4

**Value Delivered:**
- Browser configuration schema (UA, screen, timezone, etc.)
- Top 100 fingerprint database (2011-2015 era)
- Market-share prioritization for efficient scanning
- Browser engine field for future Firefox/Safari expansion

**User Feedback Stories (from Focus Group):**
- **Story: Browser Hint Filter** (MEDIUM priority)
  - AC: `--browser-hint <chrome|firefox|safari>` filters fingerprint database
  - AC: `--year-hint <2011-2015>` narrows to fingerprints from that year
  - AC: Hints are combinable: `--browser-hint chrome --year-hint 2013`
  - AC: Invalid hints produce helpful error with valid options
  - AC: Use case: Client remembers "I used Firefox on Ubuntu in 2013"

**Architectural Decisions (from ADR analysis):**
- **ADR-002: Fingerprint Database Override Flag**
  - Decision: Embedded default with optional `--fingerprint-db <path>` override
  - AC: Default fingerprints embedded in binary (works out of box)
  - AC: `--fingerprint-db <path>` loads custom CSV for power users
  - AC: Custom DB validated against schema on load
  - Rationale: Works by default, flexible for researchers testing new configs

**Standalone:** Yes - fingerprint database usable independently; integrates with Epic 1

---

### Epic 3: CLI Interface & Batch Processing

**User Outcome:** Security researchers can use a complete CLI to batch-scan addresses from CSV files with real-time progress, results output, and coverage disclaimers.

**FRs Covered:** FR-6.1, FR-6.2, FR-6.3, FR-6.4, FR-6.5, FR-6.6

**Value Delivered:**
- `entropy-lab scan randstorm [OPTIONS]` subcommand (ADR-006)
- CSV input/output for batch processing
- Real-time progress with ETA
- Clear error handling and help text
- **Coverage disclaimer in output:** "Chrome V8 only - ~29% estimated coverage"

**User Feedback Stories (from Focus Group):**
- **Story: Streaming Output for Large Batches** (MEDIUM priority)
  - AC: Results written incrementally as discovered (not buffered until end)
  - AC: Memory usage stays constant regardless of input size
  - AC: Supports 10M+ address inputs without OOM
  - AC: `--output-mode streaming` enables line-by-line output
  - AC: Use case: Exchange scanning millions of customer addresses
- **Story: Quiet/JSON Mode for Scripting** (LOW priority)
  - AC: `--quiet` suppresses progress bars and disclaimers
  - AC: `--format json` outputs machine-parseable JSON per line (JSONL)
  - AC: Errors go to stderr, results to stdout
  - AC: Exit code indicates success/failure for automation

**Architectural Decisions (from ADR analysis):**
- **ADR-004: Configurable Error Strictness**
  - Decision: Graceful by default, `--strict` for fail-fast
  - AC: Default: skip invalid CSV rows with warning, continue scanning
  - AC: `--strict` flag: fail immediately on first error
  - AC: Summary at end shows count of skipped rows with reasons
  - Rationale: Large batch friendly by default, strict mode for reproducibility
- **ADR-006: CLI Command Structure**
  - Decision: `entropy-lab scan randstorm` (grouped under scan subcommand)
  - AC: `entropy-lab scan --help` lists all available scanners
  - AC: Tab completion works naturally with nested structure
  - Rationale: Scales well as scanner count grows, discoverable

**Dependencies:** Requires Epic 1 (scanning) and Epic 2 (fingerprints) to be stable

**Standalone:** Yes - complete user interface to scanner capabilities

---

### Epic 4: Release Certification & Validation

**User Outcome:** Security researchers can trust scanner accuracy through validated test vectors, verified GPU/CPU parity, and performance benchmarks meeting release criteria.

**FRs Covered:** FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-5.5

**Value Delivered:**
- 100% validation on Randstorm disclosure test vectors
- GPU/CPU bit-parity verification (mandatory for release)
- Performance benchmarks (10x GPU speedup gate)
- Regression tests for existing 18 scanners
- <1% FP, <5% FN certification

**Hardening Stories (from Red Team analysis):**
- **Story: Test Vector Cross-Validation**
  - AC: Vectors validated against 3 independent sources (Unciphered disclosure, CryptoDeepTools Python, synthetic wallet)
  - AC: Synthetic wallet generated with known seed, scanned successfully
  - AC: Vector provenance documented (source, date, verification method)
  - AC: No "validation theater" - vectors are independently verified, not assumed correct

**User Feedback Stories (from Focus Group):**
- **Story: Deterministic/Reproducible Builds** (HIGH priority)
  - AC: `Cargo.lock` committed and pinned for all dependencies
  - AC: `--seed <N>` flag for deterministic PRNG initialization in tests
  - AC: Same inputs + same seed = byte-identical outputs across machines
  - AC: Build instructions include exact Rust toolchain version
  - AC: Use case: Academic researchers reproducing results for peer review
- **Story: Scanner Isolation Test** (LOW priority)
  - AC: Adding new scanner cannot affect existing scanner outputs
  - AC: CI test runs all scanners before/after new scanner addition
  - AC: Output diff must be empty for unrelated scanners

**Architectural Decisions (from ADR analysis):**
- **ADR-005: Test Data Management**
  - Decision: Test vectors in-repo with schema versioning
  - AC: Vectors stored in `tests/fixtures/randstorm_vectors.json`
  - AC: Schema includes `version` field for future migration
  - AC: Each vector includes provenance (source, date, verification method)
  - Rationale: Simple for Phase 1, scalable pattern for growth

**Quality Gate:** This epic serves as release certification - blocks release until all criteria pass

**Standalone:** Yes - validation gate for all prior epics

---

### Epic 5: Ethical Framework & Documentation (Parallel Track)

**User Outcome:** Security researchers have proper ethical guidelines, disclosure protocols, and documentation for responsible use from day one.

**FRs Covered:** FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5

**Value Delivered:**
- Responsible disclosure documentation (90-day window)
- Findings report templates
- SECURITY.md with legal warnings
- Ethical use guidelines and disclaimers
- Exchange/wallet owner notification templates

**Execution Note:** This epic runs in PARALLEL starting Sprint 1, not after code epics complete. Security constraints (FR-7.3) are architectural and embedded in Epic 1.

**Sprint-Gated Deliverables (from Red Team analysis):**
| Sprint | Required Deliverable |
|--------|---------------------|
| Sprint 1 | SECURITY.md skeleton with legal warnings |
| Sprint 2 | Disclosure protocol documentation |
| Sprint 3 | Legal review STARTED (not completed) |
| Sprint 4 | Report templates finalized |
| Release Gate | Legal sign-off received |

**Constraint:** One Epic 5 story must complete per sprint - documentation is not optional.

**User Feedback Stories (from Focus Group):**
- **Story: Client-Facing Vulnerability Guide** (MEDIUM priority)
  - AC: Non-technical document: "What to do if your wallet is vulnerable"
  - AC: Plain language, no jargon, actionable steps
  - AC: Includes: Don't panic, secure funds, report to exchange, timeline
  - AC: PDF-exportable for wallet recovery specialists to share with clients
  - AC: Use case: Raj sends guide to grandmother who lost savings
- **Story: Audit Trail for Compliance** (LOW priority)
  - AC: Optional `--audit-log <file>` records all scan operations
  - AC: Log includes: timestamp, user, addresses scanned, results, duration
  - AC: Log is append-only, tamper-evident (hash chain)
  - AC: Use case: Exchange proving to regulators they scanned for vulnerabilities

**Standalone:** Yes - documentation framework independent of code delivery

---

### Epic 6: Target Intelligence Infrastructure (Phase 13)

**User Outcome:** Security researchers can maintain persistent target databases and apply specialized vulnerability detection (Milk Sad, nonce reuse, brainwallet).

**FRs Covered:** FR-13.1, FR-13.2, FR-13.3, FR-13.4

**Value Delivered:**
- SQLite target database (1M+ addresses, <10ms lookup)
- Milk Sad weak seed detection
- ECDSA nonce reuse forensics
- Brainwallet passphrase scanning

**Data Contract:** Uses scan result format from Epic 1 for database ingestion

**Hardening Stories (from Red Team analysis):**
- **Story: Vulnerability Scanner Isolation**
  - AC: `VulnerabilityClass` enum with distinct variants (`Randstorm`, `MilkSad`, `NonceReuse`, `Brainwallet`)
  - AC: Each scanner validates only its own test vectors
  - AC: Database schema includes `vuln_class` column with constraint
  - AC: CLI `--vuln-type` flag prevents accidental cross-scanning
  - AC: No cross-contamination of vulnerability classifications

**Standalone:** Yes - builds on Phase 1 foundation; requires Epic 1 data contract

---

### Epic 7: Cross-Platform GPU via WGPU (Phase 13)

**User Outcome:** Security researchers on Apple Silicon and other platforms can use native GPU acceleration via Metal/Vulkan/DX12 with guaranteed result parity.

**FRs Covered:** FR-13.5

**Value Delivered:**
- WGSL ports of MWC1616, SHA256, RIPEMD160 kernels
- Native Apple Metal support
- Cross-platform GPU compatibility (Vulkan, DX12)

**Parity Requirement:** 100% bit-identical output to OpenCL backend (mandatory AC)

**Hardening Stories (from Red Team analysis):**
- **Story: WGPU Parity CI Gate**
  - AC: CI runs 10,000 seeds through both OpenCL and WGPU backends
  - AC: Any bit divergence = build failure, merge blocked
  - AC: Feature flag `wgpu` can be disabled to ship OpenCL-only if parity unachievable
  - AC: **NO `--allow-divergence` flag exists in codebase** (escape hatch forbidden)
  - AC: Parity test runs on every PR touching GPU code

**Architectural Decisions (from ADR analysis):**
- **ADR-001: GPU Backend Strategy**
  - Decision: Separate implementations with mandatory parity CI gate
  - AC: OpenCL and WGPU are separate codebases with shared test vectors
  - AC: WGPU feature-flagged, disabled if parity unachievable
  - Rationale: Ship Phase 1 fast with OpenCL, WGPU gated by parity in Phase 13

**Standalone:** Yes - alternative GPU backend; OpenCL remains functional

---

## Architectural Decision Record Summary

| ADR | Decision | Applied To |
|-----|----------|------------|
| ADR-001 | Separate GPU backends + parity gate | Epic 7 |
| ADR-002 | Embedded fingerprints + override flag | Epic 2 |
| ADR-004 | Graceful errors by default, `--strict` option | Epic 3 |
| ADR-005 | Test vectors in-repo with schema version | Epic 4 |
| ADR-006 | `entropy-lab scan randstorm` CLI structure | Epic 3 |

