# Implementation Plan: Closing Critical Gaps

**Date:** 2025-12-12
**Branch:** claude/swot-analysis-gaps-019uXNfjt2iXXM4NttULUtEn

---

## Priority 1: Electrum Seed Validation (CRITICAL)

**Status:** ✅ Utilities exist, need integration
**Effort:** 1-2 days
**Impact:** Fixes 99.6% false positive rate

### Current State
- ✅ `src/utils/electrum.rs` has complete validation utilities
- ❌ Not used in Cake Wallet scanners
- ❌ No validation in seed generation workflow

### Implementation
1. Modify `src/scans/cake_wallet.rs` to use validation
2. Modify `src/scans/cake_wallet_dart_prng.rs` to use validation
3. Modify `src/scans/cake_wallet_targeted.rs` to use validation
4. Update GPU kernels to skip invalid seeds
5. Add tests to verify validation

---

## Priority 2: Extended Address Index Support (HIGH)

**Status:** ❌ Not implemented
**Effort:** 3-4 days
**Impact:** 18x coverage improvement (5% → 90%)

### Current State
- All scanners only check index 0
- Missing 95%+ of addresses per seed

### Implementation
1. Create `src/utils/address_indices.rs` module
2. Add `--max-index` parameter to CLI
3. Modify scanners to iterate indices
4. GPU kernel updates for batch index generation
5. Add bloom filter optimization

---

## Priority 3: Multi-Path Derivation (HIGH)

**Status:** ⚠️ Partial (some scanners support it)
**Effort:** 4-5 days
**Impact:** 4x efficiency, complete coverage

### Current State
- Milk Sad has `--multipath` flag
- Other scanners don't support it

### Implementation
1. Create `src/utils/multi_path.rs` module
2. Add universal `--all-paths` CLI flag
3. Update all scanners to support multiple paths
4. GPU kernel updates for multi-path

---

## Priority 4: Randstorm/BitcoinJS Scanner (CRITICAL)

**Status:** ❌ Not implemented
**Effort:** 8-12 weeks (multi-phase)
**Impact:** 1.4M+ BTC coverage

### Current State
- Completely missing
- Highest value vulnerability

### Implementation (Phase 1 - MVP)
1. Create `src/scans/randstorm.rs` module
2. Implement V8 MWC1616 PRNG
3. Implement state → entropy → address pipeline
4. Basic CPU scanner
5. Tests with known vectors

---

## Implementation Order

### Week 1-2: Quick Wins
- ✅ Day 1-2: Electrum validation integration
- ✅ Day 3-5: Extended address indices
- ✅ Day 6-10: Multi-path derivation

### Week 3-4: Foundation
- Day 11-14: Randstorm research and design
- Day 15-20: Randstorm MVP implementation

### Week 5-8: Completion
- Day 21-30: Randstorm GPU acceleration
- Day 31-40: Testing and optimization
- Day 41-50: Documentation and release

---

## Success Metrics

**Coverage Improvement:**
- Address Space: 5% → 90% (+1700%)
- Vulnerability Coverage: 60% → 100% (+67%)
- Scanner Completeness: 13/14 → 14/14 (100%)

**Technical Metrics:**
- Electrum false positive rate: 99.6% → 0%
- Scanning efficiency: 4x improvement (multi-path)
- Research completeness: Industry-leading

---

## Risk Mitigation

**Electrum Validation:**
- Low risk, high impact
- Utilities already exist
- Quick win

**Extended Indices:**
- Medium complexity
- Performance considerations (bloom filters)
- GPU memory constraints

**Randstorm:**
- High complexity
- Requires deep research
- Multi-phase approach reduces risk

---

**Next Step:** Begin Electrum validation integration
