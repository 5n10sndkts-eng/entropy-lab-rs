# Gap Analysis Summary: Entropy Lab RS vs milksad.info

**Date:** 2025-12-06  
**Analysis Version:** 2.0  
**Comparison Source:** https://milksad.info/disclosure.html and related research

---

## Executive Summary

This document provides a high-level summary of the gap analysis comparing the entropy-lab-rs codebase against the comprehensive vulnerability research documented at milksad.info. The full technical details are available in [MILKSAD_GAP_ANALYSIS.md](MILKSAD_GAP_ANALYSIS.md).

### Current Implementation Status

**✅ Implemented (7 scanners):**
1. Libbitcoin "Milk Sad" (CVE-2023-39910) - MT19937 timestamp-based
2. Trust Wallet Browser Extension (CVE-2023-31290) - MT19937 
3. Cake Wallet Dart PRNG - Time-based weak entropy (2020-2021)
4. Android SecureRandom - Duplicate R value detection
5. Mobile Sensor Entropy - Weak PRNG simulation
6. Malicious Extension - Browser extension simulation
7. Profanity - Vanity address (stub/incomplete)

**❌ Critical Missing (3 major vulnerability classes):**
1. **Randstorm/BitcoinJS (2011-2015)** - Affects 1.4M+ BTC, $1B+ at risk
2. **Trust Wallet iOS (CVE-2024-23660)** - minstd_rand0 LCG variant
3. **bip3x Library** - PCG-XSH-RR PRNG vulnerability

---

## Top 5 Critical Gaps

### 1. 🔴 Randstorm/BitcoinJS Scanner Missing (HIGHEST PRIORITY)

**What it is:** Vulnerability in web-based Bitcoin wallets from 2011-2015 using weak JavaScript entropy  
**Affected platforms:** Blockchain.info, CoinPunk, BrainWallet, QuickCoin, Bitgo, BitPay  
**Impact:** Estimated 1.4M+ BTC at risk (over $1 billion in assets)  
**Root cause:** Math.random() + JSBN SecureRandom with less than 48 bits of entropy  
**Current status:** NO scanner implemented  
**Priority:** HIGHEST - Largest impact of all vulnerabilities

### 2. 🔴 Electrum Seed Validation Missing (CRITICAL)

**What it is:** Cake Wallet uses Electrum seed format requiring specific HMAC-SHA512 prefix  
**Impact:** Current scanner may generate invalid seeds that Cake Wallet never used  
**Problem:** Search space 4096x larger than it should be  
**Result:** False positives or missing real vulnerable wallets  
**Current status:** No validation implemented  
**Priority:** CRITICAL - Affects accuracy of existing Cake Wallet scanner

### 3. 🔴 Trust Wallet iOS Variant Missing (HIGH)

**What it is:** CVE-2024-23660 - iOS app using minstd_rand0 LCG PRNG  
**Difference:** Completely different PRNG from browser extension (which IS implemented)  
**Impact:** Missing entire class of vulnerable iOS Trust Wallet users  
**Algorithm:** Linear Congruential Generator with a=16807, m=2^31-1  
**Current status:** Only browser extension variant implemented  
**Priority:** HIGH - Separate vulnerability affecting iOS users

### 4. 🔴 Single-Path, Single-Index Limitation (HIGH)

**What it is:** Most scanners only check one derivation path and address index 0  
**Impact:** Missing ~95%+ of addresses per seed  
**What's missing:**
- Multi-path derivation (BIP44/49/84/86)
- Extended address indices (should check 0-19 minimum, 0-100+ for Cake)
- Change addresses (m/x'/1/y paths)
- Uncompressed public keys

**Current status:** Limited to single path, index 0, compressed keys only  
**Priority:** HIGH - Dramatically reduces coverage for ALL scanners

### 5. 🟠 No Bloom Filter Support (MEDIUM)

**What it is:** Efficient filtering mechanism for large-scale scanning  
**Impact:** Current approach doesn't scale well  
**Dataset:** Loyce.club provides all funded Bitcoin addresses  
**Benefit:** Dramatically reduces RPC load, enables faster scanning  
**Current status:** Not implemented  
**Priority:** MEDIUM - Essential for production-scale scanning

---

## Impact Assessment

### By Vulnerability Coverage

| Vulnerability Class | Status | Estimated Wallets | Potential Value |
|---------------------|--------|-------------------|-----------------|
| Randstorm/BitcoinJS (2011-2015) | ❌ Missing | Millions | $1B+ |
| Libbitcoin Milk Sad | ✅ Implemented | 300K+ | $900K stolen |
| Trust Wallet Browser | ✅ Implemented | Unknown | Multiple exploits |
| Trust Wallet iOS | ❌ Missing | Unknown | July 2023 exploits |
| Cake Wallet Dart PRNG | ⚠️ Partial | 8,757 | 548+ BTC |
| Profanity | ⚠️ Incomplete | Unknown | $3.3M+ stolen |
| Android SecureRandom | ✅ Implemented | Historic | 2013 vulnerability |
| bip3x Library | ❌ Missing | Some JS wallets | Unknown |

### By Feature Coverage

| Feature | Status | Impact | Priority |
|---------|--------|--------|----------|
| Multi-path derivation | ❌ Missing | High | HIGH |
| Extended address indices | ❌ Missing | High | HIGH |
| Electrum seed validation | ❌ Missing | High | CRITICAL |
| Change addresses | ❌ Missing | Medium | MEDIUM |
| Uncompressed keys | ❌ Missing | Medium | MEDIUM |
| Multiple seed lengths (18/24 words) | ❌ Missing | Medium | MEDIUM |
| Bloom filter | ❌ Missing | High (scale) | MEDIUM |
| Taproot (P2TR) | ❌ Missing | Low | LOW |

---

## Recommended Implementation Roadmap

### Phase 1: Critical Fixes (1-2 weeks)
1. 🔲 **Randstorm/BitcoinJS scanner** (HIGHEST PRIORITY)
   - Implement weak Math.random() + JSBN emulation
   - Scan 2011-2015 timeframe
   - Support compressed and uncompressed keys
   - Check P2PKH, P2SH, P2WPKH formats

2. 🔲 **Electrum seed validation** (CRITICAL)
   - Add HMAC-SHA512 prefix check for Cake Wallet
   - Fix entropy generation to match Electrum format
   - Validate against "Seed version" with "100" prefix

### Phase 2: High Priority Features (2-3 weeks)
3. 🔲 **Trust Wallet iOS scanner** (HIGH)
   - Implement minstd_rand0 LCG PRNG
   - Scan July 2023 timeframe
   - Add CVE-2024-23660 coverage

4. 🔲 **Multi-path derivation** (HIGH)
   - Implement BIP44, BIP49, BIP84, BIP86 paths
   - Add P2SH-SegWit (3xxx) addresses
   - Add Native SegWit (bc1q) addresses
   - Add Taproot (bc1p) addresses

5. 🔲 **Extended address scanning** (HIGH)
   - Scan indices 0-19 (BIP44 gap limit) minimum
   - Scan 0-100+ for Cake Wallet
   - Add change address support (m/x'/1/y)

### Phase 3: Medium Priority (3-4 weeks)
6. 🔲 **Bloom filter integration** (MEDIUM)
   - Download and process Loyce.club dataset
   - Implement efficient bloom filter
   - Integrate with all scanners

7. 🔲 **bip3x PCG scanner** (MEDIUM)
   - Implement PCG-XSH-RR algorithm
   - Scan JavaScript wallet implementations

8. 🔲 **Multiple seed lengths** (MEDIUM)
   - Support 18-word seeds (192 bits) - bx default
   - Support 24-word seeds (256 bits)
   - Support 15 and 21-word variants

### Phase 4: Completeness (4-6 weeks)
9. 🔲 **Complete Profanity implementation**
10. 🔲 **Add uncompressed key support**
11. 🔲 **Comprehensive test suite**
12. 🔲 **Documentation updates**

---

## Quick Reference: What's Missing

### Missing Vulnerability Scanners
- ❌ Randstorm/BitcoinJS (2011-2015) - BIGGEST GAP
- ❌ Trust Wallet iOS minstd_rand0
- ❌ bip3x Library PCG PRNG
- ⚠️ Profanity (incomplete)

### Missing Features
- ❌ Electrum seed validation (breaks Cake Wallet)
- ❌ Multi-path derivation (BIP44/49/84/86)
- ❌ Extended address indices (only checks index 0)
- ❌ Change addresses (m/x'/1/y)
- ❌ Uncompressed public keys
- ❌ 18/24-word seeds
- ❌ Bloom filter for scalability
- ❌ Taproot/BIP86 addresses

### What Works Well
- ✅ GPU acceleration (OpenCL)
- ✅ Libbitcoin Milk Sad scanner
- ✅ Trust Wallet browser scanner (fixed LSB extraction)
- ✅ Cake Wallet Dart PRNG scanner
- ✅ Android SecureRandom scanner
- ✅ RPC integration
- ✅ CSV verification
- ✅ Project structure and build system

---

## Metrics

**Total Gaps Identified:** 21  
**Critical Gaps:** 5  
**High Priority Gaps:** 7  
**Medium Priority Gaps:** 7  
**Low Priority Gaps:** 2  

**Estimated Implementation Effort:**
- Phase 1 (Critical): 1-2 weeks
- Phase 2 (High): 2-3 weeks  
- Phase 3 (Medium): 3-4 weeks
- Phase 4 (Complete): 4-6 weeks
- **Total:** 10-15 weeks for full feature parity

**Estimated Impact of Fixes:**
- Randstorm scanner alone: $1B+ in potentially at-risk assets
- All fixes combined: Comprehensive coverage of known weak wallet vulnerabilities
- Feature completeness: 90%+ coverage of milksad.info documented attack vectors

---

## Resources

- **Full Technical Analysis:** [MILKSAD_GAP_ANALYSIS.md](MILKSAD_GAP_ANALYSIS.md)
- **Project README:** [README.md](README.md)
- **Milksad.info:** https://milksad.info/
- **Research Updates:** https://milksad.info/posts/
- **Data Repository:** https://git.distrust.co/milksad/data

---

## Conclusion

The entropy-lab-rs project has a solid foundation with GPU acceleration and several working vulnerability scanners. However, **the most critical vulnerability class (Randstorm/BitcoinJS) affecting the largest number of wallets is completely missing**. 

**Immediate action items:**
1. Implement Randstorm/BitcoinJS scanner (highest impact)
2. Fix Electrum seed validation (breaks current Cake scanner)
3. Add Trust Wallet iOS variant
4. Implement multi-path and extended index scanning

With these implementations, the project would achieve comprehensive coverage of the major wallet vulnerabilities documented by the Milk Sad research team.

---

**For detailed technical specifications and implementation guidance, see [MILKSAD_GAP_ANALYSIS.md](MILKSAD_GAP_ANALYSIS.md).**
