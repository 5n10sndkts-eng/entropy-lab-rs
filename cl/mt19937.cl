// MT19937 Implementation for OpenCL
// Based on standard implementation

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

void mt19937_init(uint seed, __private uint* state) {
    state[0] = seed;
    for (int i = 1; i < MT_N; i++) {
        state[i] = (1812433253UL * (state[i-1] ^ (state[i-1] >> 30)) + i);
    }
}

void mt19937_twist(__private uint* state) {
    for (int i = 0; i < MT_N; i++) {
        uint x = (state[i] & MT_UPPER_MASK) | (state[(i+1) % MT_N] & MT_LOWER_MASK);
        uint y = x >> 1;
        if (x & 1) {
            y ^= MT_MATRIX_A;
        }
        state[i] = state[(i + MT_M) % MT_N] ^ y;
    }
}

// Extract first 4 words (128 bits) - MSB extraction (for Milk Sad/libbitcoin)
void mt19937_extract_128(uint seed, __private uint* output) {
    uint state[MT_N];
    
    // 1. Initialize
    mt19937_init(seed, state);
    
    // 2. Twist (generate first batch)
    mt19937_twist(state);
    
    // 3. Temper and extract first 4 words
    for (int i = 0; i < 4; i++) {
        uint y = state[i];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);
        output[i] = y;
    }
}

// Extract 16 words for LSB extraction (for Trust Wallet)
// Trust Wallet takes only the LSB (least significant byte) from each word
// See: CVE-2023-31290
void mt19937_extract_128_lsb(uint seed, __private uint* output) {
    uint state[MT_N];
    
    // 1. Initialize
    mt19937_init(seed, state);
    
    // 2. Twist (generate first batch)
    mt19937_twist(state);
    
    // 3. Temper and extract first 16 words (need 16 for 16 bytes of entropy)
    for (int i = 0; i < 16; i++) {
        uint y = state[i];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);
        output[i] = y;  // Caller will extract LSB: output[i] & 0xFF
    }
}
