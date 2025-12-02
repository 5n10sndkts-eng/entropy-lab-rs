// Helper functions for BIP39 mnemonic generation
// These are used by batch_address.cl for Milk Sad and Dart PRNG paths

// Generate BIP39 mnemonic from entropy
// Returns the length of the mnemonic string
static inline int generate_mnemonic(__private uchar* entropy, int entropy_len, __private uchar* mnemonic) {
    // Hash entropy for checksum
    uint entropy_hash_buf[8] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, entropy_len, entropy_hash_buf);
    uchar checksum = (((uchar*)entropy_hash_buf)[0] >> 4) & 0xF;
    
    // Convert entropy to word indices
    ulong mnemonic_lo = 0;
    ulong mnemonic_hi = 0;
    
    for(int i=0; i<8; i++) mnemonic_lo |= ((ulong)entropy[i]) << (i*8);
    for(int i=0; i<8; i++) mnemonic_hi |= ((ulong)entropy[i+8]) << (i*8);
    
    ushort indices[12];
    indices[0] = (mnemonic_hi >> 53) & 2047;
    indices[1] = (mnemonic_hi >> 42) & 2047;
    indices[2] = (mnemonic_hi >> 31) & 2047;
    indices[3] = (mnemonic_hi >> 20) & 2047;
    indices[4] = (mnemonic_hi >> 9)  & 2047;
    indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
    indices[6] = (mnemonic_lo >> 51) & 2047;
    indices[7] = (mnemonic_lo >> 40) & 2047;
    indices[8] = (mnemonic_lo >> 29) & 2047;
    indices[9] = (mnemonic_lo >> 18) & 2047;
    indices[10] = (mnemonic_lo >> 7) & 2047;
    indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;
    
    // Build mnemonic string
    int mnemonic_index = 0;
    for (int i=0; i < 12; i++) {
        int word_index = indices[i];
        int word_length = word_lengths[word_index];
        
        for(int j=0; j<word_length; j++) {
            mnemonic[mnemonic_index++] = words[word_index][j];
        }
        mnemonic[mnemonic_index++] = 32; // space
    }
    mnemonic[mnemonic_index - 1] = 0; // null terminate
    
    // Calculate actual length
    int len = 11; // 11 spaces
    for(int i=0; i<12; i++) len += word_lengths[indices[i]];
    
    return len;
}

// BIP39 Mnemonic to Seed (PBKDF2-HMAC-SHA512)
static inline void mnemonic_to_seed(__private uchar* mnemonic, int mnemonic_len, __private uchar* seed) {
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for(int x=0;x<128;x++){
        ipad_key[x] = 0x36;
        opad_key[x] = 0x5c;
    }

    for(int x=0;x<mnemonic_len;x++){
        ipad_key[x] = ipad_key[x] ^ mnemonic[x];
        opad_key[x] = opad_key[x] ^ mnemonic[x];
    }

    uchar sha512_result[64] __attribute__((aligned(4))) = { 0 };
    uchar key_previous_concat[256] __attribute__((aligned(4))) = { 0 };
    uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 };
    
    for(int x=0;x<128;x++){
        key_previous_concat[x] = ipad_key[x];
    }
    for(int x=0;x<12;x++){
        key_previous_concat[x+128] = salt[x];
    }

    sha512((__private ulong*)key_previous_concat, 140, (__private ulong*)sha512_result);
    copy_pad_previous(opad_key, sha512_result, key_previous_concat);
    sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
    xor_seed_with_round((__private char*)seed, (__private char*)sha512_result);

    for(int x=1;x<2048;x++){
        copy_pad_previous(ipad_key, sha512_result, key_previous_concat);
        sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
        copy_pad_previous(opad_key, sha512_result, key_previous_concat);
        sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
        xor_seed_with_round((__private char*)seed, (__private char*)sha512_result);
    }
}
