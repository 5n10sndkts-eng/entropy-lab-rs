// SHA-512 implementation for OpenCL
// Required for PBKDF2-HMAC-SHA512 in BIP39

#define SHA512_ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHA512_SHR(x, n)  ((x) >> (n))

#define SHA512_Ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SHA512_Sigma0(x) (SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^ SHA512_ROTR(x, 39))
#define SHA512_Sigma1(x) (SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^ SHA512_ROTR(x, 41))
#define SHA512_sigma0(x) (SHA512_ROTR(x, 1)  ^ SHA512_ROTR(x, 8)  ^ SHA512_SHR(x, 7))
#define SHA512_sigma1(x) (SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ SHA512_SHR(x, 6))

__constant ulong sha512_k[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

static void sha512_transform(__private ulong* state, const __private uchar* data) {
    ulong W[80];
    ulong a, b, c, d, e, f, g, h;
    ulong T1, T2;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        W[i] = ((ulong)data[i*8] << 56) | ((ulong)data[i*8+1] << 48) |
               ((ulong)data[i*8+2] << 40) | ((ulong)data[i*8+3] << 32) |
               ((ulong)data[i*8+4] << 24) | ((ulong)data[i*8+5] << 16) |
               ((ulong)data[i*8+6] << 8) | ((ulong)data[i*8+7]);
    }
    
    for (int i = 16; i < 80; i++) {
        W[i] = SHA512_sigma1(W[i-2]) + W[i-7] + SHA512_sigma0(W[i-15]) + W[i-16];
    }
    
    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Main loop
    for (int i = 0; i < 80; i++) {
        T1 = h + SHA512_Sigma1(e) + SHA512_Ch(e, f, g) + sha512_k[i] + W[i];
        T2 = SHA512_Sigma0(a) + SHA512_Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    
    // Add to state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Complete SHA-512 hash function
static void sha512_gpu(const uchar* data, uint len, uchar* hash) {
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    
    uchar buffer[128];
    uint buflen = 0;
    ulong bitlen = 0;
    
    // Process data in 128-byte blocks
    for (uint i = 0; i < len; i++) {
        buffer[buflen++] = data[i];
        if (buflen == 128) {
            sha512_transform(state, buffer);
            bitlen += 1024;
            buflen = 0;
        }
    }
    
    // Padding
    bitlen += buflen * 8;
    buffer[buflen++] = 0x80;
    
    // If not enough room for length, process block and start new one
    if (buflen > 112) {
        while (buflen < 128) buffer[buflen++] = 0;
        sha512_transform(state, buffer);
        buflen = 0;
    }
    
    // Pad with zeros
    while (buflen < 112) buffer[buflen++] = 0;
    
    // Append length as 128-bit big-endian
    for (int i = 0; i < 8; i++) buffer[buflen++] = 0; // High 64 bits
    for (int i = 0; i < 8; i++) {
        buffer[buflen++] = (bitlen >> (56 - i*8)) & 0xFF; // Low 64 bits
    }
    
    sha512_transform(state, buffer);
    
    // Output hash as big-endian bytes
    for (int i = 0; i < 8; i++) {
        hash[i*8]   = (state[i] >> 56) & 0xFF;
        hash[i*8+1] = (state[i] >> 48) & 0xFF;
        hash[i*8+2] = (state[i] >> 40) & 0xFF;
        hash[i*8+3] = (state[i] >> 32) & 0xFF;
        hash[i*8+4] = (state[i] >> 24) & 0xFF;
        hash[i*8+5] = (state[i] >> 16) & 0xFF;
        hash[i*8+6] = (state[i] >> 8) & 0xFF;
        hash[i*8+7] = state[i] & 0xFF;
    }
}

// HMAC-SHA512 implementation
static void hmac_sha512(
    const uchar* key, uint key_len,
    const uchar* data, uint data_len,
    uchar* output
) {
    uchar k_ipad[128 + 256]; // key XOR ipad + data
    uchar k_opad[128 + 64];  // key XOR opad + inner_hash
    uchar key_buf[128];
    uchar inner_hash[64];
    
    // Prepare key
    for (int i = 0; i < 128; i++) key_buf[i] = 0;
    
    if (key_len <= 128) {
        for (uint i = 0; i < key_len; i++) {
            key_buf[i] = key[i];
        }
    } else {
        // If key > block size, hash it first
        sha512_gpu(key, key_len, key_buf);
    }
    
    // Inner: SHA512((key XOR ipad) || data)
    for (int i = 0; i < 128; i++) {
        k_ipad[i] = key_buf[i] ^ 0x36;
    }
    for (uint i = 0; i < data_len && i < 256; i++) {
        k_ipad[128 + i] = data[i];
    }
    sha512_gpu(k_ipad, 128 + data_len, inner_hash);
    
    // Outer: SHA512((key XOR opad) || inner_hash)
    for (int i = 0; i < 128; i++) {
        k_opad[i] = key_buf[i] ^ 0x5C;
    }
    for (int i = 0; i < 64; i++) {
        k_opad[128 + i] = inner_hash[i];
    }
    sha512_gpu(k_opad, 192, output);
}
