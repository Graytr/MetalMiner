// NexaPow kernels, part 2 of 4: SHA-256, and HMAC-SHA256 as libsecp256k1's RFC6979 nonce function uses it.

constant uint NP_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
constant uint NP_IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static inline uint np_rotr(uint x, uint n) { return rotate(x, 32u - n); }

// One compression of the 16-word block w (clobbered: it becomes the message schedule) into st.
static inline void np_sha256(thread uint *st, thread uint *w)
{
    uint a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int r = 0; r < 64; r += 16) {
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            uint t1 = h + (np_rotr(e, 6) ^ np_rotr(e, 11) ^ np_rotr(e, 25)) + ((e & f) ^ (~e & g)) + NP_K[r + i] + w[i];
            uint t2 = (np_rotr(a, 2) ^ np_rotr(a, 13) ^ np_rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        if (r < 48) {
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                uint x15 = w[(i + 1) & 15], x2 = w[(i + 14) & 15];
                w[i] += (np_rotr(x15, 7) ^ np_rotr(x15, 18) ^ (x15 >> 3)) + w[(i + 9) & 15]
                      + (np_rotr(x2, 17) ^ np_rotr(x2, 19) ^ (x2 >> 10));
            }
        }
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// Digest of a 32-byte message (8 big-endian words), as in sha256(uint256).
static inline void np_sha256_32(thread const uint *m, thread uint *out)
{
    uint w[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = m[i]; out[i] = NP_IV[i]; }
    w[8] = 0x80000000u;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 256;
    np_sha256(out, w);
}

// Chaining states after the (K ^ ipad) and (K ^ opad) blocks of a 32-byte key.
static inline void np_hmac_pads(thread const uint *k, thread uint *ik, thread uint *ok)
{
    uint w[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = k[i] ^ 0x36363636u; w[i + 8] = 0x36363636u; ik[i] = NP_IV[i]; }
    np_sha256(ik, w);
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = k[i] ^ 0x5c5c5c5cu; w[i + 8] = 0x5c5c5c5cu; ok[i] = NP_IV[i]; }
    np_sha256(ok, w);
}

// The outer hash: out = H(ok-state || inner digest), 96 bytes in all.
static inline void np_hmac_outer(thread const uint *ok, thread const uint *inner, thread uint *out)
{
    uint w[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = inner[i]; out[i] = ok[i]; }
    w[8] = 0x80000000u;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 768;
    np_sha256(out, w);
}

// out = HMAC(K, m) for a 32-byte m, given K's pad states.
static inline void np_hmac32(thread const uint *ik, thread const uint *ok, thread const uint *m, thread uint *out)
{
    uint w[16], st[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = m[i]; st[i] = ik[i]; }
    w[8] = 0x80000000u;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 768;
    np_sha256(st, w);
    np_hmac_outer(ok, st, out);
}

// out = HMAC(K, V || sep || x || h1 || "Schnorr+SHA256  ") (113 bytes; the inner message is 177 bytes).
// xw = x as big-endian words; blockB = the second data block (last byte of x, h1, algo16, padding).
static inline void np_hmac_keydata(thread const uint *ik, thread const uint *ok, thread const uint *v, uint sep,
                                   thread const uint *xw, thread const uint *blockB, thread uint *out)
{
    uint w[16], st[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = v[i]; st[i] = ik[i]; }
    w[8] = (sep << 24) | (xw[0] >> 8);
    #pragma unroll
    for (int i = 1; i < 8; i++) w[8 + i] = (xw[i - 1] << 24) | (xw[i] >> 8);
    np_sha256(st, w);
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = blockB[i];
    np_sha256(st, w);
    np_hmac_outer(ok, st, out);
}

// out = HMAC(K, V || 0x00) (33 bytes), the RFC6979 retry step.
static inline void np_hmac33(thread const uint *ik, thread const uint *ok, thread const uint *v, thread uint *out)
{
    uint w[16], st[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = v[i]; st[i] = ik[i]; }
    w[8] = 0x00800000u;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 776;
    np_sha256(st, w);
    np_hmac_outer(ok, st, out);
}
