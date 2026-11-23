// Ethash family (Ethash, Etchash, OctaSpace): DAG generation, search, and full-hash kernels.
// The DAG is an array of 64-byte items (4 x uint4); hashimoto reads 128-byte pages (8 x uint4).

constant ulong ETHASH_RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
};

static inline void ethash_keccakf(thread ulong *a) {
    for (int r = 0; r < 24; r++) {
        ulong c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        ulong c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        ulong c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        ulong c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        ulong c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        ulong d0 = c4 ^ rotl64(c1, 1), d1 = c0 ^ rotl64(c2, 1), d2 = c1 ^ rotl64(c3, 1);
        ulong d3 = c2 ^ rotl64(c4, 1), d4 = c3 ^ rotl64(c0, 1);
        #pragma unroll
        for (int j = 0; j < 25; j += 5) { a[j] ^= d0; a[j+1] ^= d1; a[j+2] ^= d2; a[j+3] ^= d3; a[j+4] ^= d4; }
        ulong t = a[1];
        a[1]  = rotl64(a[6], 44);  a[6]  = rotl64(a[9], 20);  a[9]  = rotl64(a[22], 61); a[22] = rotl64(a[14], 39);
        a[14] = rotl64(a[20], 18); a[20] = rotl64(a[2], 62);  a[2]  = rotl64(a[12], 43); a[12] = rotl64(a[13], 25);
        a[13] = rotl64(a[19], 8);  a[19] = rotl64(a[23], 56); a[23] = rotl64(a[15], 41); a[15] = rotl64(a[4], 27);
        a[4]  = rotl64(a[24], 14); a[24] = rotl64(a[21], 2);  a[21] = rotl64(a[8], 55);  a[8]  = rotl64(a[16], 45);
        a[16] = rotl64(a[5], 36);  a[5]  = rotl64(a[3], 28);  a[3]  = rotl64(a[18], 21); a[18] = rotl64(a[17], 15);
        a[17] = rotl64(a[11], 10); a[11] = rotl64(a[7], 6);   a[7]  = rotl64(a[10], 3);  a[10] = rotl64(t, 1);
        #pragma unroll
        for (int j = 0; j < 25; j += 5) {
            ulong a0 = a[j], a1 = a[j+1], a2 = a[j+2], a3 = a[j+3], a4 = a[j+4];
            a[j] = a0 ^ (~a1 & a2); a[j+1] = a1 ^ (~a2 & a3); a[j+2] = a2 ^ (~a3 & a4);
            a[j+3] = a3 ^ (~a4 & a0); a[j+4] = a4 ^ (~a0 & a1);
        }
        a[0] ^= ETHASH_RC[r];
    }
}

static inline uint ethash_fnv(uint a, uint b) { return (a * 0x01000193u) ^ b; }

// Keccak-512 of a 64-byte block held as 16 words, in place.
static inline void ethash_keccak512_64(thread uint *w) {
    ulong a[25];
    #pragma unroll
    for (int i = 0; i < 8; i++) a[i] = (ulong)w[2*i] | ((ulong)w[2*i+1] << 32);
    a[8] = 0x8000000000000001UL;
    #pragma unroll
    for (int i = 9; i < 25; i++) a[i] = 0;
    ethash_keccakf(a);
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[2*i] = (uint)a[i]; w[2*i+1] = (uint)(a[i] >> 32); }
}

// One DAG item per thread: items [firstItem, firstItem + threads). `parents` must be a multiple of 16.
kernel void ethash_dag(device const uint4 *cache  [[buffer(0)]],
                       device uint4 *dag           [[buffer(1)]],
                       constant uint &cacheItems   [[buffer(2)]],
                       constant uint &firstItem    [[buffer(3)]],
                       constant uint &parents      [[buffer(4)]],   // 256 for Ethash, 512 for KawPow
                       uint gid [[thread_position_in_grid]])
{
    uint index = firstItem + gid;
    uint mix[16];
    device const uint4 *source = cache + 4 * (index % cacheItems);
    #pragma unroll
    for (int k = 0; k < 4; k++) { uint4 v = source[k]; mix[4*k] = v.x; mix[4*k+1] = v.y; mix[4*k+2] = v.z; mix[4*k+3] = v.w; }
    mix[0] ^= index;
    ethash_keccak512_64(mix);
    for (uint j = 0; j < parents; j += 16) {
        #pragma unroll
        for (uint r = 0; r < 16; r++) {
            device const uint4 *p = cache + 4 * (ethash_fnv(index ^ (j + r), mix[r]) % cacheItems);
            #pragma unroll
            for (int k = 0; k < 4; k++) {
                uint4 v = p[k];
                mix[4*k]   = ethash_fnv(mix[4*k],   v.x);
                mix[4*k+1] = ethash_fnv(mix[4*k+1], v.y);
                mix[4*k+2] = ethash_fnv(mix[4*k+2], v.z);
                mix[4*k+3] = ethash_fnv(mix[4*k+3], v.w);
            }
        }
    }
    ethash_keccak512_64(mix);
    device uint4 *out = dag + 4 * (ulong)index;
    #pragma unroll
    for (int k = 0; k < 4; k++) out[k] = uint4(mix[4*k], mix[4*k+1], mix[4*k+2], mix[4*k+3]);
}

// Full hashimoto for one nonce: mix digest (8 words) and final hash (4 lanes, little-endian bytes).
static inline void ethash_compute(device const uint4 *dag, constant ulong *header, ulong nonce, uint pages,
                                  thread uint *digest, thread ulong *final)
{
    ulong st[25];
    st[0] = header[0]; st[1] = header[1]; st[2] = header[2]; st[3] = header[3];
    st[4] = nonce;
    st[5] = 0x01UL;
    #pragma unroll
    for (int i = 6; i < 25; i++) st[i] = 0;
    st[8] = 0x8000000000000000UL;
    ethash_keccakf(st);

    uint s[16];
    #pragma unroll
    for (int i = 0; i < 8; i++) { s[2*i] = (uint)st[i]; s[2*i+1] = (uint)(st[i] >> 32); }
    uint mix[32];
    #pragma unroll
    for (int i = 0; i < 16; i++) { mix[i] = s[i]; mix[i+16] = s[i]; }

    for (uint i = 0; i < 64; i += 32) {
        #pragma unroll
        for (uint r = 0; r < 32; r++) {
            device const uint4 *page = dag + 8 * (ulong)(ethash_fnv((i + r) ^ s[0], mix[r]) % pages);
            #pragma unroll
            for (int k = 0; k < 8; k++) {
                uint4 v = page[k];
                mix[4*k]   = ethash_fnv(mix[4*k],   v.x);
                mix[4*k+1] = ethash_fnv(mix[4*k+1], v.y);
                mix[4*k+2] = ethash_fnv(mix[4*k+2], v.z);
                mix[4*k+3] = ethash_fnv(mix[4*k+3], v.w);
            }
        }
    }
    #pragma unroll
    for (int k = 0; k < 8; k++) digest[k] = ethash_fnv(ethash_fnv(ethash_fnv(mix[4*k], mix[4*k+1]), mix[4*k+2]), mix[4*k+3]);

    // final = keccak256(s || digest): 96 bytes, rate 136
    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = (ulong)s[2*i] | ((ulong)s[2*i+1] << 32);
    #pragma unroll
    for (int i = 0; i < 4; i++) st[8 + i] = (ulong)digest[2*i] | ((ulong)digest[2*i+1] << 32);
    st[12] = 0x01UL;
    #pragma unroll
    for (int i = 13; i < 25; i++) st[i] = 0;
    st[16] = 0x8000000000000000UL;
    ethash_keccakf(st);
    #pragma unroll
    for (int i = 0; i < 4; i++) final[i] = st[i];
}

// Search: one nonce per thread; a hit is a final hash whose first 8 bytes (big-endian) are <= target.
kernel void ethash_search(device const uint4 *dag    [[buffer(0)]],
                          constant ulong *header      [[buffer(1)]],
                          constant ulong &startNonce  [[buffer(2)]],
                          constant ulong &target      [[buffer(3)]],
                          constant uint &pages        [[buffer(4)]],
                          device SearchOutput *out    [[buffer(5)]],
                          uint gid [[thread_position_in_grid]])
{
    ulong nonce = startNonce + gid;
    uint digest[8];
    ulong final[4];
    ethash_compute(dag, header, nonce, pages, digest, final);
    if (bswap64(final[0]) <= target) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

// Full hashes for given nonces (cross-checking): 16 words per nonce, digest then final.
kernel void ethash_hash(device const uint4 *dag      [[buffer(0)]],
                        constant ulong *header        [[buffer(1)]],
                        device const ulong *nonces    [[buffer(2)]],
                        constant uint &pages          [[buffer(3)]],
                        device uint *results          [[buffer(4)]],
                        uint gid [[thread_position_in_grid]])
{
    uint digest[8];
    ulong final[4];
    ethash_compute(dag, header, nonces[gid], pages, digest, final);
    device uint *r = results + 16 * gid;
    for (int i = 0; i < 8; i++) r[i] = digest[i];
    for (int i = 0; i < 4; i++) { r[8 + 2*i] = (uint)final[i]; r[9 + 2*i] = (uint)(final[i] >> 32); }
}
