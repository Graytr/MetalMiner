// KawPow (Ravencoin): ProgPoW with RAVENCOINKAWPOW padding.
// The host generates `kawpow_program(mix, cache, data)` for the current period and prepends it to this
// file. The DAG is Ethash's (built by ethash_dag); a 2048-bit item is 16 x uint4. The 16 lanes of each
// half SIMD group work on one hash at a time; every thread owns one nonce, as in the ProgPoW reference.

constant uint KAWPOW_RC[22] = {
    0x00000001u, 0x00008082u, 0x0000808Au, 0x80008000u, 0x0000808Bu, 0x80000001u, 0x80008081u, 0x00008009u,
    0x0000008Au, 0x00000088u, 0x80008009u, 0x8000000Au, 0x8000808Bu, 0x0000008Bu, 0x00008089u, 0x00008003u,
    0x00008002u, 0x00000080u, 0x0000800Au, 0x8000000Au, 0x80008081u, 0x00008080u,
};
constant uint KAWPOW_RAVEN[15] = { 0x72, 0x41, 0x56, 0x45, 0x4E, 0x43, 0x4F, 0x49, 0x4E, 0x4B, 0x41, 0x57, 0x50, 0x4F, 0x57 };

static inline void kawpow_keccakf800(thread uint *a) {
    for (int r = 0; r < 22; r++) {
        uint c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        uint c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        uint c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        uint c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        uint c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        uint d0 = c4 ^ rotate(c1, 1u), d1 = c0 ^ rotate(c2, 1u), d2 = c1 ^ rotate(c3, 1u);
        uint d3 = c2 ^ rotate(c4, 1u), d4 = c3 ^ rotate(c0, 1u);
        #pragma unroll
        for (int j = 0; j < 25; j += 5) { a[j] ^= d0; a[j+1] ^= d1; a[j+2] ^= d2; a[j+3] ^= d3; a[j+4] ^= d4; }
        uint t = a[1];
        a[1]  = rotate(a[6], 12u);  a[6]  = rotate(a[9], 20u);  a[9]  = rotate(a[22], 29u); a[22] = rotate(a[14], 7u);
        a[14] = rotate(a[20], 18u); a[20] = rotate(a[2], 30u);  a[2]  = rotate(a[12], 11u); a[12] = rotate(a[13], 25u);
        a[13] = rotate(a[19], 8u);  a[19] = rotate(a[23], 24u); a[23] = rotate(a[15], 9u);  a[15] = rotate(a[4], 27u);
        a[4]  = rotate(a[24], 14u); a[24] = rotate(a[21], 2u);  a[21] = rotate(a[8], 23u);  a[8]  = rotate(a[16], 13u);
        a[16] = rotate(a[5], 4u);   a[5]  = rotate(a[3], 28u);  a[3]  = rotate(a[18], 21u); a[18] = rotate(a[17], 15u);
        a[17] = rotate(a[11], 10u); a[11] = rotate(a[7], 6u);   a[7]  = rotate(a[10], 3u);  a[10] = rotate(t, 1u);
        #pragma unroll
        for (int j = 0; j < 25; j += 5) {
            uint a0 = a[j], a1 = a[j+1], a2 = a[j+2], a3 = a[j+3], a4 = a[j+4];
            a[j] = a0 ^ (~a1 & a2); a[j+1] = a1 ^ (~a2 & a3); a[j+2] = a2 ^ (~a3 & a4);
            a[j+3] = a3 ^ (~a4 & a0); a[j+4] = a4 ^ (~a0 & a1);
        }
        a[0] ^= KAWPOW_RC[r];
    }
}

static inline uint kawpow_fnv1a(uint u, uint v) { return (u ^ v) * 0x01000193u; }

struct KawPowKiss { uint z, w, jsr, jcong; };
static inline uint kawpow_kiss(thread KawPowKiss &k) {
    k.z = 36969u * (k.z & 0xffffu) + (k.z >> 16);
    k.w = 18000u * (k.w & 0xffffu) + (k.w >> 16);
    k.jcong = 69069u * k.jcong + 1234567u;
    k.jsr ^= k.jsr << 17;
    k.jsr ^= k.jsr >> 13;
    k.jsr ^= k.jsr << 5;
    return (((k.z << 16) + k.w) ^ k.jcong) + k.jsr;
}

// Loads the first 16 KiB of the DAG into threadgroup memory (ProgPoW's L1 cache).
static inline void kawpow_load_cache(device const uint4 *dag, threadgroup uint *cache, uint tid, uint count) {
    for (uint i = tid; i < 1024; i += count) {
        uint4 v = dag[i];
        cache[4*i] = v.x; cache[4*i+1] = v.y; cache[4*i+2] = v.z; cache[4*i+3] = v.w;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
}

static inline void kawpow_compute(device const uint4 *dag, constant uint *header, ulong nonce, uint items,
                                  uint lane, threadgroup const uint *cache, thread uint *digest, thread uint *final)
{
    uint st[25];
    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = header[i];
    st[8] = (uint)nonce;
    st[9] = (uint)(nonce >> 32);
    #pragma unroll
    for (int i = 10; i < 25; i++) st[i] = KAWPOW_RAVEN[i - 10];
    kawpow_keccakf800(st);
    uint carry[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { carry[i] = st[i]; digest[i] = 0; }

    uint l = lane & 15u;
    ushort lane0 = (ushort)(lane - l);
    for (uint h = 0; h < 16; h++) {
        ushort owner = lane0 + (ushort)h;
        uint seed0 = simd_shuffle(carry[0], owner);
        uint seed1 = simd_shuffle(carry[1], owner);
        KawPowKiss k;
        k.z = kawpow_fnv1a(0x811c9dc5u, seed0);
        k.w = kawpow_fnv1a(k.z, seed1);
        k.jsr = kawpow_fnv1a(k.w, l);
        k.jcong = kawpow_fnv1a(k.jsr, l);
        uint mix[32];
        #pragma unroll
        for (int i = 0; i < 32; i++) mix[i] = kawpow_kiss(k);

        for (uint r = 0; r < 64; r++) {
            uint item = simd_shuffle(mix[0], (ushort)(lane0 + (r & 15u))) % items;
            uint4 data = dag[(ulong)item * 16 + ((l ^ r) & 15u)];
            kawpow_program(mix, cache, data);
        }

        uint laneHash = 0x811c9dc5u;
        #pragma unroll
        for (int i = 0; i < 32; i++) laneHash = kawpow_fnv1a(laneHash, mix[i]);
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            uint a = simd_shuffle(laneHash, (ushort)(lane0 + j));
            uint b = simd_shuffle(laneHash, (ushort)(lane0 + 8 + j));
            uint d = kawpow_fnv1a(kawpow_fnv1a(0x811c9dc5u, a), b);
            if (h == l) digest[j] = d;
        }
    }

    #pragma unroll
    for (int i = 0; i < 8; i++) { st[i] = carry[i]; st[8 + i] = digest[i]; }
    #pragma unroll
    for (int i = 16; i < 25; i++) st[i] = KAWPOW_RAVEN[i - 16];
    kawpow_keccakf800(st);
    #pragma unroll
    for (int i = 0; i < 8; i++) final[i] = st[i];
}

// Search: a hit is a final hash whose first 8 bytes, read big-endian, are <= target.
kernel void kawpow_search(device const uint4 *dag     [[buffer(0)]],
                          constant uint *header        [[buffer(1)]],
                          constant ulong &startNonce   [[buffer(2)]],
                          constant ulong &target       [[buffer(3)]],
                          constant uint &items         [[buffer(4)]],
                          device SearchOutput *out     [[buffer(5)]],
                          uint gid    [[thread_position_in_grid]],
                          uint tid    [[thread_index_in_threadgroup]],
                          uint tcount [[threads_per_threadgroup]],
                          uint lane   [[thread_index_in_simdgroup]])
{
    threadgroup uint cache[4096];
    kawpow_load_cache(dag, cache, tid, tcount);
    ulong nonce = startNonce + gid;
    uint digest[8], final[8];
    kawpow_compute(dag, header, nonce, items, lane, cache, digest, final);
    ulong head = ((ulong)bswap32(final[0]) << 32) | (ulong)bswap32(final[1]);
    if (head <= target) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

// Full results for given nonces (cross-checking): 16 words per nonce, mix digest then final hash.
kernel void kawpow_hash(device const uint4 *dag      [[buffer(0)]],
                        constant uint *header         [[buffer(1)]],
                        device const ulong *nonces    [[buffer(2)]],
                        constant uint &items          [[buffer(3)]],
                        device uint *results          [[buffer(4)]],
                        uint gid    [[thread_position_in_grid]],
                        uint tid    [[thread_index_in_threadgroup]],
                        uint tcount [[threads_per_threadgroup]],
                        uint lane   [[thread_index_in_simdgroup]])
{
    threadgroup uint cache[4096];
    kawpow_load_cache(dag, cache, tid, tcount);
    uint digest[8], final[8];
    kawpow_compute(dag, header, nonces[gid], items, lane, cache, digest, final);
    device uint *r = results + 16 * gid;
    for (int i = 0; i < 8; i++) { r[i] = digest[i]; r[8 + i] = final[i]; }
}
