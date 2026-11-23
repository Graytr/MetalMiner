// Cooperative Ethash: 8 lanes of a SIMD group share each hash's DAG reads, so every load instruction
// fetches whole 128-byte pages (lane t reads uint4 t of the page). Each thread still owns one nonce and
// does its own Keccak; the 8 hashes of an 8-lane group are walked ETHASH_PAR at a time.
// Needs ethash.metal first (Keccak, fnv). Threadgroups must be a multiple of 32 and at most ETHASH_GROUP.

#ifndef ETHASH_GROUP
#define ETHASH_GROUP 256
#endif
#ifndef ETHASH_PAR
#define ETHASH_PAR 2
#endif

static inline void ethash_coop_core(device const uint4 *dag, constant ulong *header, ulong nonce, uint pages,
                                    uint tid, uint lane,
                                    threadgroup uint4 *sharedS, threadgroup uint *sharedC,
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
    #pragma unroll
    for (int k = 0; k < 4; k++) {
        sharedS[tid * 4 + k] = uint4((uint)st[2*k], (uint)(st[2*k] >> 32), (uint)st[2*k+1], (uint)(st[2*k+1] >> 32));
    }
    simdgroup_barrier(mem_flags::mem_threadgroup);

    uint t = lane & 7u;
    uint base = tid - t;                 // first thread of this 8-lane group
    ushort lane0 = (ushort)(lane - t);   // its lane in the SIMD group
    for (uint h = 0; h < 8; h += ETHASH_PAR) {
        uint4 mix[ETHASH_PAR];
        uint init0[ETHASH_PAR];
        #pragma unroll
        for (int p = 0; p < ETHASH_PAR; p++) {
            mix[p] = sharedS[(base + h + p) * 4 + (t & 3u)];
            init0[p] = sharedS[(base + h + p) * 4].x;
        }
        for (uint a = 0; a < 64; a += 4) {
            ushort owner = lane0 + (ushort)((a >> 2) & 7u);   // lane holding mix word a % 32
            #pragma unroll
            for (uint b = 0; b < 4; b++) {
                #pragma unroll
                for (int p = 0; p < ETHASH_PAR; p++) {
                    uint page = simd_shuffle(ethash_fnv(init0[p] ^ (a + b), mix[p][b]) % pages, owner);
                    uint4 v = dag[(ulong)page * 8 + t];
                    mix[p] = uint4(ethash_fnv(mix[p].x, v.x), ethash_fnv(mix[p].y, v.y),
                                   ethash_fnv(mix[p].z, v.z), ethash_fnv(mix[p].w, v.w));
                }
            }
        }
        #pragma unroll
        for (int p = 0; p < ETHASH_PAR; p++) {
            sharedC[(base + h + p) * 8 + t] = ethash_fnv(ethash_fnv(ethash_fnv(mix[p].x, mix[p].y), mix[p].z), mix[p].w);
        }
    }
    simdgroup_barrier(mem_flags::mem_threadgroup);
    #pragma unroll
    for (int k = 0; k < 8; k++) digest[k] = sharedC[tid * 8 + k];

    // final = keccak256(s || digest); st[0..7] still hold s
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

kernel void ethash_search_coop(device const uint4 *dag    [[buffer(0)]],
                               constant ulong *header      [[buffer(1)]],
                               constant ulong &startNonce  [[buffer(2)]],
                               constant ulong &target      [[buffer(3)]],
                               constant uint &pages        [[buffer(4)]],
                               device SearchOutput *out    [[buffer(5)]],
                               uint gid  [[thread_position_in_grid]],
                               uint tid  [[thread_index_in_threadgroup]],
                               uint lane [[thread_index_in_simdgroup]])
{
    threadgroup uint4 sharedS[ETHASH_GROUP * 4];
    threadgroup uint sharedC[ETHASH_GROUP * 8];
    ulong nonce = startNonce + gid;
    uint digest[8];
    ulong final[4];
    ethash_coop_core(dag, header, nonce, pages, tid, lane, sharedS, sharedC, digest, final);
    if (bswap64(final[0]) <= target) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

kernel void ethash_hash_coop(device const uint4 *dag      [[buffer(0)]],
                             constant ulong *header        [[buffer(1)]],
                             device const ulong *nonces    [[buffer(2)]],
                             constant uint &pages          [[buffer(3)]],
                             device uint *results          [[buffer(4)]],
                             uint gid  [[thread_position_in_grid]],
                             uint tid  [[thread_index_in_threadgroup]],
                             uint lane [[thread_index_in_simdgroup]])
{
    threadgroup uint4 sharedS[ETHASH_GROUP * 4];
    threadgroup uint sharedC[ETHASH_GROUP * 8];
    uint digest[8];
    ulong final[4];
    ethash_coop_core(dag, header, nonces[gid], pages, tid, lane, sharedS, sharedC, digest, final);
    device uint *r = results + 16 * gid;
    for (int i = 0; i < 8; i++) r[i] = digest[i];
    for (int i = 0; i < 4; i++) { r[8 + 2*i] = (uint)final[i]; r[9 + 2*i] = (uint)(final[i] >> 32); }
}
