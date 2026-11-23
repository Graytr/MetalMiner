// Tari C29 (Cuckaroo29): edge generation, bucketed trimming and nonce recovery. See docs/specs/cuckaroo29.md.
//
// Edges are uint2 (node on the bucketed side, node on the other side). An edge buffer is `buckets` slots of `cap`
// edges: bucket b holds edges [b * cap, b * cap + count[b]). Writers bump count[b] atomically and drop edges past cap
// (count[b] keeps the true total, so overflow is visible). Seeding buckets every edge by its U node; trimming round r
// reads buckets keyed by one side, drops edges whose node there has no other edge, and writes the survivors swapped,
// bucketed by the other side, so the next round counts the other side.
//
// Macros set by the host: CK_EDGEBITS (29 on mainnet), CK_ZBITS (node bits per bucket, at most 17 so the two 2^ZBITS
// bit maps fit in 32 KiB of threadgroup memory), CK_SEED_MODE (0 keeps a block's 64 hashes in registers, 1 runs its
// chain twice).

#ifndef CK_EDGEBITS
#define CK_EDGEBITS 29
#endif
#ifndef CK_ZBITS
#define CK_ZBITS 16
#endif
#ifndef CK_SEED_MODE
#define CK_SEED_MODE 0
#endif

#define CK_EDGEMASK ((1u << CK_EDGEBITS) - 1u)
#define CK_ZMASK ((1u << CK_ZBITS) - 1u)
#define CK_ZWORDS (1u << (CK_ZBITS - 5))
#define CK_TABLE 4096u
#define CK_EMPTY 0xffffffffu

struct cuckaroo29_sip { ulong v0, v1, v2, v3; };

static inline void cuckaroo29_sipround(thread cuckaroo29_sip &s) {
    s.v0 += s.v1; s.v2 += s.v3; s.v1 = rotl64(s.v1, 13); s.v3 = rotl64(s.v3, 16);
    s.v1 ^= s.v0; s.v3 ^= s.v2; s.v0 = rotl64(s.v0, 32); s.v2 += s.v1; s.v0 += s.v3;
    s.v1 = rotl64(s.v1, 17); s.v3 = rotl64(s.v3, 21); s.v1 ^= s.v2; s.v3 ^= s.v0; s.v2 = rotl64(s.v2, 32);
}

// siphash-2-4 of `nonce` continuing from the current state (Cuckaroo chains the 64 hashes of a block).
static inline ulong cuckaroo29_hash24(thread cuckaroo29_sip &s, ulong nonce) {
    s.v3 ^= nonce;
    cuckaroo29_sipround(s); cuckaroo29_sipround(s);
    s.v0 ^= nonce;
    s.v2 ^= 0xffUL;
    cuckaroo29_sipround(s); cuckaroo29_sipround(s); cuckaroo29_sipround(s); cuckaroo29_sipround(s);
    return (s.v0 ^ s.v1) ^ (s.v2 ^ s.v3);
}

static inline void cuckaroo29_put(ulong h, device uint2 *dst, device atomic_uint *count, uint cap) {
    uint u = (uint)h & CK_EDGEMASK;
    uint v = (uint)(h >> 32) & CK_EDGEMASK;
    uint b = u >> CK_ZBITS;
    uint slot = atomic_fetch_add_explicit(&count[b], 1u, memory_order_relaxed);
    if (slot < cap) dst[(ulong)b * cap + slot] = uint2(u, v);
}

// Seeding: one thread per siphash block of 64 edges; every edge goes to the bucket of its U node.
kernel void cuckaroo29_seed(constant ulong *keys          [[buffer(0)]],
                            device uint2 *dst             [[buffer(1)]],
                            device atomic_uint *dstCount  [[buffer(2)]],
                            constant uint &dstCap         [[buffer(3)]],
                            uint block [[thread_position_in_grid]])
{
    cuckaroo29_sip s = { keys[0], keys[1], keys[2], keys[3] };
    ulong nonce = (ulong)block << 6;
#if CK_SEED_MODE == 0
    ulong h[64];
    #pragma unroll
    for (uint i = 0; i < 64; i++) h[i] = cuckaroo29_hash24(s, nonce + i);
    ulong last = h[63];
    #pragma unroll
    for (uint i = 0; i < 64; i++) cuckaroo29_put(i == 63 ? last : h[i] ^ last, dst, dstCount, dstCap);
#else
    ulong last = 0;
    for (uint i = 0; i < 64; i++) last = cuckaroo29_hash24(s, nonce + i);
    s = cuckaroo29_sip{ keys[0], keys[1], keys[2], keys[3] };
    for (uint i = 0; i < 64; i++) {
        ulong h = cuckaroo29_hash24(s, nonce + i);
        cuckaroo29_put(i == 63 ? h : h ^ last, dst, dstCount, dstCap);
    }
#endif
}

// Every thread reads the bucket's edge count; once all have, thread 0 zeroes it (leaving the buffer ready to refill)
// and records statistics: stats[0] counts edges dropped by full buckets, stats[roundIndex] the round's input edges.
static inline void cuckaroo29_take_count(device atomic_uint *srcCount, device atomic_uint *stats, uint roundIndex,
                                         uint bucket, uint total, uint cap, uint tid)
{
    if (tid == 0) {
        atomic_store_explicit(&srcCount[bucket], 0u, memory_order_relaxed);
        atomic_fetch_add_explicit(&stats[roundIndex], total, memory_order_relaxed);
        if (total > cap) atomic_fetch_add_explicit(&stats[0], total - cap, memory_order_relaxed);
    }
}

static inline void cuckaroo29_move(uint2 e, device uint2 *dst, device atomic_uint *dstCount, uint cap) {
    uint b = e.y >> CK_ZBITS;
    uint slot = atomic_fetch_add_explicit(&dstCount[b], 1u, memory_order_relaxed);
    if (slot < cap) dst[(ulong)b * cap + slot] = uint2(e.y, e.x);
}

// One trimming round, one threadgroup per source bucket. Two bit maps over the bucket's 2^ZBITS nodes record "seen"
// and "seen twice"; edges whose node was seen twice survive and move, swapped, to the bucket of their other node.
// Each edge is read twice (count, then move). No other threadgroup memory is used, so ZBITS = 17 fits in 32 KiB.
kernel void cuckaroo29_trim(device const uint2 *src        [[buffer(0)]],
                            device atomic_uint *srcCount   [[buffer(1)]],
                            device uint2 *dst              [[buffer(2)]],
                            device atomic_uint *dstCount   [[buffer(3)]],
                            constant uint2 &caps           [[buffer(4)]],
                            device atomic_uint *stats      [[buffer(5)]],
                            constant uint &roundIndex      [[buffer(6)]],
                            uint bucket [[threadgroup_position_in_grid]],
                            uint tid    [[thread_index_in_threadgroup]],
                            uint size   [[threads_per_threadgroup]])
{
    threadgroup atomic_uint seen[CK_ZWORDS];
    threadgroup atomic_uint twice[CK_ZWORDS];
    uint total = atomic_load_explicit(&srcCount[bucket], memory_order_relaxed);
    for (uint i = tid; i < CK_ZWORDS; i += size) {
        atomic_store_explicit(&seen[i], 0u, memory_order_relaxed);
        atomic_store_explicit(&twice[i], 0u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device);
    cuckaroo29_take_count(srcCount, stats, roundIndex, bucket, total, caps.x, tid);
    uint n = min(total, caps.x);
    device const uint2 *edges = src + (ulong)bucket * caps.x;
    for (uint i = tid; i < n; i += size) {
        uint z = edges[i].x & CK_ZMASK;
        uint bit = 1u << (z & 31u);
        if (atomic_fetch_or_explicit(&seen[z >> 5], bit, memory_order_relaxed) & bit) {
            atomic_fetch_or_explicit(&twice[z >> 5], bit, memory_order_relaxed);
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint i = tid; i < n; i += size) {
        uint2 e = edges[i];
        uint z = e.x & CK_ZMASK;
        if ((atomic_load_explicit(&twice[z >> 5], memory_order_relaxed) >> (z & 31u)) & 1u) {
            cuckaroo29_move(e, dst, dstCount, caps.y);
        }
    }
}

// The same round for late, sparse buckets: instead of bit maps over all 2^ZBITS nodes, an open-addressing table sized
// to the bucket's edge count (at least twice it, at most CK_TABLE entries) holds (node << 1 | seen twice). If an edge
// can't be inserted because the table is full, every edge of the bucket is kept: keeping an edge is always safe, it
// only postpones its removal.
kernel void cuckaroo29_trim_sparse(device const uint2 *src        [[buffer(0)]],
                                   device atomic_uint *srcCount   [[buffer(1)]],
                                   device uint2 *dst              [[buffer(2)]],
                                   device atomic_uint *dstCount   [[buffer(3)]],
                                   constant uint2 &caps           [[buffer(4)]],
                                   device atomic_uint *stats      [[buffer(5)]],
                                   constant uint &roundIndex      [[buffer(6)]],
                                   uint bucket [[threadgroup_position_in_grid]],
                                   uint tid    [[thread_index_in_threadgroup]],
                                   uint size   [[threads_per_threadgroup]])
{
    threadgroup atomic_uint table[CK_TABLE];
    threadgroup atomic_uint full;
    uint total = atomic_load_explicit(&srcCount[bucket], memory_order_relaxed);
    uint n = min(total, caps.x);
    uint slots = 64u;
    while (slots < 2u * n && slots < CK_TABLE) slots <<= 1;
    uint shift = 32u - ctz(slots);
    for (uint i = tid; i < slots; i += size) atomic_store_explicit(&table[i], CK_EMPTY, memory_order_relaxed);
    if (tid == 0) atomic_store_explicit(&full, 0u, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device);
    cuckaroo29_take_count(srcCount, stats, roundIndex, bucket, total, caps.x, tid);
    device const uint2 *edges = src + (ulong)bucket * caps.x;
    for (uint i = tid; i < n; i += size) {
        uint z = edges[i].x & CK_ZMASK;
        uint slot = (z * 0x9E3779B1u) >> shift;
        uint probes = 0;
        while (true) {
            uint expected = CK_EMPTY;
            if (atomic_compare_exchange_weak_explicit(&table[slot], &expected, z << 1,
                                                      memory_order_relaxed, memory_order_relaxed)) break;
            if (expected == CK_EMPTY) continue;   // spurious failure: try the same slot again
            if ((expected >> 1) == z) {
                atomic_fetch_or_explicit(&table[slot], 1u, memory_order_relaxed);
                break;
            }
            slot = (slot + 1u) & (slots - 1u);
            if (++probes == slots) {
                atomic_store_explicit(&full, 1u, memory_order_relaxed);
                break;
            }
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    bool keepAll = atomic_load_explicit(&full, memory_order_relaxed) != 0;
    for (uint i = tid; i < n; i += size) {
        uint2 e = edges[i];
        bool keep = keepAll;
        if (!keep) {
            uint z = e.x & CK_ZMASK;
            uint slot = (z * 0x9E3779B1u) >> shift;
            for (uint probes = 0; probes < slots; probes++) {
                uint w = atomic_load_explicit(&table[slot], memory_order_relaxed);
                if ((w >> 1) == z) {
                    keep = (w & 1u) != 0;
                    break;
                }
                if (w == CK_EMPTY) {   // not found: can't happen unless the table filled up; keep to be safe
                    keep = true;
                    break;
                }
                slot = (slot + 1u) & (slots - 1u);
            }
        }
        if (keep) cuckaroo29_move(e, dst, dstCount, caps.y);
    }
}

// Nonce recovery for a found cycle: one thread per siphash block, every edge compared with the cycle's (u, v) pairs.
// Matches are (nonce, index into the cycle).
kernel void cuckaroo29_recover(constant ulong *keys          [[buffer(0)]],
                               constant uint2 *cycle         [[buffer(1)]],
                               constant uint &cycleEdges     [[buffer(2)]],
                               device atomic_uint *found     [[buffer(3)]],
                               device uint2 *matches         [[buffer(4)]],
                               uint block [[thread_position_in_grid]])
{
    cuckaroo29_sip s = { keys[0], keys[1], keys[2], keys[3] };
    ulong nonce = (ulong)block << 6;
    ulong last = 0;
    for (uint i = 0; i < 64; i++) last = cuckaroo29_hash24(s, nonce + i);
    s = cuckaroo29_sip{ keys[0], keys[1], keys[2], keys[3] };
    for (uint i = 0; i < 64; i++) {
        ulong h = cuckaroo29_hash24(s, nonce + i);
        if (i != 63) h ^= last;
        uint u = (uint)h & CK_EDGEMASK, v = (uint)(h >> 32) & CK_EDGEMASK;
        for (uint k = 0; k < cycleEdges; k++) {
            if (cycle[k].x == u && cycle[k].y == v) {
                uint slot = atomic_fetch_add_explicit(found, 1u, memory_order_relaxed);
                if (slot < 256) matches[slot] = uint2((uint)(nonce + i), k);
            }
        }
    }
}
