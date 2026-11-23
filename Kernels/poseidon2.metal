// Quantus (QTC) proof of work. See docs/specs/poseidon2.md.
// hash = Poseidon2 sponge over header (32 B) || nonce (64 B): Goldilocks p = 2^64 - 2^32 + 1, width 12,
// rate 8, 4 + 4 external rounds, 22 internal rounds, x^7 S-box; squeezed twice into a big-endian U512.
// A nonce is valid when hash < U512::MAX / difficulty.
//
// Field elements are any 64-bit representative of their residue (lazy reduction), made canonical only
// when written out. Apple GPUs emulate 64-bit integer math, and 64-bit compares and selects are costly,
// so products are 32x32+64 multiply-add chains and reductions work on 32-bit words and end in one signed
// correction. The external layer adds into (64-bit, carry count) accumulators and reduces once per
// output; the internal layer's sum rides in each lane's multiply-add chain. Each linear layer also adds
// the round constants of the S-box layer that follows it. (Measured alternatives are in the spec note.)
//
// Tuning macros (--set m.NAME=1): P2_UNROLL_FULL / P2_UNROLL_PARTIAL unroll the external / internal round
// loops (no measurable difference on M3 Max; rolled loops keep the code small).

#ifndef P2_UNROLL_FULL
#define P2_UNROLL_FULL 0
#endif
#ifndef P2_UNROLL_PARTIAL
#define P2_UNROLL_PARTIAL 0
#endif

#define P2_STR(x) #x
#define P2_PRAGMA(x) _Pragma(P2_STR(x))
#define P2_LANES P2_PRAGMA(unroll)   // loops over state lanes: always unrolled so the state stays in registers
#if P2_UNROLL_FULL
#define P2_FULL_LOOP P2_PRAGMA(unroll)
#else
#define P2_FULL_LOOP P2_PRAGMA(unroll 1)
#endif
#if P2_UNROLL_PARTIAL
#define P2_PARTIAL_LOOP P2_PRAGMA(unroll)
#else
#define P2_PARTIAL_LOOP P2_PRAGMA(unroll 1)
#endif

constant ulong P2_P   = 0xFFFFFFFF00000001ul;
constant ulong P2_EPS = 0x00000000FFFFFFFFul;   // 2^64 mod p

// Constants added by each external layer for the S-box layer that follows it: entries 0-3 feed the
// initial rounds, entry 4 the first internal round (lane 0 only), entries 5-7 terminal rounds 1-3,
// entry 8 nothing. Terminal round 0's constants are added by the last internal layer.
constant ulong P2_RC_EXT[9][12] = {
    {0xc002e770975b1607ul, 0xbca51a8dfe14593aul, 0x72938dfbe774f7f9ul, 0xe4f2fe29e03234acul, 0xd5e0ba2f541b6449ul, 0xec33b868f3cc46c1ul,
     0x486dcb55419d475aul, 0x6c1cb2a358cc24f1ul, 0xe3f30d509a1436bbul, 0xd9a64f068dca7c29ul, 0xe59b3f57aabba1aeul, 0x2a3dd4505b478fdcul},
    {0xada1f8dc7676ed25ul, 0x2711aa8b5509d516ul, 0x4ae6acd0c9c92897ul, 0x56eb3d6b5256d67aul, 0x1f7a9d55923bf51eul, 0x3600427d397a7f68ul,
     0xe5076df75b72c3d0ul, 0xfcd59aa12c6090adul, 0xcd895e8c68b57a9eul, 0x41df7ef9d730ae3eul, 0xee3e2b889abe977dul, 0xd29bb7edbeb9c405ul},
    {0x7d5c08eef608e382ul, 0x89ae889caaf0802cul, 0xb35a8e976d2af617ul, 0xdb14234eafaf5173ul, 0x78f04462d48b1c98ul, 0x265293b0e47ce88aul,
     0x999a649b69b9d32ful, 0x64b0a186698e01d3ul, 0xee0b22d0dfae8bb8ul, 0x4fd53e50ca04a7eeul, 0x5762bfe181f25047ul, 0xf51593e2beb5e3bdul},
    {0x1e5e2b5760e32477ul, 0x622462a1f9aaaeedul, 0xaa284b3ecdb222aeul, 0x63c8e72f542bf3fcul, 0x3ba588cacb43b5e0ul, 0x23eda6f3c99150ddul,
     0xaad3bea4baac9a5aul, 0xe9da8d699b94184aul, 0xcdb13f4cd93e024cul, 0x902cbd0956f655e3ul, 0x5b4e40ffc759532ful, 0xde795c20a2357af7ul},
    {0x97f7798a784ad863ul, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0x605f902830872e01ul, 0x3fd5eb927e95fe4ful, 0xe81025b5a24c69cdul, 0xf7d0ce75de23f74eul, 0xf39942b6a8585089ul, 0x6d808a08f7b71df6ul,
     0xf8806b6588f49a8bul, 0x57df2d8c2a32107aul, 0x16e7c2074d654a2dul, 0x213de241fcf33835ul, 0xb0f2b8905a0976f6ul, 0xd8e3cf2bbd355417ul},
    {0xe498691679d9330ful, 0x763b45d2a3821b28ul, 0x0908bf65eb0a1f0dul, 0x7691eb2d194b24f4ul, 0x0e43551233ae13b2ul, 0x93c393dbfc2fe76ful,
     0x98f607485d48cdeaul, 0xe3d95f30309819c0ul, 0x1ef581a93eaf6acful, 0x0b24c1b7a030fca4ul, 0x624370be5670b327ul, 0x5f1e28615a11e486ul},
    {0xfe04051f909e042bul, 0x7257e5b147fd3803ul, 0xe6ae134bb82f2e78ul, 0x5711fd5cf4784511ul, 0xf83a42660c08c0bcul, 0x2cd8c96d9a3ce855ul,
     0x7d2ffb1bb0e17271ul, 0x85ae1528caea3811ul, 0x52a345d5c7adb0b8ul, 0x504c4c51f3faee94ul, 0xbce34a649cfccaf9ul, 0xe0a3389266fb6dc9ul},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};
constant ulong P2_RC_TERMINAL0[12] = {
    0x7b72c539e0ea4c6eul, 0x144573dae2ce9976ul, 0x802028b68f35fc88ul, 0x6d36c5022c4fe7c2ul, 0xa205d0ffa9b9def3ul, 0xf6e7e38b1ea6ba2ful,
    0x34f7909ae5258d64ul, 0xb0464d9d77b97fcaul, 0x64ddb9d5de7e00a6ul, 0x0ed0d75c27975d97ul, 0x1cbb36f11127338bul, 0x6673e505cfd0b6baul,
};
// Internal round constants shifted by one: internal layer r (0..20) adds round r + 1's constant to lane 0
// (round 0's comes from P2_RC_EXT[4]).
constant ulong P2_RC_PARTIAL_NEXT[21] = {
    0xd1d2bf082f60d4f0ul, 0x69a377a79f9ad206ul, 0xa9d06906a3858e24ul, 0x295275001eede5b5ul, 0x5874e441117bd746ul,
    0x8a084bbba8ed86ccul, 0x3defd7645cde6425ul, 0x3998cfe6871cc137ul, 0x3e52ef8bca48314aul, 0x964a209f85dc9eccul, 0x3fcc9ee82cc4577eul,
    0x8e79b4a5d0096d6dul, 0x8492362ad2392556ul, 0xee72f470262574d6ul, 0x1e0e18496da2444aul, 0x0f3a74bf215eaac6ul, 0x1b061b76a1c0ded3ul,
    0x192c42d86803d7a6ul, 0xf6d49ff997ae0260ul, 0x3ec372e7a0fa3786ul, 0x5538cdf4f23445d3ul,
};
// Every diagonal entry's high word is below 2^32 - 1, which p2_mul_add relies on.
constant ulong P2_DIAG[12] = {
    0xc3b6c08e23ba9300ul, 0xd84b5de94a324fb6ul, 0x0d0c371c5b35b84ful, 0x7964f570e7188037ul, 0x5daf18bbd996604bul, 0x6743bc47b9595257ul,
    0x5528b9362c59bb70ul, 0xac45e25b7127b68bul, 0xa2077d7dfbb606b5ul, 0xf3faac6faee378aeul, 0x0c6388b51545e883ul, 0xd27dbb6944917b60ul,
};

// ---- Goldilocks arithmetic ----

static inline ulong p2_canon(ulong a) { return a >= P2_P ? a - P2_P : a; }

// a + b for two 64-bit representatives (only used a few times per nonce).
static inline ulong p2_add(ulong a, ulong b) {
    ulong s = a + b;
    ulong t = s + (s < a ? P2_EPS : 0ul);       // 2^64 = EPS (mod p)
    return t + (t < s ? P2_EPS : 0ul);          // a second wrap is possible only for two non-canonical inputs
}

// value = lo + c * 2^64, with c a small carry count.
struct P2Acc {
    ulong lo;
    uint c;
};

static inline P2Acc p2_acc(ulong a) { return P2Acc{a, 0u}; }
static inline P2Acc p2_acc_add(P2Acc a, ulong b) {
    ulong s = a.lo + b;
    return P2Acc{s, a.c + (s < b ? 1u : 0u)};
}
static inline P2Acc p2_acc_add2(P2Acc a, P2Acc b) {
    ulong s = a.lo + b.lo;
    return P2Acc{s, a.c + b.c + (s < b.lo ? 1u : 0u)};
}
static inline P2Acc p2_acc_double(ulong a) { return P2Acc{a << 1, uint(a >> 63)}; }
// lo + c * (2^32 - 1), wrapping once more if needed; c < 2^32 keeps c * EPS below 2^64.
static inline ulong p2_fold(P2Acc a) {
    ulong t = (ulong(a.c) << 32) - ulong(a.c);
    ulong r = a.lo + t;
    return r + (r < t ? P2_EPS : 0ul);
}

// 128-bit value as 32-bit words w0 (least significant) .. w3.
struct P2Wide {
    uint w0, w1, w2, w3;
};

// w mod p as a 64-bit representative: w0 + w1 B + w2 B^2 + w3 B^3 with B = 2^32, B^2 = B - 1 and
// B^3 = -1 (mod p), is (w0 - w2 - w3) + (w1 + w2) B.
static inline ulong p2_reduce(P2Wide w) {
    uint t = w.w0 - w.w2;
    uint borrow = w.w0 < w.w2 ? 1u : 0u;
    uint lo = t - w.w3;
    borrow += t < w.w3 ? 1u : 0u;                 // 0..2
    uint h = w.w1 + w.w2;
    uint carry = h < w.w1 ? 1u : 0u;              // 0..1
    uint hi = h - borrow;
    uint under = h < borrow ? 1u : 0u;            // 0..1
    // value = hi:lo + (carry - under) * 2^64, with 2^64 = EPS. When carry - under = 1, hi <= B - 2, and
    // when it is -1, hi >= B - 2, so adding the sign-extended correction can't wrap.
    ulong r = ulong(hi) << 32 | lo;
    ulong d = ulong(long(int(carry) - int(under)));
    return r + ((d << 32) - d);
}

// Schoolbook product as 32x32+64 multiply-adds; no step can exceed 2^64 - 1.
static inline P2Wide p2_mul_wide(ulong a, ulong b) {
    uint a0 = uint(a), a1 = uint(a >> 32), b0 = uint(b), b1 = uint(b >> 32);
    ulong ll = ulong(a0) * b0;
    ulong lh = ulong(a0) * b1 + (ll >> 32);
    ulong hl = ulong(a1) * b0 + (lh & P2_EPS);
    ulong hh = ulong(a1) * b1 + (lh >> 32) + (hl >> 32);
    return P2Wide{uint(ll), uint(hl), uint(hh), uint(hh >> 32)};
}

static inline P2Wide p2_sqr_wide(ulong a) {
    uint a0 = uint(a), a1 = uint(a >> 32);
    ulong ll = ulong(a0) * a0;
    ulong lh = ulong(a0) * a1;                                         // the cross term, counted twice
    ulong mid = (ll >> 32) + ((lh & P2_EPS) << 1);                     // < 3 * 2^32
    ulong hh = ulong(a1) * a1 + ((lh >> 32) << 1) + (mid >> 32);       // <= 2^64 - 1
    return P2Wide{uint(ll), uint(mid), uint(hh), uint(hh >> 32)};
}

static inline ulong p2_mul(ulong a, ulong b) { return p2_reduce(p2_mul_wide(a, b)); }
static inline ulong p2_sqr(ulong a) { return p2_reduce(p2_sqr_wide(a)); }

// x * d + a (mod p) for a diagonal constant d (high word below 2^32 - 1) and a below 2^96: the addend
// rides along in the multiply-add chain, and no step can exceed 2^64 - 1.
static inline ulong p2_mul_add(ulong x, ulong d, P2Acc a) {
    uint x0 = uint(x), x1 = uint(x >> 32), d0 = uint(d), d1 = uint(d >> 32);
    ulong ll = ulong(x0) * d0 + (a.lo & P2_EPS);
    ulong lh = ulong(x0) * d1 + (ll >> 32) + (a.lo >> 32);
    ulong hl = ulong(x1) * d0 + (lh & P2_EPS);
    ulong hh = ulong(x1) * d1 + (lh >> 32) + (hl >> 32) + a.c;
    return p2_reduce(P2Wide{uint(ll), uint(hl), uint(hh), uint(hh >> 32)});
}

static inline ulong p2_sbox(ulong x) {
    ulong x2 = p2_sqr(x);
    ulong x4 = p2_sqr(x2);
    ulong x6 = p2_mul(x4, x2);
    return p2_mul(x6, x);
}

// ---- Poseidon2 permutation ----

// The external layer circ(2 M4, M4, M4) with M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]], plus the
// next round's constants. Each output is a sum of at most 29 terms below 2^64, so carry counts stay small.
static inline void p2_external(thread ulong *s, constant ulong *rc) {
    P2Acc y[12];
    P2_LANES
    for (int c = 0; c < 12; c += 4) {
        ulong x0 = s[c], x1 = s[c + 1], x2 = s[c + 2], x3 = s[c + 3];
        P2Acc t01 = p2_acc_add(p2_acc(x0), x1);
        P2Acc t23 = p2_acc_add(p2_acc(x2), x3);
        P2Acc t0123 = p2_acc_add2(t01, t23);
        P2Acc t01123 = p2_acc_add(t0123, x1);
        P2Acc t01233 = p2_acc_add(t0123, x3);
        y[c]     = p2_acc_add2(t01123, t01);                 // 2 x0 + 3 x1 + x2 + x3
        y[c + 1] = p2_acc_add2(t01123, p2_acc_double(x2));   // x0 + 2 x1 + 3 x2 + x3
        y[c + 2] = p2_acc_add2(t01233, t23);                 // x0 + x1 + 2 x2 + 3 x3
        y[c + 3] = p2_acc_add2(t01233, p2_acc_double(x0));   // 3 x0 + x1 + x2 + 2 x3
    }
    P2_LANES
    for (int k = 0; k < 4; k++) {
        P2Acc sum = p2_acc_add2(p2_acc_add2(y[k], y[k + 4]), y[k + 8]);
        s[k]     = p2_fold(p2_acc_add(p2_acc_add2(y[k], sum), rc[k]));
        s[k + 4] = p2_fold(p2_acc_add(p2_acc_add2(y[k + 4], sum), rc[k + 4]));
        s[k + 8] = p2_fold(p2_acc_add(p2_acc_add2(y[k + 8], sum), rc[k + 8]));
    }
}

// The internal layer: state[i] = sum + diag[i] * state[i], plus the next round's constants: rc0 on lane 0,
// or extra[i] on every lane for the last internal layer (which feeds terminal round 0).
static inline void p2_internal(thread ulong *s, ulong rc0, constant ulong *extra) {
    P2Acc sum = p2_acc(s[0]);
    P2_LANES
    for (int i = 1; i < 12; i++) sum = p2_acc_add(sum, s[i]);   // below 12 * 2^64
    P2_LANES
    for (int i = 0; i < 12; i++) {
        P2Acc a = extra ? p2_acc_add(sum, extra[i]) : (i == 0 ? p2_acc_add(sum, rc0) : sum);
        s[i] = p2_mul_add(s[i], P2_DIAG[i], a);
    }
}

static inline void p2_permute(thread ulong *s) {
    p2_external(s, P2_RC_EXT[0]);
    P2_FULL_LOOP
    for (int r = 0; r < 4; r++) {
        P2_LANES
        for (int i = 0; i < 12; i++) s[i] = p2_sbox(s[i]);
        p2_external(s, P2_RC_EXT[r + 1]);
    }
    P2_PARTIAL_LOOP
    for (int r = 0; r < 21; r++) {
        s[0] = p2_sbox(s[0]);
        p2_internal(s, P2_RC_PARTIAL_NEXT[r], nullptr);
    }
    s[0] = p2_sbox(s[0]);
    p2_internal(s, 0ul, P2_RC_TERMINAL0);
    P2_FULL_LOOP
    for (int r = 0; r < 4; r++) {
        P2_LANES
        for (int i = 0; i < 12; i++) s[i] = p2_sbox(s[i]);
        p2_external(s, P2_RC_EXT[r + 5]);
    }
}

// ---- Mining ----

// One job: the sponge after the header block and the nonce's high 32 bytes, plus the next six nonce
// felts (nonce bytes 32..55); the GPU adds the last two, which hold a big-endian 64-bit counter.
struct Poseidon2Job {
    ulong state[12];
    ulong target[8];   // U512 target, most significant word first
    ulong start;       // counter of thread 0
    uint count;        // threads that do work
    uint pad;
};

#define POSEIDON2_MAX_HITS 64
struct Poseidon2Hit {
    ulong counter;
    ulong hash[8];     // big-endian U512 words, most significant first
};
struct Poseidon2Output {
    atomic_uint count;
    uint pad;
    Poseidon2Hit hits[POSEIDON2_MAX_HITS];
};

// Per-nonce work up to the first digest: the counter's two felts (nonce bytes 56..63 read as
// little-endian u32s), permute, the padding block (terminator felt 1, pad felt 1), permute.
static inline void p2_first_digest(constant Poseidon2Job &job, ulong counter, thread ulong *s) {
    P2_LANES
    for (int i = 0; i < 12; i++) s[i] = job.state[i];
    s[6] = p2_add(s[6], ulong(bswap32(uint(counter >> 32))));
    s[7] = p2_add(s[7], ulong(bswap32(uint(counter))));
    p2_permute(s);
    s[0] = p2_add(s[0], 1ul);
    s[1] = p2_add(s[1], 1ul);
    p2_permute(s);
}

// Hash words 0-3 from the first digest, then the second squeeze for words 4-7. Word k is the k-th most
// significant 64 bits of the big-endian U512 (the digest felt's little-endian bytes, byte-swapped).
static inline void p2_hash_words(thread ulong *s, thread ulong *w) {
    P2_LANES
    for (int i = 0; i < 4; i++) w[i] = bswap64(p2_canon(s[i]));
    p2_permute(s);
    P2_LANES
    for (int i = 0; i < 4; i++) w[4 + i] = bswap64(p2_canon(s[i]));
}

kernel void poseidon2_search(constant Poseidon2Job &job [[buffer(0)]],
                             device Poseidon2Output &out [[buffer(1)]],
                             uint gid [[thread_position_in_grid]]) {
    if (gid >= job.count) return;
    ulong counter = job.start + gid;
    ulong s[12];
    p2_first_digest(job, counter, s);
#ifndef POSEIDON2_ALWAYS_SQUEEZE
    // The top 64 hash bits settle all but about 1 in 2^64 comparisons; finish the hash only when they don't.
    if (bswap64(p2_canon(s[0])) > job.target[0]) return;
#endif
    ulong w[8];
    p2_hash_words(s, w);
    bool below = false;
    P2_LANES
    for (int i = 7; i >= 0; i--) {   // the most significant differing word decides
        if (w[i] != job.target[i]) below = w[i] < job.target[i];
    }
    if (!below) return;
    uint slot = atomic_fetch_add_explicit(&out.count, 1u, memory_order_relaxed);
    if (slot < POSEIDON2_MAX_HITS) {
        out.hits[slot].counter = counter;
        P2_LANES
        for (int k = 0; k < 8; k++) out.hits[slot].hash[k] = w[k];
    }
}

// The search kernel's path for every nonce, writing all full hashes (cross-check only).
kernel void poseidon2_walk(constant Poseidon2Job &job [[buffer(0)]],
                           device ulong *out [[buffer(1)]],
                           uint gid [[thread_position_in_grid]]) {
    if (gid >= job.count) return;
    ulong s[12];
    p2_first_digest(job, job.start + gid, s);
    ulong w[8];
    p2_hash_words(s, w);
    P2_LANES
    for (int k = 0; k < 8; k++) out[8 * gid + k] = w[k];
}

// The whole sponge from scratch over arbitrary 96-byte inputs (header || nonce), cross-check only.
kernel void poseidon2_hash(device const uint *in [[buffer(0)]],
                           device ulong *out [[buffer(1)]],
                           constant uint &n [[buffer(2)]],
                           uint gid [[thread_position_in_grid]]) {
    if (gid >= n) return;
    ulong s[12];
    P2_LANES
    for (int i = 0; i < 12; i++) s[i] = 0;
    for (int b = 0; b < 3; b++) {
        P2_LANES
        for (int i = 0; i < 8; i++) s[i] = p2_add(s[i], ulong(in[24 * gid + 8 * b + i]));
        p2_permute(s);
    }
    s[0] = p2_add(s[0], 1ul);
    s[1] = p2_add(s[1], 1ul);
    p2_permute(s);
    ulong w[8];
    p2_hash_words(s, w);
    P2_LANES
    for (int k = 0; k < 8; k++) out[8 * gid + k] = w[k];
}
