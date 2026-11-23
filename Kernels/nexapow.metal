// NexaPow (Nexa) kernels, part 4 of 4: the per-nonce proof of work and the search, hash and table kernels.
// Library order: nexapow_field.metal, nexapow_sha.metal, nexapow_ec.metal, nexapow.metal.
//
// miningHash = sha256d(commitment || len || nonce), h1 = sha256(miningHash), sig = Schnorr signature of h1 with
// secret key miningHash (secp256k1, libsecp256k1 RFC6979 nonce with "Schnorr+SHA256  ", k negated unless
// jacobi(R.y) = 1, e = sha256(R.x || compressed P || h1), s = k + e x), powHash = sha256(R.x || s); a hit is
// powHash read as a little-endian 256-bit number <= target. One nonce per thread.
//
// The nonce (at most 16 bytes) is the pool's extranonce, then the thread's 64-bit counter little-endian, then any
// zero fill. The host lays out the mining hash's block words 8..15 (length byte, extranonce, fill, padding, bit
// length) with zeros where the counter goes, and says where that is (job.cword, job.cshift).
//
// Development switches (profiling only; results are wrong with them): NEXAPOW_SKIP_EC (no point
// multiplications), NEXAPOW_SKIP_POW (no exponentiation), NEXAPOW_SKIP_RFC (no HMAC-DRBG, k = x).

struct NexaPowJob {
    uint commit[8];   // header commitment, internal byte order, as big-endian SHA-256 words
    uint tail[8];     // block words 8..15 of the mining hash, zero where the counter goes
    uint cword;       // the block word holding the counter's first byte (8..10)
    uint cshift;      // 8 x that byte's position in the word (0, 8, 16 or 24)
    uint pad;         // 0 (nexapow_prof.metal reads it as a runtime zero)
    uint spare;       // 0
    uint target[8];   // little-endian 32-bit limbs
    uint ipad0[8];    // SHA-256 state after a block of 0x36 / 0x5c bytes (HMAC pads of the all-zero key)
    uint opad0[8];
};

struct NexaPowOut {
    uint mining[8];
    uint h1[8];
    uint sig[16];
    uint pow[8];
    bool valid;
    bool hit;
};

// UintToArith256(hash) <= target, with hash as SHA-256 digest words: limb l of the little-endian number
// is bswap32(word l). Computed as the borrow of target - number.
static inline bool np_meets_target(thread const uint *digest, constant uint *target)
{
    uint borrow = 0;
    #pragma unroll
    for (int l = 0; l < 8; l++) {
        ulong d = (ulong)target[l] - (ulong)bswap32(digest[l]) - (ulong)borrow;
        borrow = (uint)(d >> 63);
    }
    return borrow == 0;
}

static inline void np_nexapow(device const uint4 *table, constant NexaPowJob &job, ulong nonce, thread NexaPowOut &o)
{
    o.valid = false;
    o.hit = false;
    uint w[16], st[8];

    // miningHash = sha256d(commitment || len || nonce), one block: the counter's 8 little-endian bytes, read as a
    // big-endian 64-bit value, land in block words cword .. cword + 2, starting cshift bits into the first.
    ulong cbe = ((ulong)bswap32((uint)nonce) << 32) | (ulong)bswap32((uint)(nonce >> 32));
    uint c0 = (uint)(cbe >> (32 + job.cshift)), c1 = (uint)(cbe >> job.cshift), c2 = (uint)(cbe << (32 - job.cshift));
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint wi = 8u + (uint)i;
        w[i] = job.commit[i];
        st[i] = NP_IV[i];
        w[8 + i] = job.tail[i] | (wi == job.cword ? c0 : 0u) | (wi == job.cword + 1u ? c1 : 0u) | (wi == job.cword + 2u ? c2 : 0u);
    }
    np_sha256(st, w);
    uint mh[8], h1[8];
    np_sha256_32(st, mh);
    np_sha256_32(mh, h1);
    #pragma unroll
    for (int i = 0; i < 8; i++) { o.mining[i] = mh[i]; o.h1[i] = h1[i]; }

    // secret key x = miningHash read big-endian; invalid keys fail the proof of work
    np_fe x;
    #pragma unroll
    for (int i = 0; i < 8; i++) x.v[i] = mh[7 - i];
    if (!np_scalar_valid(x.v)) return;

    // RFC6979 nonce: HMAC-DRBG over x || h1 || "Schnorr+SHA256  " starting from K = 0, V = 0x01..01
    np_fe k;
#ifdef NEXAPOW_SKIP_RFC
    k = x;
#else
    uint blockB[16];
    blockB[0] = (mh[7] << 24) | (h1[0] >> 8);
    #pragma unroll
    for (int i = 1; i < 8; i++) blockB[i] = (h1[i - 1] << 24) | (h1[i] >> 8);
    blockB[8] = (h1[7] << 24) | 0x00536368u;   // "Sch"
    blockB[9] = 0x6E6F7272u;                     // "norr"
    blockB[10] = 0x2B534841u;                    // "+SHA"
    blockB[11] = 0x32353620u;                    // "256 "
    blockB[12] = 0x20800000u;                    // " ", then the 0x80 pad byte
    blockB[13] = 0;
    blockB[14] = 0;
    blockB[15] = 177 * 8;
    uint K[8], V[8], ik[8], ok[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) { ik[i] = job.ipad0[i]; ok[i] = job.opad0[i]; V[i] = 0x01010101u; }
    for (uint sep = 0; sep < 2; sep++) {
        np_hmac_keydata(ik, ok, V, sep, mh, blockB, K);
        np_hmac_pads(K, ik, ok);
        np_hmac32(ik, ok, V, V);
    }
    for (;;) {
        np_hmac32(ik, ok, V, V);
        #pragma unroll
        for (int i = 0; i < 8; i++) k.v[i] = V[7 - i];
        if (np_scalar_valid(k.v)) break;
        np_hmac33(ik, ok, V, K);   // retry (probability about 2^-128)
        np_hmac_pads(K, ik, ok);
        np_hmac32(ik, ok, V, V);
    }
#endif

    // P = x G and R = k G
    bool infP = false, infR = false;
    np_jac P, R;
#ifdef NEXAPOW_SKIP_EC
    np_load_affine(table + 4 * (ulong)(x.v[0] & 1023u), P.x, P.y);
    np_load_affine(table + 4 * (ulong)(k.v[1] & 1023u), R.x, R.y);
    P.z = np_fe_one();
    R.z = np_fe_one();
#else
    P = np_mul_g(table, x, infP);
    R = np_mul_g(table, k, infR);
#endif
    if (infP || infR) return;

    // One exponentiation gives both inverses and jacobi(R.y): with a = Zp^2 Yr Zr and t = a^((p-3)/4),
    // t^2 a = a^((p-1)/2) = jacobi(Yr Zr) = jacobi(R.y), and a^-1 = t^4 a.
    np_fe v = np_fe_mul(R.y, R.z);
    np_fe zp2 = np_fe_sqr(P.z);
    np_fe a = np_fe_mul(zp2, v);
#ifdef NEXAPOW_SKIP_POW
    np_fe t = a;
#else
    np_fe t = np_fe_pow_p34(a);
#endif
    np_fe t2 = np_fe_sqr(t);
    bool quad = np_fe_is_one(np_fe_mul(t2, a));
    np_fe ainv = np_fe_mul(np_fe_sqr(t2), a);
    np_fe zpi = np_fe_mul(ainv, np_fe_mul(P.z, v));
    np_fe zri = np_fe_mul(ainv, np_fe_mul(zp2, R.y));
    np_fe zpi2 = np_fe_sqr(zpi);
    np_fe px = np_fe_normalize(np_fe_mul(P.x, zpi2));
    np_fe py = np_fe_normalize(np_fe_mul(P.y, np_fe_mul(zpi2, zpi)));
    np_fe rx = np_fe_normalize(np_fe_mul(R.x, np_fe_sqr(zri)));
    if (!quad) np_scalar_negate(k.v);

    // e = sha256(R.x || 02/03 || P.x || h1), 97 bytes
    #pragma unroll
    for (int i = 0; i < 8; i++) { w[i] = rx.v[7 - i]; st[i] = NP_IV[i]; }
    w[8] = ((2u + (py.v[0] & 1u)) << 24) | (px.v[7] >> 8);
    #pragma unroll
    for (int i = 1; i < 8; i++) w[8 + i] = (px.v[8 - i] << 24) | (px.v[7 - i] >> 8);
    np_sha256(st, w);
    w[0] = (px.v[0] << 24) | (h1[0] >> 8);
    #pragma unroll
    for (int i = 1; i < 8; i++) w[i] = (h1[i - 1] << 24) | (h1[i] >> 8);
    w[8] = (h1[7] << 24) | 0x00800000u;
    #pragma unroll
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 97 * 8;
    np_sha256(st, w);
    uint e[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) e[i] = st[7 - i];
    if (!np_scalar_valid(e)) return;   // the node fails the signature here (probability about 2^-128)

    // s = k + e x mod n; signature = R.x || s
    uint s[8];
    np_scalar_muladd(e, x.v, k.v, s);
    #pragma unroll
    for (int i = 0; i < 8; i++) { o.sig[i] = rx.v[7 - i]; o.sig[8 + i] = s[7 - i]; }

    // powHash = sha256(signature), 64 bytes
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = o.sig[i];
    #pragma unroll
    for (int i = 0; i < 8; i++) st[i] = NP_IV[i];
    np_sha256(st, w);
    w[0] = 0x80000000u;
    #pragma unroll
    for (int i = 1; i < 15; i++) w[i] = 0;
    w[15] = 512;
    np_sha256(st, w);
    #pragma unroll
    for (int i = 0; i < 8; i++) o.pow[i] = st[i];
    o.valid = true;
    o.hit = np_meets_target(st, job.target);
}

kernel void nexapow_search(device const uint4 *table     [[buffer(0)]],
                           constant NexaPowJob &job       [[buffer(1)]],
                           constant ulong &startNonce     [[buffer(2)]],
                           device SearchOutput *out       [[buffer(3)]],
                           uint gid [[thread_position_in_grid]])
{
    ulong nonce = startNonce + gid;
    NexaPowOut o;
    np_nexapow(table, job, nonce, o);
    if (o.valid && o.hit) {
        uint slot = atomic_fetch_add_explicit(&out->count, 1u, memory_order_relaxed);
        if (slot < SEARCH_MAX_HITS) out->nonce[slot] = nonce;
    }
}

// Cross-checking: 48 words per nonce: miningHash, h1, signature (16), powHash, valid, hit, then the top six
// target limbs as this kernel read them (diagnostics).
kernel void nexapow_hash(device const uint4 *table     [[buffer(0)]],
                         constant NexaPowJob &job       [[buffer(1)]],
                         device const ulong *nonces     [[buffer(2)]],
                         device uint *results           [[buffer(3)]],
                         uint gid [[thread_position_in_grid]])
{
    NexaPowOut o;
    np_nexapow(table, job, nonces[gid], o);
    device uint *r = results + 48 * gid;
    for (int i = 0; i < 8; i++) { r[i] = o.mining[i]; r[8 + i] = o.h1[i]; r[32 + i] = o.valid ? o.pow[i] : 0; }
    for (int i = 0; i < 16; i++) r[16 + i] = o.valid ? o.sig[i] : 0;
    r[40] = o.valid ? 1 : 0;
    r[41] = o.hit ? 1 : 0;
    for (int i = 0; i < 6; i++) r[42 + i] = job.target[7 - i];
}

// Table entries [first, first + count): entry e is window e / TSIZE, multiple j = e % TSIZE + 1 of that
// window's base 2^(W i) G (bases: affine, 4 uint4 each). Output affine, 4 uint4 per entry.
kernel void nexapow_table(device const uint4 *bases [[buffer(0)]],
                          device uint4 *table       [[buffer(1)]],
                          constant uint &first      [[buffer(2)]],
                          constant uint &count      [[buffer(3)]],
                          uint gid [[thread_position_in_grid]])
{
    if (gid >= count) return;
    uint e = first + gid;
    uint window = e / NEXAPOW_TSIZE, j = e % NEXAPOW_TSIZE + 1;
    np_fe bx, by;
    np_load_affine(bases + 4 * window, bx, by);
    np_jac q;
    q.x = bx; q.y = by; q.z = np_fe_one();
    bool inf = false;
    for (int b = 30 - (int)clz(j); b >= 0; b--) {
        q = np_dbl(q);
        if ((j >> b) & 1u) np_madd(q, bx, by, inf);
    }
    np_fe zi = np_fe_inv(q.z);
    np_fe zi2 = np_fe_sqr(zi);
    np_fe ax = np_fe_normalize(np_fe_mul(q.x, zi2));
    np_fe ay = np_fe_normalize(np_fe_mul(q.y, np_fe_mul(zi2, zi)));
    device uint4 *o = table + 4 * (ulong)e;
    o[0] = uint4(ax.v[0], ax.v[1], ax.v[2], ax.v[3]);
    o[1] = uint4(ax.v[4], ax.v[5], ax.v[6], ax.v[7]);
    o[2] = uint4(ay.v[0], ay.v[1], ay.v[2], ay.v[3]);
    o[3] = uint4(ay.v[4], ay.v[5], ay.v[6], ay.v[7]);
}
