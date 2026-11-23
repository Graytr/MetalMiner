import Foundation

/// CPU reference for Tari's C29 proof of work: Cuckaroo29 exactly as Grin launched it, with Tari's key derivation,
/// proof packing and difficulty. Written from tari-project/tari base_layer/core/src/proof_of_work/cuckaroo_pow.rs and
/// siphash.rs (development branch, November 2026) and mimblewimble/grin core/src/pow/cuckaroo.rs.
///
/// - siphash keys: blake2b-256(nonce as 8 big-endian bytes || 32-byte mining hash), read as four little-endian u64s
/// - edge n: Cuckoo-style siphash-2-4 (the keys are the initial state, rotation 21) chained over the 64 nonces of n's
///   block; every value but the block's last is xored with the last; u = h & mask, v = (h >> 32) & mask
/// - proof: 42 ascending edge nonces whose edges form one cycle alternating between the U and V node sets
/// - proof hash: blake2b-256 of the nonces bit-packed 29 bits each, least significant bit first (153 bytes)
/// - difficulty: (2^256 - 1) / proof hash read as a big-endian number, capped at 2^64 - 1
enum Cuckaroo29Reference {
    static let cycleLength = 42

    // MARK: BLAKE2b (RFC 7693), unkeyed

    static let blakeIV: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]
    static let blakeSigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    static func blake2b(_ input: [UInt8], outputBytes: Int = 32) -> [UInt8] {
        var h = blakeIV
        h[0] ^= 0x0101_0000 ^ UInt64(outputBytes)
        var offset = 0
        var counter: UInt64 = 0
        repeat {
            let take = min(128, input.count - offset)
            counter += UInt64(take)
            var m = [UInt64](repeating: 0, count: 16)
            for i in 0 ..< take { m[i / 8] |= UInt64(input[offset + i]) << (8 * UInt64(i % 8)) }
            blakeCompress(&h, m, counter, last: offset + take == input.count)
            offset += take
        } while offset < input.count
        var out: [UInt8] = []
        for word in h { out.appendLE(word) }
        return Array(out.prefix(outputBytes))
    }

    static func blakeCompress(_ h: inout [UInt64], _ m: [UInt64], _ counter: UInt64, last: Bool) {
        var v = h + blakeIV
        v[12] ^= counter
        if last { v[14] = ~v[14] }
        func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x &>> n) | (x &<< (64 &- n)) }
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotr(v[d] ^ v[a], 32)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 63)
        }
        for r in 0 ..< 12 {
            let s = blakeSigma[r % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0 ..< 8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    // MARK: Cuckoo-style siphash-2-4

    struct Sip {
        var v0: UInt64, v1: UInt64, v2: UInt64, v3: UInt64

        init(_ keys: [UInt64]) {
            v0 = keys[0]
            v1 = keys[1]
            v2 = keys[2]
            v3 = keys[3]
        }

        @inline(__always) static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 { (x &<< n) | (x &>> (64 &- n)) }

        @inline(__always) mutating func round() {
            v0 &+= v1; v2 &+= v3; v1 = Sip.rotl(v1, 13); v3 = Sip.rotl(v3, 16)
            v1 ^= v0; v3 ^= v2; v0 = Sip.rotl(v0, 32); v2 &+= v1; v0 &+= v3
            v1 = Sip.rotl(v1, 17); v3 = Sip.rotl(v3, 21); v1 ^= v2; v3 ^= v0; v2 = Sip.rotl(v2, 32)
        }

        /// One siphash-2-4 of `nonce`, continuing from the current state: Cuckaroo chains a block's 64 hashes.
        @inline(__always) mutating func hash24(_ nonce: UInt64) -> UInt64 {
            v3 ^= nonce
            round(); round()
            v0 ^= nonce
            v2 ^= 0xFF
            round(); round(); round(); round()
            return (v0 ^ v1) ^ (v2 ^ v3)
        }
    }

    static func siphash24(_ keys: [UInt64], _ nonce: UInt64) -> UInt64 {
        var sip = Sip(keys)
        return sip.hash24(nonce)
    }

    /// The 64 final values of siphash block `block` (edge nonces 64 * block ... 64 * block + 63).
    static func blockValues(_ keys: [UInt64], block: Int, into out: UnsafeMutablePointer<UInt64>) {
        var sip = Sip(keys)
        let first = UInt64(block) << 6
        for i in 0 ..< 64 { out[i] = sip.hash24(first + UInt64(i)) }
        let last = out[63]
        for i in 0 ..< 63 { out[i] ^= last }
    }

    /// Tari's siphash_block(keys, nonce, 21).
    static func sipblock(_ keys: [UInt64], _ nonce: UInt64) -> UInt64 {
        withUnsafeTemporaryAllocation(of: UInt64.self, capacity: 64) { buffer in
            blockValues(keys, block: Int(nonce >> 6), into: buffer.baseAddress!)
            return buffer[Int(nonce & 63)]
        }
    }

    /// Edge `nonce` as (u, v).
    static func edge(_ keys: [UInt64], _ nonce: UInt64, edgeBits: Int) -> SIMD2<UInt32> {
        let h = sipblock(keys, nonce)
        let mask = (UInt64(1) << UInt64(edgeBits)) - 1
        return SIMD2(UInt32(h & mask), UInt32((h >> 32) & mask))
    }

    // MARK: Keys, verification, proof hash, difficulty

    /// Tari's determine_sip_hash: blake2b-256(nonce big-endian || mining hash).
    static func keyBytes(miningHash: [UInt8], nonce: UInt64) -> [UInt8] {
        var input: [UInt8] = []
        withUnsafeBytes(of: nonce.bigEndian) { input.append(contentsOf: $0) }
        return blake2b(input + miningHash)
    }

    static func keys(fromBytes bytes: [UInt8]) -> [UInt64] { (0 ..< 4).map { bytes.le64(at: 8 * $0) } }

    static func keys(miningHash: [UInt8], nonce: UInt64) -> [UInt64] {
        keys(fromBytes: keyBytes(miningHash: miningHash, nonce: nonce))
    }

    /// The (u, v) endpoints of `nonces`, checking Tari's nonce rules (in range, strictly ascending).
    static func endpoints(keys: [UInt64], nonces: [UInt64], edgeBits: Int) -> (uvs: [UInt64], problem: String?) {
        let mask = (UInt64(1) << UInt64(edgeBits)) - 1
        var uvs: [UInt64] = []
        for (n, nonce) in nonces.enumerated() {
            if nonce > mask { return ([], "nonce too large") }
            if n > 0 && nonce <= nonces[n - 1] { return ([], "nonces not ascending") }
            let h = sipblock(keys, nonce)
            uvs.append(h & mask)
            uvs.append((h >> 32) & mask)
        }
        return (uvs, nil)
    }

    /// Tari's post-fork bipartite verifier (verify_from_edges_bipartite, a port of Grin's cuckaroo verify).
    /// Returns nil for a valid cycle, otherwise the reason it fails.
    static func verify(keys: [UInt64], nonces: [UInt64], edgeBits: Int, cycleLength: Int = cycleLength) -> String? {
        guard nonces.count == cycleLength else { return "wrong number of nonces" }
        let (uvs, problem) = endpoints(keys: keys, nonces: nonces, edgeBits: edgeBits)
        if let problem { return problem }
        var xor0: UInt64 = 0, xor1: UInt64 = 0
        for n in 0 ..< cycleLength {
            xor0 ^= uvs[2 * n]
            xor1 ^= uvs[2 * n + 1]
        }
        if xor0 != 0 || xor1 != 0 { return "endpoints don't match" }
        let size = 2 * cycleLength
        var n = 0, i = 0
        repeat {
            var j = i, k = i
            while true {
                k = (k + 2) % size
                if k == i { break }
                if uvs[k] == uvs[i] {
                    if j != i { return "branch in cycle" }
                    j = k
                }
            }
            if j == i { return "cycle dead ends" }
            i = j ^ 1
            n += 1
        } while i != 0
        return n == cycleLength ? nil : "cycle too short"
    }

    /// Bit-packs nonces `edgeBits` bits each, least significant bit first (Tari's canonical pow_data).
    static func pack(_ nonces: [UInt64], edgeBits: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: (nonces.count * edgeBits + 7) / 8)
        var bit = 0
        for nonce in nonces {
            for k in 0 ..< edgeBits where (nonce >> UInt64(k)) & 1 == 1 {
                out[(bit + k) >> 3] |= UInt8(1) << UInt8((bit + k) & 7)
            }
            bit += edgeBits
        }
        return out
    }

    /// Inverse of `pack`; nil unless the length is exact and the unused high bits are zero (Tari's canonical form).
    static func unpack(_ bytes: [UInt8], edgeBits: Int, count: Int) -> [UInt64]? {
        guard bytes.count == (count * edgeBits + 7) / 8 else { return nil }
        func bit(_ i: Int) -> UInt64 { UInt64(bytes[i >> 3] >> UInt8(i & 7)) & 1 }
        for i in count * edgeBits ..< bytes.count * 8 where bit(i) == 1 { return nil }
        return (0 ..< count).map { n in
            (0 ..< edgeBits).reduce(UInt64(0)) { $0 | bit(n * edgeBits + $1) << UInt64($1) }
        }
    }

    /// Tari's Difficulty::big_endian_difficulty: floor((2^256 - 1) / H), H the hash read big-endian, capped at 2^64 - 1.
    static func difficulty(hash: [UInt8]) -> UInt64 {
        let h = (0 ..< 4).map { i in (0 ..< 8).reduce(UInt64(0)) { $0 << 8 | UInt64(hash[8 * i + $1]) } }
        if h[0] == 0 { return .max }   // H < 2^192: the quotient is at least 2^64 (H = 0 is an error in Tari)
        // q * H <= 2^256 - 1 exactly when the 320-bit product has nothing above bit 255
        func fits(_ q: UInt64) -> Bool {
            var carry: UInt64 = 0
            for limb in h.reversed() {
                let (high, low) = q.multipliedFullWidth(by: limb)
                let (_, overflow) = low.addingReportingOverflow(carry)
                carry = high &+ (overflow ? 1 : 0)
            }
            return carry == 0
        }
        var q: UInt64 = 0
        for bit in stride(from: 63, through: 0, by: -1) where fits(q | UInt64(1) << UInt64(bit)) {
            q |= UInt64(1) << UInt64(bit)
        }
        return q
    }

    // MARK: Helpers for the GPU checks

    /// A bijective 64-bit mix of a stored edge (x, y); bucket fingerprints are wrapping sums of these.
    @inline(__always) static func fingerprint(_ x: UInt32, _ y: UInt32) -> UInt64 {
        var z = UInt64(x) | UInt64(y) << 32
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    /// Runs `job(chunk, counts, sums)` for every chunk on all cores, each with its own zeroed per-bucket counters,
    /// and returns the totals per bucket.
    static func perBucketTotals(buckets: Int, chunks: Int,
                                _ job: (Int, UnsafeMutablePointer<UInt32>, UnsafeMutablePointer<UInt64>) -> Void)
        -> (counts: [UInt32], sums: [UInt64]) {
        let counts = UnsafeMutablePointer<UInt32>.allocate(capacity: chunks * buckets)
        counts.initialize(repeating: 0, count: chunks * buckets)
        let sums = UnsafeMutablePointer<UInt64>.allocate(capacity: chunks * buckets)
        sums.initialize(repeating: 0, count: chunks * buckets)
        defer {
            counts.deallocate()
            sums.deallocate()
        }
        DispatchQueue.concurrentPerform(iterations: chunks) { c in job(c, counts + c * buckets, sums + c * buckets) }
        var totalCounts = [UInt32](repeating: 0, count: buckets)
        var totalSums = [UInt64](repeating: 0, count: buckets)
        for c in 0 ..< chunks {
            for b in 0 ..< buckets {
                totalCounts[b] &+= counts[c * buckets + b]
                totalSums[b] &+= sums[c * buckets + b]
            }
        }
        return (totalCounts, totalSums)
    }

    /// What seeding must produce: per U bucket (top edgeBits - zBits bits of u), the edge count and fingerprint sum.
    static func seedTotals(keys: [UInt64], edgeBits: Int, zBits: Int) -> (counts: [UInt32], sums: [UInt64]) {
        let blocks = 1 << (edgeBits - 6)
        let chunks = min(blocks, 256)
        let perChunk = blocks / chunks
        let mask = (UInt64(1) << UInt64(edgeBits)) - 1
        let shift = UInt32(zBits)
        return perBucketTotals(buckets: 1 << (edgeBits - zBits), chunks: chunks) { c, counts, sums in
            withUnsafeTemporaryAllocation(of: UInt64.self, capacity: 64) { buffer in
                let values = buffer.baseAddress!
                for block in c * perChunk ..< (c + 1) * perChunk {
                    blockValues(keys, block: block, into: values)
                    for i in 0 ..< 64 {
                        let u = UInt32(values[i] & mask), v = UInt32((values[i] >> 32) & mask)
                        let b = Int(u >> shift)
                        counts[b] &+= 1
                        sums[b] &+= fingerprint(u, v)
                    }
                }
            }
        }
    }

    /// Independent trimming reference for small graphs: every edge, whole-graph degree counts, `rounds` rounds
    /// (odd rounds count U nodes, even rounds V nodes). Returns the surviving edges as (u, v), sorted.
    static func trimmed(keys: [UInt64], edgeBits: Int, rounds: Int) -> [SIMD2<UInt32>] {
        let n = 1 << edgeBits
        let mask = (UInt64(1) << UInt64(edgeBits)) - 1
        var us = [UInt32](repeating: 0, count: n), vs = [UInt32](repeating: 0, count: n)
        withUnsafeTemporaryAllocation(of: UInt64.self, capacity: 64) { buffer in
            for block in 0 ..< n / 64 {
                blockValues(keys, block: block, into: buffer.baseAddress!)
                for i in 0 ..< 64 {
                    us[64 * block + i] = UInt32(buffer[i] & mask)
                    vs[64 * block + i] = UInt32((buffer[i] >> 32) & mask)
                }
            }
        }
        var alive = Array(0 ..< n)
        for round in stride(from: 1, through: rounds, by: 1) {
            let side = round % 2 == 1 ? us : vs
            var degree = [UInt8](repeating: 0, count: n)
            for e in alive where degree[Int(side[e])] < 2 { degree[Int(side[e])] += 1 }
            alive = alive.filter { degree[Int(side[$0])] >= 2 }
        }
        return sortedEdges(alive.map { SIMD2(us[$0], vs[$0]) })
    }

    static func sortedEdges(_ edges: [SIMD2<UInt32>]) -> [SIMD2<UInt32>] {
        edges.sorted { $0.x != $1.x ? $0.x < $1.x : $0.y < $1.y }
    }
}
