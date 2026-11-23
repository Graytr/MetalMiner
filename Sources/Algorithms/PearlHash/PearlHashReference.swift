import Foundation

/// Pearl's `MiningConfiguration` (zk-pow src/api/proof.rs): what a miner commits to in the job key.
struct PearlHashConfig {
    /// Common dimension of the product (`common_dim`).
    var k: Int
    /// Noise rank: partial sums are folded into the jackpot after every `rank` products.
    var rank: Int
    /// Row offsets of A and column offsets of B that make up one jackpot tile (`rows_pattern`, `cols_pattern`).
    var rows: [Int]
    var cols: [Int]

    /// The default configuration of Pearl's own miner (zk-pow bindings/go/src/mine.rs `build_default_config`):
    /// rank on the rank-penalty floor (128), k = 16 * rank, a 4 x 8 tile.
    static func standard(k: Int = 2048) -> PearlHashConfig {
        PearlHashConfig(k: k, rank: 128, rows: [0, 8, 64, 72], cols: [0, 1, 8, 9, 32, 33, 40, 41])
    }

    var dotProductLength: Int { k - k % rank }
    var tileSize: Int { rows.count * cols.count }
    /// Consensus `extract_difficulty_bound`: the target is multiplied by the work of one attempt.
    var attemptWork: Int { tileSize * dotProductLength }
    /// The rank-penalty rule (mainnet from height 96,251): tile size * (dot length / rank) * 128.
    /// Equal to `attemptWork` at rank 128. This is the "hashes" one jackpot attempt is worth.
    var penalizedAttemptWork: Int { tileSize * (dotProductLength / rank) * 128 }

    /// `PeriodicPattern::from_list`: (stride, length) dimensions, innermost first, padded to 3.
    static func shape(_ list: [Int]) -> [(stride: Int, length: Int)] {
        var p = list
        var dims: [(stride: Int, length: Int)] = []
        while p.count > 1 {
            var found = false
            for period in 1 ..< p.count where p.count % period == 0 {
                let s = p[period]
                if (0 ..< p.count - period).allSatisfy({ p[$0] + s == p[$0 + period] }) {
                    dims.append((s, p.count / period))
                    p = Array(p[0 ..< period])
                    found = true
                    break
                }
            }
            precondition(found, "pattern \(list) is not periodic")
        }
        dims.reverse()
        let period = dims.last.map { $0.stride * $0.length } ?? 1
        while dims.count < 3 { dims.append((period, 1)) }
        return dims
    }

    /// `PeriodicPattern::to_bytes`: (factor - 1, length - 1) per dimension.
    static func patternBytes(_ list: [Int]) -> [UInt8] {
        var out: [UInt8] = []
        var minStride = 1
        for d in shape(list) {
            out.append(UInt8(d.stride / minStride - 1))
            out.append(UInt8(d.length - 1))
            minStride = d.stride * d.length
        }
        return out
    }

    /// `PeriodicPattern::offset_is_valid`: offsets whose pattern copies tile the dimension.
    static func offsetIsValid(_ list: [Int], _ offset: Int) -> Bool {
        var o = offset
        for d in shape(list).reversed() {
            o %= d.stride * d.length
            if o >= d.stride { return false }
        }
        return true
    }

    /// The 52 serialized bytes: k (u32) | rank (u16) | mma type 0 (u16) | rows (6) | cols (6) | 32 zero bytes (no MoE).
    var bytes: [UInt8] {
        var b: [UInt8] = []
        b.appendLE(UInt32(k))
        b.appendLE(UInt16(rank))
        b.appendLE(UInt16(0))
        b += PearlHashConfig.patternBytes(rows)
        b += PearlHashConfig.patternBytes(cols)
        b += [UInt8](repeating: 0, count: 32)
        return b
    }
}

/// The part of a Pearl block header that PearlHash hashes (zk-pow `IncompleteBlockHeader`): the wire
/// header (node/wire/blockheader.go) without its trailing 32-byte ProofCommitment.
struct PearlHashHeader {
    var version: UInt32
    /// Hashes in wire (internal) byte order, i.e. reversed from how explorers print them.
    var prevBlock: [UInt8]
    var merkleRoot: [UInt8]
    var timestamp: UInt32
    var bits: UInt32

    static func wireOrder(display hex: String) -> [UInt8] { Array([UInt8](hex: hex)!.reversed()) }

    /// version (LE) | prev block | merkle root | time (LE) | bits (LE): 76 bytes.
    var bytes: [UInt8] {
        var b: [UInt8] = []
        b.appendLE(version)
        b += prevBlock
        b += merkleRoot
        b.appendLE(timestamp)
        b.appendLE(bits)
        return b
    }
}

/// rand_chacha 0.9 `ChaCha20Rng` seeded with rand_core 0.9 `seed_from_u64`, and rand 0.9's
/// `random_range(-64..=64)` for i8, to rebuild the matrices behind zk-pow's proof fixture.
struct PearlHashChaCha20Rng {
    private var key: [UInt32] = []
    private var counter: UInt64 = 0
    private var buffer = [UInt32](repeating: 0, count: 16)
    private var index = 16

    init(seedFromU64 seed: UInt64) {
        var state = seed
        for _ in 0 ..< 8 {   // PCG32, one 4-byte word of the 32-byte seed at a time
            state = state &* 6_364_136_223_846_793_005 &+ 11_634_580_027_462_260_723
            let xorshifted = UInt32(truncatingIfNeeded: ((state >> 18) ^ state) >> 27)
            let rot = UInt32(truncatingIfNeeded: state >> 59)
            key.append((xorshifted >> rot) | (xorshifted << ((32 - rot) & 31)))
        }
    }

    @inline(__always)
    private static func quarter(_ a: inout UInt32, _ b: inout UInt32, _ c: inout UInt32, _ d: inout UInt32) {
        a = a &+ b; d ^= a; d = (d << 16) | (d >> 16)
        c = c &+ d; b ^= c; b = (b << 12) | (b >> 20)
        a = a &+ b; d ^= a; d = (d << 8) | (d >> 24)
        c = c &+ d; b ^= c; b = (b << 7) | (b >> 25)
    }

    /// One ChaCha20 block: 64-bit block counter in words 12-13, stream (nonce) 0 in words 14-15.
    private mutating func refill() {
        let j: [UInt32] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574,
                           key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                           UInt32(truncatingIfNeeded: counter), UInt32(truncatingIfNeeded: counter >> 32), 0, 0]
        var x0 = j[0], x1 = j[1], x2 = j[2], x3 = j[3], x4 = j[4], x5 = j[5], x6 = j[6], x7 = j[7]
        var x8 = j[8], x9 = j[9], x10 = j[10], x11 = j[11], x12 = j[12], x13 = j[13], x14 = j[14], x15 = j[15]
        for _ in 0 ..< 10 {
            Self.quarter(&x0, &x4, &x8, &x12); Self.quarter(&x1, &x5, &x9, &x13)
            Self.quarter(&x2, &x6, &x10, &x14); Self.quarter(&x3, &x7, &x11, &x15)
            Self.quarter(&x0, &x5, &x10, &x15); Self.quarter(&x1, &x6, &x11, &x12)
            Self.quarter(&x2, &x7, &x8, &x13); Self.quarter(&x3, &x4, &x9, &x14)
        }
        let x = [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15]
        for i in 0 ..< 16 { buffer[i] = x[i] &+ j[i] }
        counter &+= 1
        index = 0
    }

    mutating func nextU32() -> UInt32 {
        if index >= 16 { refill() }
        let value = buffer[index]
        index += 1
        return value
    }

    /// rand 0.9 `UniformInt<i8>::sample_single_inclusive(-64, 64)` (default, non-"unbiased" build):
    /// a 32-bit widening multiply by 129, with one extra draw when the low half lands in the biased zone.
    mutating func int7() -> Int8 {
        let product = UInt64(nextU32()) * 129
        var result = UInt32(product >> 32)
        let low = UInt32(truncatingIfNeeded: product)
        if low > UInt32(0) &- 129 {
            let high = UInt32((UInt64(nextU32()) * 129) >> 32)
            if low.addingReportingOverflow(high).overflow { result += 1 }
        }
        return Int8(Int(result) - 64)
    }
}

/// CPU reference for PearlHash, written from Pearl's Rust sources (zk-pow src/ffi/mine.rs, src/api/*.rs,
/// src/circuit/pearl_noise.rs, pearl-blake3) and checked against the vectors pinned in that code.
enum PearlHashReference {
    /// Domain-separation salts of the V3 (salted) seed derivation (zk-pow src/api/seed.rs).
    static let saltA = [UInt8](hex: "8249406ca0ed15169616f692fcf076f892dbdb2a7023b852f0d47719c390017b")!
    static let saltB = [UInt8](hex: "11300632ec6301ca2be2af718b3f4d4f1ae9c63988e8cc044844301d71b89aa9")!
    static let labelA = Array("A_tensor".utf8) + [UInt8](repeating: 0, count: 24)
    static let labelB = Array("B_tensor".utf8) + [UInt8](repeating: 0, count: 24)

    /// job_key = BLAKE3(header (76 bytes) || mining configuration (52 bytes)).
    static func jobKey(_ header: PearlHashHeader, _ config: PearlHashConfig) -> [UInt8] {
        PearlHashBlake3.hash(header.bytes + config.bytes)
    }

    /// Matrix commitment: keyed BLAKE3 (key = job_key) of the bytes zero-padded to whole 1,024-byte chunks,
    /// which equals the root of pearl-blake3's Merkle tree. A is hashed row-major, B column-major (B^T row-major).
    static func commitment(_ matrix: [UInt8], jobKey: [UInt8]) -> [UInt8] {
        let padded = matrix.count % 1024 == 0 ? matrix : matrix + [UInt8](repeating: 0, count: 1024 - matrix.count % 1024)
        return PearlHashBlake3.hash(padded, key: jobKey)
    }

    /// V3 salting: BLAKE3(root || dimension (u32 LE) || 28 zero bytes, key = salt).
    static func bindRoot(_ root: [UInt8], dimension: Int, salt: [UInt8]) -> [UInt8] {
        var message = root
        message.appendLE(UInt32(dimension))
        message += [UInt8](repeating: 0, count: 28)
        return PearlHashBlake3.hash(message, key: salt)
    }

    /// `PublicProofParams::commitment_hash`: b = BLAKE3(job_key || hash_b), a = BLAKE3(b || hash_a),
    /// with the roots salted first under V3 (mainnet from height 99,000).
    static func noiseSeeds(jobKey: [UInt8], hashA: [UInt8], hashB: [UInt8], m: Int, n: Int, salted: Bool) -> (a: [UInt8], b: [UInt8]) {
        let ha = salted ? bindRoot(hashA, dimension: m, salt: saltA) : hashA
        let hb = salted ? bindRoot(hashB, dimension: n, salt: saltB) : hashB
        let b = PearlHashBlake3.hash(jobKey + hb)
        return (PearlHashBlake3.hash(b + ha), b)
    }

    /// `get_random_hash`: BLAKE3(8 i32 slots with slot `slot` = index + 1 || 32-byte label, key = seed).
    static func randomHash(index: Int, label: [UInt8], key: [UInt8], slot: Int) -> [UInt8] {
        var message = [UInt8](repeating: 0, count: 32)
        let value = UInt32(truncatingIfNeeded: index + 1)
        for i in 0 ..< 4 { message[4 * slot + i] = UInt8(truncatingIfNeeded: value >> UInt32(8 * i)) }
        return PearlHashBlake3.hash(message + label, key: key)
    }

    /// Row `row` of a uniform noise factor (E_AL, or a row of E_BR^T): `rank` values in -32...31.
    static func uniformRow(_ row: Int, rank: Int, label: [UInt8], key: [UInt8]) -> [Int8] {
        var out: [Int8] = []
        out.reserveCapacity(rank)
        var block = -1
        var hash: [UInt8] = []
        for i in row * rank ..< (row + 1) * rank {
            if i / 32 != block {
                block = i / 32
                hash = randomHash(index: block, label: label, key: key, slot: 0)
            }
            out.append(Int8(Int(hash[i % 32] & 63) - 32))
        }
        return out
    }

    /// The sparse factor (E_AR^T or E_BL): for each of the k positions, the rank index with +1 and the one with -1.
    static func permutation(k: Int, rank: Int, label: [UInt8], key: [UInt8]) -> [(plus: Int, minus: Int)] {
        var out: [(plus: Int, minus: Int)] = []
        out.reserveCapacity(k)
        let mask = UInt32(rank - 1)
        for draw in 0 ..< (k + 7) / 8 {
            let hash = randomHash(index: draw, label: label, key: key, slot: 1)
            for j in 0 ..< 8 where draw * 8 + j < k {
                let w = hash.le32(at: 4 * j)
                let first = w & mask
                let second = first ^ (1 + UInt32((UInt64(mask) * UInt64(w)) >> 32))
                out.append((Int(first), Int(second)))
            }
        }
        return out
    }

    /// A row of A + E_A (or a column of B + E_B): base[l] + e[plus(l)] - e[minus(l)].
    static func noised(_ base: ArraySlice<UInt8>, e: [Int8], perm: [(plus: Int, minus: Int)]) -> [Int8] {
        var out = [Int8](repeating: 0, count: perm.count)
        var l = 0
        for byte in base {
            out[l] = Int8(Int(Int8(bitPattern: byte)) + Int(e[perm[l].plus]) - Int(e[perm[l].minus]))
            l += 1
        }
        return out
    }

    /// One attempt's 16 jackpot words: after every `rank` products the tile's int32 partial sums are XORed
    /// together and folded into word (block mod 16) with a 13-bit left rotation.
    static func jackpot(rows: [[Int8]], cols: [[Int8]], config: PearlHashConfig) -> [UInt32] {
        let h = rows.count, w = cols.count, rank = config.rank
        var acc = [Int32](repeating: 0, count: h * w)
        var jp = [UInt32](repeating: 0, count: 16)
        for block in 0 ..< config.dotProductLength / rank {
            for u in 0 ..< h {
                rows[u].withUnsafeBufferPointer { a in
                    for v in 0 ..< w {
                        cols[v].withUnsafeBufferPointer { b in
                            var s: Int32 = 0
                            for l in block * rank ..< (block + 1) * rank { s &+= Int32(a[l]) &* Int32(b[l]) }
                            acc[u * w + v] &+= s
                        }
                    }
                }
            }
            var x: UInt32 = 0
            for value in acc { x ^= UInt32(bitPattern: value) }
            let t = block % 16
            jp[t] = ((jp[t] << 13) | (jp[t] >> 19)) ^ x
        }
        return jp
    }

    /// BLAKE3(jackpot words, little-endian, key = A's noise seed).
    static func jackpotHash(_ jp: [UInt32], aSeed: [UInt8]) -> [UInt8] {
        PearlHashBlake3.hash(PearlHashBlake3.bytes(jp), key: aSeed)
    }

    /// `nbits_to_difficulty`: the compact target as 8 little-endian words.
    static func target(bits: UInt32) -> [UInt32] {
        let exponent = Int(bits >> 24)
        let mantissa = bits & 0x00FF_FFFF
        var t = [UInt32](repeating: 0, count: 8)
        if mantissa == 0 || exponent == 0 || mantissa & 0x0080_0000 != 0 { return t }
        if exponent <= 3 {
            t[0] = mantissa >> UInt32(8 * (3 - exponent))
            return t
        }
        let shift = 8 * (exponent - 3)
        let word = shift / 32
        let wide = UInt64(mantissa) << UInt64(shift % 32)
        if word < 8 { t[word] = UInt32(truncatingIfNeeded: wide) }
        if word + 1 < 8 { t[word + 1] = UInt32(truncatingIfNeeded: wide >> 32) }
        return t
    }

    /// target * factor, saturating at 2^256 - 1 like consensus `scale`.
    static func scale(_ target: [UInt32], by factor: Int) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: 8)
        var carry: UInt64 = 0
        for i in 0 ..< 8 {
            let p = UInt64(target[i]) * UInt64(factor) + carry
            out[i] = UInt32(truncatingIfNeeded: p)
            carry = p >> 32
        }
        return carry == 0 ? out : [UInt32](repeating: .max, count: 8)
    }

    /// The jackpot hash read as a little-endian 256-bit number, compared with an inclusive bound.
    static func meets(_ hash: [UInt8], _ bound: [UInt32]) -> Bool {
        for w in stride(from: 7, through: 0, by: -1) {
            let h = hash.le32(at: 4 * w)
            if h != bound[w] { return h < bound[w] }
        }
        return true
    }

    // MARK: - Known-answer vectors

    static func runVectors() throws -> [String] {
        [try blake3Vectors(), try seedVectors(), try fixtureVector()]
    }

    /// BLAKE3 official test vectors (BLAKE3-team/BLAKE3 test_vectors/test_vectors.json): input byte i = i % 251,
    /// first 32 bytes of `hash` and `keyed_hash`; also the left-path rehash against a full hash.
    static func blake3Vectors() throws -> String {
        let key = Array("whats the Elvish word for friend".utf8)
        let cases: [(Int, String, String)] = [
            (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
            (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"),
            (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"),
            (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e"),
            (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"),
            (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69"),
            (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1"),
            (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5"),
            (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a"),
            (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b", "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5"),
            (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4", "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d"),
            (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47", "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419"),
            (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7"),
        ]
        for (length, plain, keyed) in cases {
            let input = (0 ..< length).map { UInt8($0 % 251) }
            let h = PearlHashBlake3.hash(input).hex
            let kh = PearlHashBlake3.hash(input, key: key).hex
            guard h == plain else { throw MinerError("BLAKE3 hash, \(length) bytes: \(h), expected \(plain)") }
            guard kh == keyed else { throw MinerError("BLAKE3 keyed hash, \(length) bytes: \(kh), expected \(keyed)") }
        }
        // Rehashing through the left path (as mining does after changing the first chunk) gives the full hash.
        let data = (0 ..< 102400).map { UInt8($0 % 251) }
        var changed = data
        for i in 0 ..< 32 { changed[i] ^= 0x5A }
        let path = PearlHashBlake3.LeftPath(data: data, key: key)
        let viaPath = changed.withUnsafeBytes { path.root(firstChunk: UnsafeRawBufferPointer(rebasing: $0[0 ..< 1024])) }
        guard viaPath == PearlHashBlake3.hash(changed, key: key) else { throw MinerError("BLAKE3 left-path rehash differs from the full hash") }
        return "BLAKE3: official hash + keyed_hash vectors at \(cases.count) lengths (0 to 102,400 bytes) match; left-path rehash matches"
    }

    /// zk-pow src/api/seed.rs: the V3 salts are BLAKE3 of their context strings, and the pinned
    /// `commitment_hash_pinned_vectors` (job_key 0x11.., hash_a 0xAA.., hash_b 0xBB.., m 192, n 320).
    static func seedVectors() throws -> String {
        guard PearlHashBlake3.hash(Array("pearl/cert-v3/noise-seed/A".utf8)) == saltA,
              PearlHashBlake3.hash(Array("pearl/cert-v3/noise-seed/B".utf8)) == saltB
        else { throw MinerError("V3 seed salts differ from BLAKE3 of their context strings") }
        let jobKey = [UInt8](repeating: 0x11, count: 32)
        let hashA = [UInt8](repeating: 0xAA, count: 32)
        let hashB = [UInt8](repeating: 0xBB, count: 32)
        let expected: [(Bool, String, String)] = [
            (false, "add6f7ea5feebf89c8a77e2ebfa0d82442e7dbb0046dbd48971861d12fcb0177", "483b07b6f73105030b9482255f37723f3fed69ae916724ee8291848b8c28794b"),
            (true, "60ed9b73c5a9599b200b6cd563e7f0d5d9a67d2402d85fd4ef966c580080d0e5", "301784168005ec833ab0aa60006f7fe7faaa95307d8c1fc6819b2ffdd717eccf"),
        ]
        for (salted, b, a) in expected {
            let seeds = noiseSeeds(jobKey: jobKey, hashA: hashA, hashB: hashB, m: 192, n: 320, salted: salted)
            guard seeds.b.hex == b, seeds.a.hex == a else {
                throw MinerError("\(salted ? "salted" : "legacy") noise seeds \(seeds.b.hex) / \(seeds.a.hex), expected \(b) / \(a)")
            }
        }
        return "noise seeds: V3 salts and zk-pow's pinned legacy + salted commitment_hash vectors match"
    }

    /// zk-pow fixures/v2_stark_proof.bin, a proof mined by the official code (src/circuit/compat_test.rs):
    /// ChaCha20Rng::seed_from_u64(0xdeadbeef) fills A (6144 x 1216) then B (1216 x 4096) with -64...64;
    /// header new_for_test(0x1D2FFFFF); rank 64; tile rows/cols [0,1,8,9,64,65,72,73]; legacy seeds.
    /// Its public data pins the mining config, hash_a, hash_b, hash_jackpot and the winning tile (4, 1312).
    /// Mining walks tiles row offset first, so every earlier tile must miss the bound.
    static func fixtureVector() throws -> String {
        let m = 6144, n = 4096, k = 1216
        let pattern = [0, 1, 8, 9, 64, 65, 72, 73]
        let config = PearlHashConfig(k: k, rank: 64, rows: pattern, cols: pattern)
        let expectedConfig = "c004000040000000000103010301000103010301" + String(repeating: "00", count: 32)
        guard config.bytes.hex == expectedConfig else { throw MinerError("fixture mining config serializes as \(config.bytes.hex)") }
        let header = PearlHashHeader(version: 0, prevBlock: [UInt8](repeating: 1, count: 32),
                                     merkleRoot: [UInt8](repeating: 2, count: 32), timestamp: 0x6666_6666, bits: 0x1D2F_FFFF)

        var rng = PearlHashChaCha20Rng(seedFromU64: 0xDEAD_BEEF)
        var a = [UInt8](repeating: 0, count: m * k)
        for i in 0 ..< m * k { a[i] = UInt8(bitPattern: rng.int7()) }
        var bt = [UInt8](repeating: 0, count: n * k)
        for row in 0 ..< k {
            for col in 0 ..< n { bt[col * k + row] = UInt8(bitPattern: rng.int7()) }
        }
        let jobKey = jobKey(header, config)
        let hashA = commitment(a, jobKey: jobKey)
        let hashB = commitment(bt, jobKey: jobKey)
        guard hashA.hex == "18ed78c6389255cf053efb8926d27e476ef4a2b49b37bc7db1417235e3368af3" else {
            throw MinerError("fixture hash_a \(hashA.hex)")
        }
        guard hashB.hex == "bf221b9e1613d1946c67124aa7f46e8ab5ad07a7407677e6945ee404c6df9641" else {
            throw MinerError("fixture hash_b \(hashB.hex)")
        }
        let seeds = noiseSeeds(jobKey: jobKey, hashA: hashA, hashB: hashB, m: m, n: n, salted: false)
        let permA = permutation(k: k, rank: config.rank, label: labelA, key: seeds.a)
        let permB = permutation(k: k, rank: config.rank, label: labelB, key: seeds.b)
        var colCache: [Int: [Int8]] = [:]
        func column(_ c: Int) -> [Int8] {
            if let cached = colCache[c] { return cached }
            let e = uniformRow(c, rank: config.rank, label: labelB, key: seeds.b)
            let value = noised(bt[c * k ..< (c + 1) * k], e: e, perm: permB)
            colCache[c] = value
            return value
        }
        let bound = scale(target(bits: header.bits), by: config.attemptWork)
        let rowOffsets = (0 ..< m).filter { PearlHashConfig.offsetIsValid(pattern, $0) }
        let colOffsets = (0 ..< n).filter { PearlHashConfig.offsetIsValid(pattern, $0) }
        var tried = 0
        for tr in rowOffsets {
            let rows = pattern.map { r -> [Int8] in
                let e = uniformRow(tr + r, rank: config.rank, label: labelA, key: seeds.a)
                return noised(a[(tr + r) * k ..< (tr + r + 1) * k], e: e, perm: permA)
            }
            for tc in colOffsets {
                let cols = pattern.map { column(tc + $0) }
                let hash = jackpotHash(jackpot(rows: rows, cols: cols, config: config), aSeed: seeds.a)
                tried += 1
                guard meets(hash, bound) else { continue }
                guard tr == 4, tc == 1312 else { throw MinerError("fixture: first winning tile is (\(tr), \(tc)), expected (4, 1312)") }
                guard hash.hex == "b51284b608cd76c099d30e403e2b6adbbc8ff3357f50663c4910a28940612400" else {
                    throw MinerError("fixture hash_jackpot \(hash.hex)")
                }
                return "zk-pow v2 proof fixture: ChaCha20 matrices give its hash_a and hash_b; tile (4, 1312) is the first of \(tried) in mining order to meet target 0x1D2FFFFF x 77,824 and gives its hash_jackpot"
            }
            if tried > 2000 { break }
        }
        throw MinerError("fixture: no winning tile among the first \(tried)")
    }
}
