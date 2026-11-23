import Foundation

/// CPU reference for Octopus, Conflux's proof of work, written from conflux-rust crates/cfxcore/pow
/// (shared.rs, compute.rs, cache.rs, seed_compute.rs). The light cache, DAG items, seed hash and Keccak are
/// Ethash's (EthashReference and Keccak from the Ethash folder) with Octopus sizes. Conflux publishes no
/// known-answer vectors, so `vectors` are real mainnet blocks.
enum OctopusReference {
    /// Heights per stage. The cache and DAG grow once per stage (about every 7.2 days on mainnet).
    static let stageLength = 1 << 19
    static let cacheBytesInit = 1 << 24
    static let cacheBytesGrowth = 1 << 16
    static let datasetBytesInit = 1 << 32
    static let datasetBytesGrowth = 1 << 24
    /// One access of the DAG walk reads a 256-byte page: 4 DAG items of 64 bytes.
    static let pageBytes = 256
    static let accesses = 32
    /// The field F_P with P = 2^20 - 2^14 + 1, and the generator remap() raises.
    static let modulus: UInt64 = 1_032_193
    static let generator: UInt64 = 11
    /// Polynomial coefficients per warp (degree 1023); a warp is 32 consecutive nonces from a multiple of 32.
    static let coefficientCount = 1024
    static let warp = 32
    static let fnvPrime: UInt32 = 0x0100_0193

    static func stage(height: Int) -> Int { height / stageLength }

    static func cacheSize(stage: Int) -> Int { primeSize(below: cacheBytesInit + cacheBytesGrowth * stage, unit: 64) }

    static func datasetSize(stage: Int) -> Int {
        primeSize(below: datasetBytesInit + datasetBytesGrowth * stage, unit: pageBytes)
    }

    /// shared.rs: step down from `bytes - unit` by two units until the unit count is prime.
    static func primeSize(below bytes: Int, unit: Int) -> Int {
        var size = bytes - unit
        while !EthashReference.isPrime(size / unit) { size -= 2 * unit }
        return size
    }

    /// --quick sizes: a 1 MiB cache and a 64 MiB DAG (not a mainnet stage).
    static var quickCacheBytes: Int { primeSize(below: 1 << 20, unit: 64) }
    static var quickDatasetBytes: Int { primeSize(below: 1 << 26, unit: pageBytes) }

    @inline(__always) static func fnv(_ a: UInt32, _ b: UInt32) -> UInt32 { (a &* fnvPrime) ^ b }

    static func powMod(_ base: UInt64, _ exponent: UInt64) -> UInt64 {
        var result: UInt64 = 1, a = base % modulus, e = exponent
        while e > 0 {
            if e & 1 == 1 { result = result * a % modulus }
            a = a * a % modulus
            e >>= 1
        }
        return result
    }

    static func gcd(_ a: UInt64, _ b: UInt64) -> UInt64 {
        var (a, b) = (a, b)
        while b != 0 { (a, b) = (b, a % b) }
        return a
    }

    /// compute.rs remap: 11^e with e = h mod (P-2) + 1 stripped of factors shared with P-1.
    static func remap(_ h: UInt64) -> UInt64 {
        var e = h % (modulus - 2) + 1
        while true {
            let g = gcd(e, modulus - 1)
            if g == 1 { break }
            e /= g
        }
        return powMod(generator, e)
    }

    /// The job's quadratic a*y^2 + b*y + c and the base w of the evaluation points y = w^k.
    struct Params { var a, b, c, w: UInt64 }

    /// The 32-byte PoW problem hash as four little-endian words (also the SipHash state).
    static func headerWords(_ header: [UInt8]) -> [UInt64] { (0 ..< 4).map { header.le64(at: 8 * $0) } }

    static func params(header: [UInt8]) -> Params {
        let v = headerWords(header)
        let a = remap(v[0]), b = remap(v[1]), w = remap(v[3])
        var h = v[2]
        var c = remap(h)
        while b * b % modulus == 4 * a * c % modulus {   // compute_c: keep b^2 - 4ac nonzero
            h &+= 1
            c = remap(h)
        }
        return Params(a: a, b: b, c: c, w: w)
    }

    /// Every evaluation point of a job, x_k = a*w^2k + b*w^k + c for k < 1024; nonce n uses k = n % 32 + 32 i.
    /// The GPU reads this table; `evaluate` steps through the powers the way compute.rs does.
    static func points(_ p: Params) -> [UInt32] {
        let w2 = p.w * p.w % modulus
        var wk: UInt64 = 1, w2k: UInt64 = 1
        var x: [UInt32] = []
        for _ in 0 ..< coefficientCount {
            x.append(UInt32((p.a * w2k + p.b * wk + p.c) % modulus))
            wk = wk * p.w % modulus
            w2k = w2k * w2 % modulus
        }
        return x
    }

    /// compute.rs SipHasher: SipHash rounds on a state that is the header words themselves (no key constants).
    struct Sip {
        var v0, v1, v2, v3: UInt64

        @inline(__always) static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 { (x &<< n) | (x &>> (64 &- n)) }

        mutating func round() {
            v0 = v0 &+ v1; v2 = v2 &+ v3
            v1 = Sip.rotl(v1, 13); v3 = Sip.rotl(v3, 16)
            v1 ^= v0; v3 ^= v2
            v0 = Sip.rotl(v0, 32)
            v2 = v2 &+ v1; v0 = v0 &+ v3
            v1 = Sip.rotl(v1, 17); v3 = Sip.rotl(v3, 21)
            v1 ^= v2; v3 ^= v0
            v2 = Sip.rotl(v2, 32)
        }

        mutating func hash24(_ nonce: UInt64) {
            v3 ^= nonce
            round(); round()
            v0 ^= nonce
            v2 ^= 0xff
            round(); round(); round(); round()
        }

        var lanes: UInt64 { v0 ^ v1 ^ v2 ^ v3 }
    }

    /// The 1024 coefficients shared by the warp of `nonce`: lane i runs a chain on nonce (nonce & ~31) + i
    /// and fills d[32 j + i] for j < 32.
    static func coefficients(header: [UInt8], nonce: UInt64) -> [UInt32] {
        let v = headerWords(header)
        let base = nonce / UInt64(warp) * UInt64(warp)
        var d = [UInt32](repeating: 0, count: coefficientCount)
        for i in 0 ..< warp {
            var sip = Sip(v0: v[0], v1: v[1], v2: v[2], v3: v[3])
            sip.hash24(base + UInt64(i))
            for j in 0 ..< coefficientCount / warp {
                sip.round()
                d[j * warp + i] = UInt32((sip.lanes & 0xffff_ffff) % modulus)
            }
        }
        return d
    }

    /// compute.rs multi-evaluation: the polynomial sum d_j x^j at this nonce's 32 points, and their FNV-64 fold.
    static func evaluate(_ p: Params, d: [UInt32], nonce: UInt64) -> (result: UInt64, values: [UInt32]) {
        let w2 = p.w * p.w % modulus
        let lane = nonce % UInt64(warp)
        var wpow: UInt64 = 1, w2pow: UInt64 = 1
        for _ in 0 ..< lane {
            wpow = wpow * p.w % modulus
            w2pow = w2pow * w2 % modulus
        }
        var fullW = wpow, fullW2 = w2pow   // become w^32 and w^64
        for _ in lane ..< UInt64(warp) {
            fullW = fullW * p.w % modulus
            fullW2 = fullW2 * w2 % modulus
        }
        var result: UInt64 = 0
        var values: [UInt32] = []
        for _ in 0 ..< warp {
            let x = (p.a * w2pow + p.b * wpow + p.c) % modulus
            var pv: UInt64 = 0
            for j in stride(from: coefficientCount - 1, through: 0, by: -1) { pv = (pv * x + UInt64(d[j])) % modulus }
            values.append(UInt32(pv))
            result = result &* UInt64(fnvPrime) ^ pv
            wpow = wpow * fullW % modulus
            w2pow = w2pow * fullW2 % modulus
        }
        return (result, values)
    }

    static func reduce(_ m: [UInt32], _ w: Int) -> UInt32 { fnv(fnv(fnv(m[w], m[w + 1]), m[w + 2]), m[w + 3]) }

    /// Octopus for one nonce: (mix digest, final hash), 32 bytes each. `item(i)` returns DAG item i as 16 words.
    static func hash(header: [UInt8], nonce: UInt64, datasetBytes: Int,
                     item: (UInt32) -> [UInt32]) -> (digest: [UInt8], final: [UInt8]) {
        let (result, values) = evaluate(params(header: header), d: coefficients(header: header, nonce: nonce), nonce: nonce)
        var seedInput = header
        seedInput.appendLE(result)
        let s = Keccak.keccak512(seedInput)
        let sWords = (0 ..< 16).map { s.le32(at: 4 * $0) }
        var mix = sWords + sWords + sWords + sWords
        let pages = UInt32(datasetBytes / pageBytes)
        for i in 0 ..< accesses {
            let page = fnv(sWords[0] ^ UInt32(i) ^ values[i], mix[i]) % pages
            for n in 0 ..< 4 {
                let node = item(4 * page + UInt32(n))
                for w in 0 ..< 16 { mix[16 * n + w] = fnv(mix[16 * n + w], node[w]) }
            }
        }
        var digest: [UInt8] = []
        for i in 0 ..< 8 { digest.appendLE(fnv(reduce(mix, 4 * i), reduce(mix, 32 + 4 * i))) }
        return (digest, Keccak.keccak256(s + digest))
    }

    // MARK: Mainnet vectors

    /// Pivot blocks read from main.confluxrpc.com (and evm.confluxrpc.com for the eSpace base price) on
    /// 2026-11-19. `problem` is the PoW input keccak256(rlp(header without nonce)); the same RLP with the nonce
    /// reproduces `block`, the block hash. `quality` is the RPC's powQuality, floor(2^256 / (hash + 1)) for
    /// nonces below 2^128, which pins the top ~80 bits of the hash. Only the nonce's low 64 bits are hashed
    /// (two of these nonces are 128-bit).
    static let vectors: [(height: Int, block: String, problem: String, nonce: String, quality: UInt64)] = [
        (4096, "ed9d8ad1dc505b0c5349a3bad68f1de551861eaad9bbd7d7715ef4789572097f",
         "5025e5df40c039ec00343520f110d15ec0b38734c9f9c945880ab66a85f3c5c5", "b4de08708", 0x1e301c8bfd),
        (100_000_000, "029130a0617e10df8e1bcb032b9a9fe2937b117314535e05eb8c93d46b20b143",
         "8c03f99c72afad07ad0fe89d28c83a6aad5118558d52a2800fcfaec46bd5d97f", "35847700061b0795", 0xce2083c3a2f),
        (134_217_728, "0e5e583755ce6a8fbd576b10713c71dde9ecb01ffc54bc7bce43f27a030ced48",
         "8882c5ef85f6470b2126c8c7785b70893ce69bf25f6e2789dbf7b3513ee627ce", "dbd8e3da6184c51f", 0x12bc15abf85),
        (161_619_713, "faf7d352d5fbe704683790796f771e80c7b05445f22578a483da52a8b4562590",
         "ea54fa50a0649f198540761de11935cbf9caa63e134c6046d208129c83c74e05", "6d82fe68eea21cd504823a31d72d312f",
         0xb1f347a037),
        (161_619_725, "1d3435d7fb70976e3042a15de78dc896346b15da1ce60810086c646c9bb204c4",
         "8be477eb8472e7a399a4b6da2e2bc0e467f725f97653713b742d31716b29670a", "84450a74b6707338", 0x1b18fb543e9),
        (161_619_767, "fdec84abc528476af2c4cac55f835e6ee21760755bb66193f54f1a333ee2a79b",
         "11cfce46999638a324bc3a7b8a2054b5f918d0f15046d3668894676ad5c5947b", "8d78df3aa29952da06c8ecd0e738dc6d",
         0x2074303e5aa),
        (161_619_968, "00ecd3aa6cfa6017cabe9f54de5222145eb8296d68e5ff7fa0b21404443b3839",
         "562e364f45d54802720ff3bdbb520740c6e4438845f7f22f3db99a0a12b3d261", "118e78927a61af2e", 0x19354b78650),
    ]

    /// floor(2^256 / d) as four 64-bit limbs, most significant first (d >= 2).
    static func twoPow256(dividedBy d: UInt64) -> [UInt64] {
        var remainder: UInt64 = 1   // the leading 1 of 2^256
        var limbs: [UInt64] = []
        for _ in 0 ..< 4 {
            let (q, r) = d.dividingFullWidth((high: remainder, low: 0))
            limbs.append(q)
            remainder = r
        }
        return limbs
    }

    /// A hash read as a big-endian 256-bit number (Conflux's BigEndianHash), as four limbs, most significant first.
    static func limbs(_ hash: [UInt8]) -> [UInt64] {
        (0 ..< 4).map { k in (0 ..< 8).reduce(UInt64(0)) { $0 << 8 | UInt64(hash[8 * k + $1]) } }
    }

    /// The hashes whose PoW quality floor(2^256 / (hash + 1)) is q: from 2^256/(q+1) to 2^256/q - 1 (floors).
    static func hashRange(quality q: UInt64) -> (low: [UInt64], high: [UInt64]) {
        var high = twoPow256(dividedBy: q)
        var i = 3
        while high[i] == 0 {
            high[i] = UInt64.max
            i -= 1
        }
        high[i] -= 1
        return (twoPow256(dividedBy: q + 1), high)
    }

    /// Light-verifies every vector, building one cache per stage; `cached` supplies one already built.
    static func runVectors(cached: (stage: Int, cache: [UInt32])? = nil) throws -> [String] {
        var caches: [Int: [UInt32]] = [:]
        if let cached = cached { caches[cached.stage] = cached.cache }
        var lines: [String] = []
        for v in vectors {
            let blockStage = OctopusReference.stage(height: v.height)
            if caches[blockStage] == nil {
                caches[blockStage] = EthashReference.makeCache(size: cacheSize(stage: blockStage),
                                                               seed: EthashReference.seed(iterations: blockStage))
            }
            let cache = caches[blockStage]!
            let header = [UInt8](hex: v.problem)!
            let nonce = UInt64(v.nonce.suffix(16), radix: 16)!
            let result = cache.withUnsafeBufferPointer { c in
                hash(header: header, nonce: nonce, datasetBytes: datasetSize(stage: blockStage)) { i in
                    EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: i)
                }
            }
            let h = limbs(result.final)
            let range = hashRange(quality: v.quality)
            guard !h.lexicographicallyPrecedes(range.low), !range.high.lexicographicallyPrecedes(h) else {
                throw MinerError("octopus block \(v.height): hash \(result.final.hex) doesn't have mainnet's PoW quality 0x\(String(v.quality, radix: 16))")
            }
            lines.append("block \(v.height) (stage \(blockStage)): hash \(result.final.hex.prefix(18))… has mainnet's PoW quality 0x\(String(v.quality, radix: 16))")
        }
        return lines
    }
}
