import Foundation

/// CPU reference for Ethash, written from the Ethash spec (ethereum.org "Ethash" / the yellow paper appendix)
/// and checked against chfast/ethash's published hash vectors.
enum EthashReference {
    static let cacheBytesInit = 1 << 24
    static let cacheBytesGrowth = 1 << 17
    static let datasetBytesInit = 1 << 30
    static let datasetBytesGrowth = 1 << 23
    static let datasetParents = 256
    static let cacheRounds = 3
    static let accesses = 64

    @inline(__always) static func fnv(_ a: UInt32, _ b: UInt32) -> UInt32 { (a &* 0x0100_0193) ^ b }

    static func isPrime(_ n: Int) -> Bool {
        if n < 2 { return false }
        if n % 2 == 0 { return n == 2 }
        var d = 3
        while d * d <= n {
            if n % d == 0 { return false }
            d += 2
        }
        return true
    }

    /// Light cache size in bytes for a size epoch.
    static func cacheSize(epoch: Int) -> Int {
        var size = cacheBytesInit + cacheBytesGrowth * epoch - 64
        while !isPrime(size / 64) { size -= 2 * 64 }
        return size
    }

    /// Full dataset (DAG) size in bytes for a size epoch.
    static func datasetSize(epoch: Int) -> Int {
        var size = datasetBytesInit + datasetBytesGrowth * epoch - 128
        while !isPrime(size / 128) { size -= 2 * 128 }
        return size
    }

    /// keccak256 applied `iterations` times to 32 zero bytes.
    static func seed(iterations: Int) -> [UInt8] {
        var seed = [UInt8](repeating: 0, count: 32)
        for _ in 0 ..< iterations { seed = Keccak.keccak256(seed) }
        return seed
    }

    /// The light cache as little-endian 32-bit words, 16 per 64-byte item.
    static func makeCache(size: Int, seed: [UInt8]) -> [UInt32] {
        let n = size / 64
        var cache = [UInt32](repeating: 0, count: n * 16)
        let first = Keccak.keccak512(seed)
        cache.withUnsafeMutableBufferPointer { buffer in
            let c = buffer.baseAddress!
            for w in 0 ..< 16 { c[w] = first.le32(at: 4 * w) }
            for i in 1 ..< n {
                (c + 16 * i).update(from: c + 16 * (i - 1), count: 16)
                Keccak.keccak512InPlace(c + 16 * i)
            }
            for _ in 0 ..< cacheRounds {
                for i in 0 ..< n {
                    let v = Int(c[16 * i]) % n
                    let previous = (i + n - 1) % n
                    for w in 0 ..< 16 { c[16 * i + w] = c[16 * previous + w] ^ c[16 * v + w] }
                    Keccak.keccak512InPlace(c + 16 * i)
                }
            }
        }
        return cache
    }

    /// One 64-byte DAG item computed from the light cache, as 16 words. KawPow uses 512 parents.
    static func datasetItem(cache: UnsafePointer<UInt32>, cacheItems n: Int, index: UInt32, parents: Int = 256) -> [UInt32] {
        var mix = [UInt32](repeating: 0, count: 16)
        mix.withUnsafeMutableBufferPointer { buffer in
            let m = buffer.baseAddress!
            let source = cache + 16 * (Int(index) % n)
            for w in 0 ..< 16 { m[w] = source[w] }
            m[0] ^= index
            Keccak.keccak512InPlace(m)
            for j in 0 ..< parents {
                let parent = Int(fnv(index ^ UInt32(j), m[j % 16]) % UInt32(n))
                let p = cache + 16 * parent
                for w in 0 ..< 16 { m[w] = fnv(m[w], p[w]) }
            }
            Keccak.keccak512InPlace(m)
        }
        return mix
    }

    /// hashimoto: returns (mix digest, final hash), 32 bytes each. `item` returns DAG item i as 16 words.
    static func hashimoto(header: [UInt8], nonce: UInt64, datasetBytes: Int,
                          item: (UInt32) -> [UInt32]) -> (mix: [UInt8], final: [UInt8]) {
        var seedInput = header
        seedInput.appendLE(nonce)
        let s = Keccak.keccak512(seedInput)
        let sWords = (0 ..< 16).map { s.le32(at: 4 * $0) }
        var mix = sWords + sWords
        let pages = UInt32(datasetBytes / 128)
        for i in 0 ..< accesses {
            let page = fnv(UInt32(i) ^ sWords[0], mix[i % 32]) % pages
            let data = item(2 * page) + item(2 * page + 1)
            for k in 0 ..< 32 { mix[k] = fnv(mix[k], data[k]) }
        }
        var digest: [UInt8] = []
        for k in 0 ..< 8 {
            digest.appendLE(fnv(fnv(fnv(mix[4 * k], mix[4 * k + 1]), mix[4 * k + 2]), mix[4 * k + 3]))
        }
        return (digest, Keccak.keccak256(s + digest))
    }

    /// Published vectors from chfast/ethash test/unittests/test_cases.hpp
    /// (block number, header hash, nonce, mix hash, final hash).
    static let vectors: [(block: Int, header: String, nonce: String, mix: String, final: String)] = [
        (0, "2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce", "4242424242424242",
         "58f759ede17a706c93f13030328bcea40c1d1341fb26f2facd21ceb0dae57017", "dd47fd2d98db51078356852d7c4014e6a5d6c387c35f40e2875b74a256ed7906"),
        (2, "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe", "307692cf71b12f6d",
         "e55d02c555a7969361cf74a9ec6211d8c14e4517930a00442f171bdb1698d175", "ab9b13423cface72cbec8424221651bc2e384ef0f7a560e038fc68c8d8684829"),
        (2683077, "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512", "8c5eaec000788d41",
         "93e85c97b34ccd8091e09ddb513fdc9e680fa8898d4a0737205e60af710a3dcb", "00000000000204882a6213f68fe89bc368df25c1ad999f82532a7433e99bc48e"),
        (5000000, "bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a", "4617a20003ba3f25",
         "94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea", "0000000000001a5b18ae31b7417b7c045bc6dd78cc3b694c4bebfaefef6b3c56"),
        (5000001, "2cd14041cfc3bd13064cfd58e26c0bddf1e97a4202c4b8076444a7cd4515f8c3", "1af47f2007922384",
         "46cb1268ac6b218eb01b9bd46f1533561d085620c9bfc23eadb8ab106f84b2d8", "0000000000000a4230cfc483a3f739a5101192c3d4f9c8314f4508be24c28257"),
        (5000002, "9e79bced19062baf7c47e516ad3a1bd779222404d05b4205def30a13c7d87b5b", "c9a044201dd998f2",
         "028a19d6dcf0975972285f71a23fe3a468886ad24cc63f969158d427556d6bb5", "0000000000000eec80fbc4c472507b6c212c4f216043318f3fb3e696a0e80b06"),
        (5306861, "53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f", "d337f82001e992c5",
         "26c64f063dac85ae3585526b446be6754faf044876aa3e20f770bea567e04d1d", "00000000000003f1554d8071ff0903268fcb70f30f4af3bf7ec7dc69cdf509f3"),
    ]

    /// Runs every published vector (light verification, standard 30,000-block epochs). Throws on mismatch.
    static func runVectors() throws -> [String] {
        var lines: [String] = []
        var caches: [Int: [UInt32]] = [:]
        for v in vectors {
            let epoch = v.block / 30_000
            if caches[epoch] == nil { caches[epoch] = makeCache(size: cacheSize(epoch: epoch), seed: seed(iterations: epoch)) }
            let cache = caches[epoch]!
            let header = [UInt8](hex: v.header)!
            let nonce = UInt64(v.nonce, radix: 16)!
            let result = cache.withUnsafeBufferPointer { c in
                hashimoto(header: header, nonce: nonce, datasetBytes: datasetSize(epoch: epoch)) { i in
                    datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: i)
                }
            }
            guard result.mix.hex == v.mix, result.final.hex == v.final else {
                throw MinerError("ethash vector block \(v.block): got mix \(result.mix.hex) final \(result.final.hex)")
            }
            lines.append("block \(v.block) (epoch \(epoch)): mix and final hash match")
        }
        return lines
    }
}
