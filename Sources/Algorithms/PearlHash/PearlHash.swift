import Foundation
import Metal

enum PearlHashFamily {
    static let algorithms: [MiningAlgorithm.Type] = [PearlHashAlgorithm.self]
    static let poolMiners: [PoolMiner.Type] = [PearlHashPoolMiner.self]
}

/// Pearl (PRL), algorithm PearlHash: see docs/specs/pearlhash.md.
/// Options: --set m=N (rows of A, multiple of 128), --set n=N (columns of B, multiple of 64),
/// --set k=N (common dimension, multiple of 128 from 2048 to 65536), --set profile=N (time each kernel
/// over N instances instead of the cross-check), --set PEARLHASH_<MACRO>=V (kernel compile-time options).
///
/// A nonce is one instance: the miner's matrices A (fixed per job) and B, whose first 32 entries of
/// column 0 carry the nonce. Each instance is m/4 x n/8 jackpot attempts (4 x 8 tiles) of
/// 32 * k "hashes" each, the unit the network difficulty and Kryptex's share accounting use.
final class PearlHashAlgorithm: MiningAlgorithm {
    static let id = "pearlhash"
    static let coins = ["PRL"]

    /// The mainnet job the benchmark mines on: block 145,681 (explorer.pearlresearch.ai, 2026-11-19
    /// 21:02 UTC), difficulty 63,225,014. V3 certificates (salted seeds) are required from height
    /// 99,000 and the rank-penalty rule (rank >= 128) from 96,251, so both are on.
    static let referenceHeight = 145_681
    static let referenceHeader = PearlHashHeader(
        version: 0x2000_0000,
        prevBlock: PearlHashHeader.wireOrder(display: "c229cf7a6006f98d3cc1d572e648cad56de33820a0307f1764911ff5854f7d05"),
        merkleRoot: PearlHashHeader.wireOrder(display: "a311aef235cd8b40df63fe7e1526f5a35919e54eea45d81eea6b3c1c2da082d0"),
        timestamp: 1_795_122_127, bits: 0x1743_EE30)

    static let instanceStride = 256
    static let maxHits = 62

    let gpu: GPU
    let options: AlgoConfig
    let config: PearlHashConfig
    let m: Int
    let n: Int
    let a: [UInt8]
    let btBase: [UInt8]
    /// The job being mined: the reference block until a pool sets one (setJob).
    private(set) var header: PearlHashHeader
    /// V3 certificates salt the noise seeds (mainnet from height 99,000); a pool job says which version it wants.
    private(set) var salted = true
    private(set) var jobKey: [UInt8]
    private(set) var hashA: [UInt8]
    private(set) var btPath: PearlHashBlake3.LeftPath
    /// A's Merkle tree under the current job key, kept to open rows of A in shares (built by setJob).
    private(set) var aTree: PearlHashMerkleTree?
    let aBuffer: MTLBuffer
    let btBuffer: MTLBuffer
    let anBuffer: MTLBuffer
    let bnBuffer: MTLBuffer
    let ealBuffer: MTLBuffer
    let ebrBuffer: MTLBuffer
    let permABuffer: MTLBuffer
    let permBBuffer: MTLBuffer
    let hitsBuffer: MTLBuffer
    var instances: MTLBuffer
    let noisePipeline: MTLComputePipelineState
    let applyPipeline: MTLComputePipelineState
    let minePipeline: MTLComputePipelineState
    let probePipeline: MTLComputePipelineState
    let setupSummary: String
    var defaultBatch: Int { 2 }

    init(gpu: GPU, config options: AlgoConfig) throws {
        let t0 = now()
        let config = PearlHashConfig.standard(k: options.int("k") ?? 2048)
        let m = options.int("m") ?? (options.quick ? 512 : 4096)
        let n = options.int("n") ?? (options.quick ? 512 : 4096)
        let k = config.k
        guard k % 128 == 0, k >= 16 * config.rank, k <= min(1 << 16, 4 * config.rank * config.rank) else {
            throw MinerError("k must be a multiple of 128 from 2048 to 65536")
        }
        guard m > 0, n > 0, m % 128 == 0, n % 64 == 0, m <= 1 << 24, n <= 1 << 24 else {
            throw MinerError("m must be a multiple of 128 and n a multiple of 64")
        }
        self.gpu = gpu
        self.options = options
        self.config = config
        self.m = m
        self.n = n
        a = Self.randomInt7(count: m * k)
        btBase = Self.randomInt7(count: n * k)
        header = Self.referenceHeader
        jobKey = PearlHashReference.jobKey(Self.referenceHeader, config)
        hashA = PearlHashReference.commitment(a, jobKey: jobKey)
        btPath = PearlHashBlake3.LeftPath(data: btBase, key: jobKey)

        var macros = ["PEARLHASH_K": "\(k)", "PEARLHASH_R": "\(config.rank)"]
        for (key, value) in options.options where key.hasPrefix("PEARLHASH_") { macros[key] = value }
        let library = try gpu.library(["pearlhash.metal"], macros: macros)
        noisePipeline = try gpu.pipeline(library, "pearlhash_noise")
        applyPipeline = try gpu.pipeline(library, "pearlhash_apply")
        minePipeline = try gpu.pipeline(library, "pearlhash_mine")
        probePipeline = try gpu.pipeline(library, "pearlhash_layout_probe")
        guard minePipeline.maxTotalThreadsPerThreadgroup >= 256 else {
            throw MinerError("pearlhash_mine allows only \(minePipeline.maxTotalThreadsPerThreadgroup) threads per threadgroup; it needs 256")
        }
        aBuffer = try gpu.buffer(a, label: "pearlhash A")
        btBuffer = try gpu.buffer(btBase, label: "pearlhash B^T")
        anBuffer = try gpu.privateBuffer(m * k, label: "pearlhash A'")
        bnBuffer = try gpu.privateBuffer(n * k, label: "pearlhash B'^T")
        ealBuffer = try gpu.privateBuffer(m * config.rank, label: "pearlhash E_AL")
        ebrBuffer = try gpu.privateBuffer(n * config.rank, label: "pearlhash E_BR^T")
        permABuffer = try gpu.privateBuffer(4 * k, label: "pearlhash E_AR")
        permBBuffer = try gpu.privateBuffer(4 * k, label: "pearlhash E_BL")
        hitsBuffer = try gpu.buffer(8 + 16 * Self.maxHits, label: "pearlhash hits")
        instances = try gpu.buffer(64 * Self.instanceStride, label: "pearlhash instances")

        let tiles = (m / 4) * (n / 8)
        let perInstance = Double(tiles) * Double(config.penalizedAttemptWork)
        setupSummary = "height \(Self.referenceHeight) (2026-11-19) · nbits 0x\(String(Self.referenceHeader.bits, radix: 16)) · V3 salted seeds"
            + " · k \(k), rank \(config.rank), 4x8 tiles · A \(m)x\(k), B \(k)x\(n): \(tiles) attempts of \(config.penalizedAttemptWork) H"
            + " = \(formatRate(perInstance, "H")) per instance · setup \(fmt(now() - t0, 2)) s"
    }

    /// Work credited per instance: attempts x (tile size x k x 128 / rank), i.e. one per multiply-accumulate.
    var hashesPerInstance: Double { Double((m / 4) * (n / 8)) * Double(config.penalizedAttemptWork) }

    /// Uniform int7 values (-64...63) as bytes.
    static func randomInt7(count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        out.withUnsafeMutableBytes { raw in
            for start in stride(from: 0, to: raw.count, by: 8) {
                let t = (generator.next() & 0x7F7F_7F7F_7F7F_7F7F) ^ 0x4040_4040_4040_4040   // bytewise (b & 127) - 64
                let word = t | ((t & 0x4040_4040_4040_4040) << 1)
                for i in 0 ..< min(8, raw.count - start) { raw[start + i] = UInt8(truncatingIfNeeded: word >> UInt64(8 * i)) }
            }
        }
        return out
    }

    func knownAnswerTests() throws -> [String] { try PearlHashReference.runVectors() }

    // MARK: - Instances

    /// Entries 0..<32 of B^T (column 0 of B) for a nonce: 2 bits each, as values -2...1.
    static func nonceEntries(_ nonce: UInt64) -> [UInt8] {
        (0 ..< 32).map { UInt8(bitPattern: Int8(Int((nonce >> UInt64(2 * $0)) & 3) - 2)) }
    }

    /// B's commitment for an instance, rehashed along its left path (one chunk + one parent per level).
    func instanceHashB(nonce: UInt64) -> [UInt8] {
        var chunk = Array(btBase[0 ..< 1024])
        chunk.replaceSubrange(0 ..< 32, with: Self.nonceEntries(nonce))
        return chunk.withUnsafeBytes { btPath.root(firstChunk: $0) }
    }

    /// Noise seeds of an instance.
    func instanceSeeds(nonce: UInt64) -> (a: [UInt8], b: [UInt8]) {
        PearlHashReference.noiseSeeds(jobKey: jobKey, hashA: hashA, hashB: instanceHashB(nonce: nonce), m: m, n: n, salted: salted)
    }

    func reserveInstances(_ count: Int) throws {
        if count * Self.instanceStride > instances.length {
            instances = try gpu.buffer(count * Self.instanceStride, label: "pearlhash instances")
        }
    }

    func writeInstance(_ index: Int, nonce: UInt64) {
        let seeds = instanceSeeds(nonce: nonce)
        let base = instances.contents() + index * Self.instanceStride
        seeds.a.withUnsafeBytes { base.copyMemory(from: $0.baseAddress!, byteCount: 32) }
        seeds.b.withUnsafeBytes { (base + 32).copyMemory(from: $0.baseAddress!, byteCount: 32) }
        (base + 64).storeBytes(of: nonce, as: UInt64.self)
    }

    func params(bound: [UInt32], writeHashes: Bool) -> [UInt32] {
        [UInt32(m), UInt32(n), UInt32(config.k), UInt32(config.rank),
         UInt32(m * config.rank / 32), UInt32(n * config.rank / 32), UInt32((config.k + 7) / 8), writeHashes ? 1 : 0] + bound
    }

    /// Noise, noisy matrices, then the search, for one instance.
    func encode(_ encoder: MTLComputeCommandEncoder, instance index: Int, params: [UInt32], hashes: MTLBuffer?) {
        params.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: $0.count, index: 0) }
        encoder.setBuffer(instances, offset: index * Self.instanceStride, index: 1)

        encoder.setBuffer(ealBuffer, offset: 0, index: 2)
        encoder.setBuffer(ebrBuffer, offset: 0, index: 3)
        encoder.setBuffer(permABuffer, offset: 0, index: 4)
        encoder.setBuffer(permBBuffer, offset: 0, index: 5)
        gpu.dispatch(encoder, noisePipeline, threads: Int(params[4] + params[5] + 2 * params[6]), group: 64)

        encoder.setBuffer(aBuffer, offset: 0, index: 2)
        encoder.setBuffer(btBuffer, offset: 0, index: 3)
        encoder.setBuffer(ealBuffer, offset: 0, index: 4)
        encoder.setBuffer(ebrBuffer, offset: 0, index: 5)
        encoder.setBuffer(permABuffer, offset: 0, index: 6)
        encoder.setBuffer(permBBuffer, offset: 0, index: 7)
        encoder.setBuffer(anBuffer, offset: 0, index: 8)
        encoder.setBuffer(bnBuffer, offset: 0, index: 9)
        gpu.dispatch(encoder, applyPipeline, threads: (m + n) * config.k / 16, group: 256)

        encoder.setComputePipelineState(minePipeline)
        encoder.setBuffer(anBuffer, offset: 0, index: 2)
        encoder.setBuffer(bnBuffer, offset: 0, index: 3)
        encoder.setBuffer(hitsBuffer, offset: 0, index: 4)
        encoder.setBuffer(hashes ?? hitsBuffer, offset: 0, index: 5)
        encoder.dispatchThreadgroups(MTLSize(width: n / 64, height: m / 128, depth: 1),
                                     threadsPerThreadgroup: MTLSize(width: 256, height: 1, depth: 1))
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        try reserveInstances(count)
        for i in 0 ..< count { writeInstance(i, nonce: startNonce &+ UInt64(i)) }
        hitsBuffer.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        let p = params(bound: [UInt32](repeating: 0, count: 8), writeHashes: false)   // bound 0: unreachable
        try gpu.compute("pearlhash search") { encoder in
            for i in 0 ..< count { encode(encoder, instance: i, params: p, hashes: nil) }
        }
        return Double(count) * hashesPerInstance
    }

    // MARK: - Pool jobs

    /// A tile that met the bound: the instance nonce and the tile's first row of A and first column of B.
    struct Hit {
        let nonce: UInt64
        let tRows: Int
        let tCols: Int
    }

    /// Switches to a pool job: its 76-byte header, and whether its certificate version salts the noise seeds (V3).
    /// The matrices stay; their commitments (and A's Merkle tree, for shares) are recomputed under the new job key.
    func setJob(header: PearlHashHeader, salted: Bool) {
        self.header = header
        self.salted = salted
        jobKey = PearlHashReference.jobKey(header, config)
        let tree = PearlHashMerkleTree(data: a, key: jobKey)
        aTree = tree
        hashA = tree.root
        btPath = PearlHashBlake3.LeftPath(data: btBase, key: jobKey)
    }

    /// One real search batch of `count` instances from `startNonce` on the current job, against `bound` (share target
    /// x attempt work, little-endian words, inclusive). Returns the tiles that met it (at most maxHits).
    func search(startNonce: UInt64, count: Int, bound: [UInt32]) throws -> [Hit] {
        try reserveInstances(count)
        for i in 0 ..< count { writeInstance(i, nonce: startNonce &+ UInt64(i)) }
        hitsBuffer.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        let p = params(bound: bound, writeHashes: false)
        try gpu.compute("pearlhash pool search") { encoder in
            for i in 0 ..< count { encode(encoder, instance: i, params: p, hashes: nil) }
        }
        let found = min(Int(hitsBuffer.contents().load(as: UInt32.self)), Self.maxHits)
        return (0 ..< found).map { i in
            let base = hitsBuffer.contents() + 8 + 16 * i
            return Hit(nonce: base.load(as: UInt64.self), tRows: Int(base.load(fromByteOffset: 8, as: UInt32.self)),
                       tCols: Int(base.load(fromByteOffset: 12, as: UInt32.self)))
        }
    }

    /// The PlainProof a pool needs for one tile of one instance on the current job: the tile's rows of A and columns
    /// of B (rows of B^T, with the instance nonce in place) opened against the job's commitments.
    func plainProof(nonce: UInt64, tRows: Int, tCols: Int) throws -> PearlHashPlainProof {
        let k = config.k
        let aTree = self.aTree ?? PearlHashMerkleTree(data: a, key: jobKey)
        guard aTree.root == hashA else { throw MinerError("A's Merkle root differs from its commitment") }
        var bt = btBase
        bt.replaceSubrange(0 ..< 32, with: Self.nonceEntries(nonce))
        let btTree = PearlHashMerkleTree(data: bt, key: jobKey)
        guard btTree.root == instanceHashB(nonce: nonce) else { throw MinerError("B^T's Merkle root differs from the instance's commitment") }
        return PearlHashPlainProof(m: m, n: n, k: k, noiseRank: config.rank,
                                   a: aTree.open(rows: config.rows.map { tRows + $0 }, rowLength: k, data: a),
                                   bt: btTree.open(rows: config.cols.map { tCols + $0 }, rowLength: k, data: bt))
    }
}
