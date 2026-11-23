import Foundation
import Metal

enum Autolykos2Family {
    static let algorithms: [MiningAlgorithm.Type] = [Autolykos2.self]
    static let poolMiners: [PoolMiner.Type] = [Autolykos2PoolMiner.self]
}

/// Autolykos v2, Ergo's proof of work. Options: --set height=H (table height), --set n=N (table size
/// override), --set kernel=simple|coop (gather strategy), --set blake=u32|mix|u64 (BLAKE2b arithmetic),
/// --set storage=shared|private (table buffer), --set group=G (threads per threadgroup for the search kernel).
final class Autolykos2: MiningAlgorithm {
    static let id = "autolykos2"
    static let coins = ["ERG"]

    /// Mainnet tip when this port was written: block 1,920,429 at 2026-11-19 20:53:00 UTC
    /// (api.ergoplatform.com); blocks averaged 121.1 s from height 1,000,000 to 1,920,429.
    static let referenceHeight = 1_920_429
    static let referenceTime = 1_795_121_580.0
    static let blockSeconds = 121.1
    /// Table size for --quick (not a power of two, like mainnet N).
    static let quickN = 1_234_567
    /// Largest threadgroup the cooperative kernels accept (AL2_GROUP in autolykos2.metal).
    static let maxCoopGroup = 256

    static var estimatedHeight: Int {
        referenceHeight + max(0, Int((Date().timeIntervalSince1970 - referenceTime) / blockSeconds))
    }

    let gpu: GPU
    /// The table's height and size. A pool job at another height rebuilds the table in place (`setJob`).
    private(set) var height: Int
    private(set) var n: Int
    private(set) var table: MTLBuffer
    /// A table size fixed by --set n or --quick, kept at every height.
    let fixedN: Int?
    let privateStorage: Bool
    let tablePipeline: MTLComputePipelineState
    let msg: [UInt8]
    let params: MTLBuffer
    let target: MTLBuffer
    let output: MTLBuffer
    let coop: Bool
    let searchPipeline: MTLComputePipelineState
    let hashPipeline: MTLComputePipelineState
    let group: Int
    /// GPU seconds to rebuild the table, which a miner does for every block (the table depends on the height).
    private(set) var tableSeconds: Double
    let setupSummary: String
    /// The pool job (`setJob`): its AL2Params and its share target as 8 words, most significant first.
    let jobParams: MTLBuffer
    let jobTarget: MTLBuffer
    /// The table depends on the height, so a miner rebuilds it every block; mining stops meanwhile.
    var overheadFraction: Double { tableSeconds / Self.blockSeconds }
    var defaultBatch: Int { 1 << 22 }

    required init(gpu: GPU, config: AlgoConfig) throws {
        // The rate depends only on N. While today's N equals the reference block's, build that block's table so the
        // cross-check can mine the real block on the GPU; after the next N step, use the estimated height.
        let estimated = Self.estimatedHeight
        let sameN = Autolykos2Reference.calcN(height: estimated) == Autolykos2Reference.calcN(height: Self.referenceHeight)
        let height = config.int("height") ?? (sameN ? Self.referenceHeight : estimated)
        let fixedN = config.int("n") ?? (config.quick ? Self.quickN : nil)
        let n = fixedN ?? Autolykos2Reference.calcN(height: height)
        guard height > 0, height <= Int(UInt32.max), n > 1, n < (1 << 31) else {
            throw MinerError("height \(height) or N \(n) out of range")
        }
        let kernel = config.options["kernel"] ?? "simple"
        let blake = config.options["blake"] ?? "u32"
        let storage = config.options["storage"] ?? "shared"
        let macros = ["u32": [:], "mix": ["AL2_MIX": "1"], "u64": ["AL2_U64": "1"]][blake]
        guard ["simple", "coop"].contains(kernel), ["shared", "private"].contains(storage), let macros else {
            throw MinerError("kernel must be simple or coop, blake u32, mix or u64, storage shared or private")
        }

        let library = try gpu.library(["autolykos2.metal"], macros: macros)
        let tablePipeline = try gpu.pipeline(library, "autolykos2_table")
        let table = try Self.allocateTable(gpu: gpu, n: n, privateStorage: storage == "private")
        let t0 = now()
        let gpuSeconds = try Self.fillTable(gpu: gpu, pipeline: tablePipeline, table: table, n: n, height: height)
        let wallSeconds = now() - t0

        let msg = randomBytes(32)
        self.gpu = gpu
        self.height = height
        self.n = n
        self.table = table
        self.fixedN = fixedN
        privateStorage = storage == "private"
        self.tablePipeline = tablePipeline
        self.msg = msg
        tableSeconds = gpuSeconds
        coop = kernel == "coop"
        params = try gpu.buffer(Self.params(msg: msg, n: n), label: "autolykos2 params")
        target = try gpu.buffer([UInt32](repeating: 0, count: 8), label: "autolykos2 target")   // no hit is below 0
        output = try gpu.buffer(8 + 8 * 62, label: "autolykos2 hits")
        jobParams = try gpu.buffer(Self.params(msg: msg, n: n), label: "autolykos2 job params")
        jobTarget = try gpu.buffer([UInt32](repeating: 0, count: 8), label: "autolykos2 job target")
        searchPipeline = try gpu.pipeline(library, coop ? "autolykos2_search_coop" : "autolykos2_search")
        hashPipeline = try gpu.pipeline(library, coop ? "autolykos2_hash_coop" : "autolykos2_hash")
        let requested = config.int("group") ?? 256
        group = coop ? max(32, min(Self.maxCoopGroup, requested) / 32 * 32) : requested
        let blocks = Double(n) * 65 / max(gpuSeconds, 1e-9)
        let share = gpuSeconds / Self.blockSeconds * 100
        setupSummary = "height \(height) · N \(n) · table \(formatBytes(n * 32)) (\(storage)) in \(fmt(wallSeconds, 1)) s"
            + " (GPU \(fmt(gpuSeconds, 2)) s = \(fmt(share, 1))% of a \(Int(Self.blockSeconds)) s block, rebuilt every block;"
            + " \(fmt(blocks / 1e9, 2)) G BLAKE2b blocks/s) · \(kernel) kernel, BLAKE2b \(blake)"
    }

    static func allocateTable(gpu: GPU, n: Int, privateStorage: Bool) throws -> MTLBuffer {
        privateStorage ? try gpu.privateBuffer(n * 32, label: "autolykos2 table") : try gpu.buffer(n * 32, label: "autolykos2 table")
    }

    /// Fills `table` with the N elements for `height` in chunks of about 0.25 s; returns the GPU seconds.
    static func fillTable(gpu: GPU, pipeline: MTLComputePipelineState, table: MTLBuffer, n: Int, height: Int) throws -> Double {
        var gpuSeconds = 0.0
        var first = 0
        var chunk = 1 << 18
        while first < n {
            let count = min(chunk, n - first)
            var start = UInt32(first), size = UInt32(n), h = UInt32(height)
            let seconds = try gpu.compute("autolykos2 table") { encoder in
                encoder.setBuffer(table, offset: 0, index: 0)
                encoder.setBytes(&start, length: 4, index: 1)
                encoder.setBytes(&size, length: 4, index: 2)
                encoder.setBytes(&h, length: 4, index: 3)
                gpu.dispatch(encoder, pipeline, threads: count, group: 64)
            }
            gpuSeconds += seconds
            first += count
            // Aim for about 0.25 s per command buffer, well inside the GPU watchdog.
            chunk = max(1 << 16, min(chunk * 4, Int(Double(count) * 0.25 / max(seconds, 1e-4))))
        }
        return gpuSeconds
    }

    /// AL2Params: msg words, seed-hash words 4..6, floor((2^64 - 1) / N), then N | floor((2^32 - 1) / N) << 32.
    static func params(msg: [UInt8], n: Int) -> [UInt64] {
        let w = (0 ..< 4).map { msg.le64(at: 8 * $0) }
        let seed = (0 ..< 3).map { (w[$0] >> 8) | (w[$0 + 1] << 56) }
        let mod64 = UInt64.max / UInt64(n)
        let mod32 = UInt64(UInt32.max / UInt32(n))
        return w + seed + [mod64, UInt64(n) | mod32 << 32]
    }

    static func be64(_ x: UInt64) -> [UInt8] { (0 ..< 8).map { UInt8(truncatingIfNeeded: x >> (56 - 8 * UInt64($0))) } }

    /// A 32-byte big-endian number as the kernel's 8 target words, most significant first.
    static func targetWords(_ bytes: [UInt8]) -> [UInt32] {
        (0 ..< 8).map { k in bytes[4 * k ..< 4 * k + 4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } }
    }

    /// Cooperative kernels need whole SIMD groups.
    private func padded(_ count: Int) -> Int { coop ? (count + 31) / 32 * 32 : count }

    // MARK: Pool jobs

    /// A pool job: the 32-byte message, the block height (the table is rebuilt in place when it changes, and
    /// reallocated when N changes) and the share target as 32 big-endian bytes (a hit is below it). Returns the
    /// GPU seconds spent rebuilding the table, 0 when the height is unchanged.
    @discardableResult
    func setJob(msg: [UInt8], height: Int, target: [UInt8]) throws -> Double {
        guard msg.count == 32, target.count == 32 else { throw MinerError("a job needs a 32-byte message and target") }
        var seconds = 0.0
        if height != self.height {
            guard height > 0, height <= Int(UInt32.max) else { throw MinerError("height \(height) out of range") }
            let newN = fixedN ?? Autolykos2Reference.calcN(height: height)
            self.height = 0   // no valid table until the rebuild finishes
            if newN != n {
                table = try gpu.buffer(16, label: "autolykos2 placeholder")   // release the old table first
                n = 0
                table = try Self.allocateTable(gpu: gpu, n: newN, privateStorage: privateStorage)
                n = newN
            }
            seconds = try Self.fillTable(gpu: gpu, pipeline: tablePipeline, table: table, n: n, height: height)
            self.height = height
            tableSeconds = seconds
        }
        Self.params(msg: msg, n: n).withUnsafeBytes { jobParams.contents().copyMemory(from: $0.baseAddress!, byteCount: $0.count) }
        Self.targetWords(target).withUnsafeBytes { jobTarget.contents().copyMemory(from: $0.baseAddress!, byteCount: 32) }
        return seconds
    }

    /// The search kernel over the pool job's nonces [start, start + count) (count a multiple of 32 for the coop
    /// kernel). Returns the nonces whose hit is below the job's target (at most 62, sorted) and how many the
    /// kernel counted.
    func searchJob(start: UInt64, count: Int) throws -> (nonces: [UInt64], hits: Int) {
        guard height > 0, n > 1 else { throw MinerError("no table: the last rebuild failed") }
        var first = start
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("autolykos2 job search") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(jobParams, offset: 0, index: 1)
            encoder.setBytes(&first, length: 8, index: 2)
            encoder.setBuffer(jobTarget, offset: 0, index: 3)
            encoder.setBuffer(output, offset: 0, index: 4)
            gpu.dispatch(encoder, searchPipeline, threads: padded(count), group: group)
        }
        let hits = Int(output.contents().load(as: UInt32.self))
        let stored = (output.contents() + 8).bindMemory(to: UInt64.self, capacity: 62)
        return ((0 ..< min(hits, 62)).map { stored[$0] }.sorted(), hits)
    }

    // MARK: Checks

    func knownAnswerTests() throws -> [String] { try Autolykos2Reference.runVectors() }

    /// Table elements as the GPU stored them (blit-copied out first when the table is private).
    private func readElements(_ indices: [UInt32]) throws -> [[UInt32]] {
        var source = table
        var offsets = indices.map { 32 * Int($0) }
        if table.storageMode == .private {
            let staging = try gpu.buffer(indices.count * 32, label: "autolykos2 staging")
            try gpu.run("autolykos2 read table") { commands in
                guard let blit = commands.makeBlitCommandEncoder() else { throw MinerError("can't create a blit encoder") }
                for (s, offset) in offsets.enumerated() {
                    blit.copy(from: table, sourceOffset: offset, to: staging, destinationOffset: 32 * s, size: 32)
                }
                blit.endEncoding()
            }
            source = staging
            offsets = indices.indices.map { 32 * $0 }
        }
        return offsets.map { offset in
            let words = (source.contents() + offset).bindMemory(to: UInt32.self, capacity: 8)
            return Array(UnsafeBufferPointer(start: words, count: 8))
        }
    }

    /// GPU intermediates for the given nonces: the first index, the seed hash and the hit (big-endian bytes).
    private func evaluateOnGPU(nonces: [UInt64], params: MTLBuffer) throws -> [(first: UInt32, seed: [UInt8], hit: [UInt8])] {
        precondition(nonces.count == padded(nonces.count))
        let nonceBuffer = try gpu.buffer(nonces, label: "autolykos2 nonces")
        let results = try gpu.buffer(nonces.count * 17 * 4, label: "autolykos2 results")
        try gpu.compute("autolykos2 hash") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(params, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBuffer(results, offset: 0, index: 3)
            gpu.dispatch(encoder, hashPipeline, threads: nonces.count, group: 32)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: nonces.count * 17)
        return (0 ..< nonces.count).map { s in
            let r = words + 17 * s
            var seed: [UInt8] = []
            for q in 0 ..< 8 { seed.appendLE(r[1 + q]) }
            let hit = (0 ..< 8).flatMap { Autolykos2Reference.be32(r[9 + $0]) }
            return (r[0], seed, hit)
        }
    }

    /// Runs the search kernel over [start, start + count) against a 32-byte big-endian target; returns the hits.
    private func search(params: MTLBuffer, start: UInt64, count: Int, target bytes: [UInt8]) throws -> [UInt64] {
        precondition(count == padded(count))
        let targetBuffer = try gpu.buffer(Self.targetWords(bytes), label: "autolykos2 check target")
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        var first = start
        try gpu.compute("autolykos2 search check") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(params, offset: 0, index: 1)
            encoder.setBytes(&first, length: 8, index: 2)
            encoder.setBuffer(targetBuffer, offset: 0, index: 3)
            encoder.setBuffer(output, offset: 0, index: 4)
            gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
        }
        let hits = min(Int(output.contents().load(as: UInt32.self)), 62)
        let nonces = (output.contents() + 8).bindMemory(to: UInt64.self, capacity: 62)
        return (0 ..< hits).map { nonces[$0] }.sorted()
    }

    func crossCheck(samples: Int) throws -> String {
        let elements = Autolykos2Reference.Elements(height: UInt32(height))

        // 1. Table elements (first, last, random) against the CPU.
        let indices = [0, UInt32(n - 1)] + (0 ..< 62).map { _ in UInt32.random(in: 0 ..< UInt32(n)) }
        for (j, gpuLimbs) in zip(indices, try readElements(indices)) {
            guard gpuLimbs == Autolykos2Reference.limbs(elements.element(j)) else {
                throw MinerError("table element \(j) differs from the CPU reference")
            }
        }

        // 2. Every intermediate for consecutive nonces from a random start (whole SIMD groups for coop).
        let count = padded(samples)
        let start = UInt64.random(in: 0 ... UInt64.max - UInt64(count))
        let nonces = (0 ..< UInt64(count)).map { start + $0 }
        let gpuResults = try evaluateOnGPU(nonces: nonces, params: params)
        var hits: [[UInt8]] = []
        for (s, nonce) in nonces.enumerated() {
            let cpu = Autolykos2Reference.evaluate(msg: msg, nonce: Self.be64(nonce), n: n, element: elements.element)
            let g = gpuResults[s]
            guard g.first == cpu.i, g.seed == cpu.seedHash, g.hit == cpu.hit else {
                throw MinerError("nonce \(String(nonce, radix: 16)): GPU i \(g.first) seed \(g.seed.hex) hit \(g.hit.hex)"
                                 + " vs CPU i \(cpu.i) seed \(cpu.seedHash.hex) hit \(cpu.hit.hex)")
            }
            hits.append(cpu.hit)
        }

        // 3. The search kernel with the target just above the smallest hit reports exactly that nonce;
        //    with the target equal to it (hit < target is strict), nothing.
        let best = hits.indices.min { Autolykos2Reference.less(hits[$0], hits[$1]) }!
        var above = hits[best]
        for b in (0 ..< 32).reversed() {
            above[b] &+= 1
            if above[b] != 0 { break }
        }
        let found = try search(params: params, start: start, count: count, target: above)
        guard found == [nonces[best]] else { throw MinerError("search with target min+1 reported \(found), expected \(nonces[best])") }
        let none = try search(params: params, start: start, count: count, target: hits[best])
        guard none.isEmpty else { throw MinerError("search with target = min hit reported \(none)") }

        // 4. A real mainnet block at this height: the GPU search finds its nonce at the block's own target.
        var block = ""
        if n == Autolykos2Reference.calcN(height: height),
           let real = Autolykos2Reference.mainnet.first(where: { Int($0.header.height) == height }) {
            let header = real.header
            guard let b = Autolykos2Reference.target(nBits: header.nBits) else { throw MinerError("bad nBits") }
            let blockParams = try gpu.buffer(Self.params(msg: header.msg, n: n), label: "autolykos2 block params")
            let nonce = header.nonceBytes.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            let found = try search(params: blockParams, start: nonce &- 1000, count: 4096, target: b)
            guard found == [nonce] else { throw MinerError("mainnet block \(height): GPU search found \(found), expected [\(nonce)]") }
            block = "; GPU search mines mainnet block \(height) (nonce \(header.nonce) of 4096, at its target)"
        }
        return "\(indices.count) table elements, \(count) full hashes (i, seed, hit) match the CPU;"
            + " search reports exactly the hits\(block)"
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let threads = padded(count)
        var start = startNonce
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("autolykos2 search") { encoder in
            encoder.setBuffer(table, offset: 0, index: 0)
            encoder.setBuffer(params, offset: 0, index: 1)
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBuffer(target, offset: 0, index: 3)
            encoder.setBuffer(output, offset: 0, index: 4)
            gpu.dispatch(encoder, searchPipeline, threads: threads, group: group)
        }
        return Double(threads)
    }
}
