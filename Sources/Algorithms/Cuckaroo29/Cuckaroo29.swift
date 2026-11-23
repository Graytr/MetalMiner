import Foundation
import Metal

enum Cuckaroo29Family {
    static let algorithms: [MiningAlgorithm.Type] = [Cuckaroo29Miner.self]
    static let poolMiners: [PoolMiner.Type] = [Cuckaroo29PoolMiner.self]
}

/// Tari's C29 proof of work (Cuckaroo29, 42-cycles). Per graph (one header nonce): siphash keys on the CPU; edge
/// generation into buckets by U node and `rounds` bucketed trimming rounds on the GPU; cycle finding over the few
/// surviving edges on the CPU; for each 42-cycle, nonce recovery on the GPU, then verification, the proof hash and the
/// difficulty on the CPU. `solve(miningHash:nonce:)` is one graph of a pool job (Cuckaroo29PoolMiner); `runBatch` runs
/// the same path on a random mining hash for the benchmark. Options (--set key=value) are listed in
/// docs/specs/cuckaroo29.md.
final class Cuckaroo29Miner: MiningAlgorithm {
    static let id = "cuckaroo29"
    static let coins = ["XTM"]
    static let unit = "G/s"

    /// A verified 42-cycle: its sorted edge nonces, Tari pow_data (those nonces packed 29 bits each, 153 bytes), proof
    /// hash (blake2b-256 of pow_data) and Tari difficulty.
    struct Solution {
        let nonces: [UInt64]
        let powData: [UInt8]
        let hash: [UInt8]
        let difficulty: UInt64
    }

    let gpu: GPU
    let edgeBits: Int
    let zBits: Int
    let rounds: Int
    let buckets: Int
    let capA: Int
    let capB: Int
    let edgesA: MTLBuffer
    let edgesB: MTLBuffer
    let countA: MTLBuffer
    let countB: MTLBuffer
    let stats: MTLBuffer
    let seedPipeline: MTLComputePipelineState
    let trimPipeline: MTLComputePipelineState
    let sparsePipeline: MTLComputePipelineState
    let recoverPipeline: MTLComputePipelineState
    let seedGroup: Int
    /// Rounds 1 ... earlyRounds use the bit-map kernel with earlyGroup threads per threadgroup, rounds up to
    /// sparseFrom the same kernel with lateGroup threads, later rounds the hash-table kernel with sparseGroup threads.
    let earlyRounds: Int
    let sparseFrom: Int
    let earlyGroup: Int
    let lateGroup: Int
    let sparseGroup: Int
    let verbose: Bool
    let checks: Bool
    let miningHash: [UInt8]
    /// A solution is a hit when its difficulty reaches this; the benchmark's can't be reached.
    var targetDifficulty = UInt64.max
    private(set) var hits: [(nonce: UInt64, solution: Solution)] = []
    private(set) var graphs = 0
    private(set) var cyclesFound = 0
    private(set) var droppedEdges = 0
    private var lastGPUTimes: [Double] = []
    private var lastCopySeconds = 0.0
    let setupSummary: String
    var defaultBatch: Int { 1 }

    required init(gpu: GPU, config: AlgoConfig) throws {
        let edgeBits = config.int("edgebits") ?? (config.quick ? 19 : 29)
        let zBits = config.int("zbits") ?? (config.quick ? 12 : 17)
        guard (12 ... 31).contains(edgeBits) else { throw MinerError("cuckaroo29: edgebits must be 12 ... 31") }
        guard (6 ... 17).contains(zBits), (1 ... 16).contains(edgeBits - zBits) else {
            throw MinerError("cuckaroo29: zbits must be 6 ... 17 and leave 1 ... 16 bucket bits")
        }
        let rounds = config.int("rounds") ?? (config.quick ? 40 : 192)
        guard rounds >= 1 else { throw MinerError("cuckaroo29: rounds must be at least 1") }
        let seedMode = config.int("seed") ?? 0
        let seedGroup = config.int("seedgroup") ?? 256
        let earlyGroup = config.int("group") ?? 1024
        let lateGroup = config.int("lategroup") ?? 256
        let sparseGroup = config.int("sparsegroup") ?? 128
        for (name, value) in [("seedgroup", seedGroup), ("group", earlyGroup), ("lategroup", lateGroup),
                              ("sparsegroup", sparseGroup)] where value % 32 != 0 || !(32 ... 1024).contains(value) {
            throw MinerError("cuckaroo29: \(name) must be a multiple of 32, at most 1024")
        }
        let margin = Double(config.int("margin") ?? 10)

        let buckets = 1 << (edgeBits - zBits)
        let perBucket = Double(1 << zBits)
        // Seeding fills a bucket with about 2^zBits edges and round 1 keeps 1 - 1/e of them; `margin` standard
        // deviations spare (an overflowing bucket drops edges, which can only lose cycles).
        func capacity(_ mean: Double) -> Int { (Int(mean + margin * mean.squareRoot()) + 63) / 64 * 64 }
        let capA = capacity(perBucket)
        let capB = capacity(perBucket * (1 - exp(-1.0)))
        let library = try gpu.library(["cuckaroo29.metal"], macros: [
            "CK_EDGEBITS": "\(edgeBits)", "CK_ZBITS": "\(zBits)", "CK_SEED_MODE": "\(seedMode)",
        ])
        let seedPipeline = try gpu.pipeline(library, "cuckaroo29_seed")
        let trimPipeline = try gpu.pipeline(library, "cuckaroo29_trim")
        let sparsePipeline = try gpu.pipeline(library, "cuckaroo29_trim_sparse")
        let recoverPipeline = try gpu.pipeline(library, "cuckaroo29_recover")

        self.gpu = gpu
        self.edgeBits = edgeBits
        self.zBits = zBits
        self.rounds = rounds
        self.buckets = buckets
        self.capA = capA
        self.capB = capB
        edgesA = try gpu.buffer(buckets * capA * 8, label: "cuckaroo29 edges A")
        edgesB = try gpu.buffer(buckets * capB * 8, label: "cuckaroo29 edges B")
        countA = try gpu.buffer(buckets * 4, label: "cuckaroo29 counts A")
        countB = try gpu.buffer(buckets * 4, label: "cuckaroo29 counts B")
        stats = try gpu.buffer((rounds + 2) * 4, label: "cuckaroo29 stats")
        self.seedPipeline = seedPipeline
        self.trimPipeline = trimPipeline
        self.sparsePipeline = sparsePipeline
        self.recoverPipeline = recoverPipeline
        self.seedGroup = min(seedGroup, seedPipeline.maxTotalThreadsPerThreadgroup)
        earlyRounds = config.int("early") ?? 8
        sparseFrom = config.int("sparse") ?? 24
        self.earlyGroup = min(earlyGroup, trimPipeline.maxTotalThreadsPerThreadgroup)
        self.lateGroup = min(lateGroup, trimPipeline.maxTotalThreadsPerThreadgroup)
        self.sparseGroup = min(sparseGroup, sparsePipeline.maxTotalThreadsPerThreadgroup)
        verbose = config.int("verbose") == 1
        checks = config.int("check") != 0
        miningHash = randomBytes(32)
        setupSummary = "2^\(edgeBits) edges · \(buckets) buckets of 2^\(zBits) nodes · edge buffers "
            + "\(formatBytes(buckets * (capA + capB) * 8)) · \(rounds) trimming rounds (bit maps to round \(sparseFrom),"
            + " then hash tables)"
    }

    deinit {
        if verbose && graphs > 0 {
            print("   [c29] \(graphs) graphs, \(cyclesFound) 42-cycles found:"
                + " \(fmt(Double(cyclesFound) * 42 / Double(graphs), 2)) x the 1/42 per graph a random graph has")
        }
    }

    func knownAnswerTests() throws -> [String] { try Cuckaroo29Reference.runVectors() }

    // MARK: GPU steps

    /// Zeroes both bucket counts and the statistics; the GPU is idle whenever this runs.
    private func resetCounts() {
        memset(countA.contents(), 0, countA.length)
        memset(countB.contents(), 0, countB.length)
        memset(stats.contents(), 0, stats.length)
    }

    private func encodeSeed(_ encoder: MTLComputeCommandEncoder, keys: [UInt64]) {
        encoder.setComputePipelineState(seedPipeline)
        keys.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: 32, index: 0) }
        encoder.setBuffer(edgesA, offset: 0, index: 1)
        encoder.setBuffer(countA, offset: 0, index: 2)
        var cap = UInt32(capA)
        encoder.setBytes(&cap, length: 4, index: 3)
        gpu.dispatch(encoder, seedPipeline, threads: 1 << (edgeBits - 6), group: seedGroup)
    }

    /// Round r reads A and writes B when r is odd, the reverse when even.
    private func encodeTrim(_ encoder: MTLComputeCommandEncoder, round: Int) {
        let odd = round % 2 == 1
        let sparse = round > sparseFrom
        encoder.setComputePipelineState(sparse ? sparsePipeline : trimPipeline)
        encoder.setBuffer(odd ? edgesA : edgesB, offset: 0, index: 0)
        encoder.setBuffer(odd ? countA : countB, offset: 0, index: 1)
        encoder.setBuffer(odd ? edgesB : edgesA, offset: 0, index: 2)
        encoder.setBuffer(odd ? countB : countA, offset: 0, index: 3)
        var caps = SIMD2<UInt32>(UInt32(odd ? capA : capB), UInt32(odd ? capB : capA))
        encoder.setBytes(&caps, length: 8, index: 4)
        encoder.setBuffer(stats, offset: 0, index: 5)
        var index = UInt32(round)
        encoder.setBytes(&index, length: 4, index: 6)
        let group = sparse ? sparseGroup : round <= earlyRounds ? earlyGroup : lateGroup
        encoder.dispatchThreadgroups(MTLSize(width: buckets, height: 1, depth: 1),
                                     threadsPerThreadgroup: MTLSize(width: group, height: 1, depth: 1))
    }

    /// Seeds and trims one graph on the GPU and returns the surviving edges as (u, v) pairs. The work is split into
    /// command buffers of about 100 ms or less (seeding with rounds 1-2, rounds 3-18, then 32 rounds at a time), well
    /// under the GPU watchdog; verbose mode times seeding and rounds 1-4 on their own.
    func trim(keys: [UInt64]) throws -> [SIMD2<UInt32>] {
        resetCounts()
        var groups: [[Int]] = []   // 0 is seeding, r is round r
        var current = [0]
        if verbose {
            groups.append(current)
            current = []
        }
        for round in 1 ... rounds {
            current.append(round)
            if (verbose && round <= 4) || round == 2 || round == 18 || (round > 18 && (round - 18) % 32 == 0) {
                groups.append(current)
                current = []
            }
        }
        if !current.isEmpty { groups.append(current) }

        var commandBuffers: [MTLCommandBuffer] = []
        for group in groups {
            guard let commands = gpu.queue.makeCommandBuffer(), let encoder = commands.makeComputeCommandEncoder() else {
                throw MinerError("can't create a command buffer")
            }
            commands.label = "cuckaroo29 trim"
            for step in group {
                if step == 0 { encodeSeed(encoder, keys: keys) } else { encodeTrim(encoder, round: step) }
            }
            encoder.endEncoding()
            commands.commit()
            commandBuffers.append(commands)
        }
        for commands in commandBuffers {
            commands.waitUntilCompleted()
            if let error = commands.error { throw MinerError("GPU error in cuckaroo29 trim: \(error.localizedDescription)") }
        }
        lastGPUTimes = commandBuffers.map { $0.gpuEndTime - $0.gpuStartTime }
        GPUThrottle.shared.rest(after: lastGPUTimes.reduce(0, +))   // quiet mode (GPU.run does this for everyone else)
        let start = now()
        let survivors = takeSurvivors()
        lastCopySeconds = now() - start
        return survivors
    }

    /// Copies the surviving edges out of the last round's buffer as (u, v) and zeroes its counts.
    private func takeSurvivors() -> [SIMD2<UInt32>] {
        let inB = rounds % 2 == 1   // odd rounds write B, which holds edges as (v, u)
        let cap = inB ? capB : capA
        let counts = (inB ? countB : countA).contents().bindMemory(to: UInt32.self, capacity: buckets)
        let edges = (inB ? edgesB : edgesA).contents().bindMemory(to: SIMD2<UInt32>.self, capacity: buckets * cap)
        droppedEdges += Int(stats.contents().load(as: UInt32.self))
        var out: [SIMD2<UInt32>] = []
        for b in 0 ..< buckets {
            let n = Int(counts[b])
            droppedEdges += max(0, n - cap)
            let base = edges + b * cap
            for i in 0 ..< min(n, cap) { out.append(inB ? SIMD2(base[i].y, base[i].x) : base[i]) }
            counts[b] = 0
        }
        return out
    }

    /// The edge nonces of a cycle given as (u, v) pairs, sorted. Regenerates every edge on the GPU.
    private func recover(keys: [UInt64], cycle: [SIMD2<UInt32>]) throws -> [UInt64] {
        let cycleBuffer = try gpu.buffer(cycle, label: "cuckaroo29 cycle")
        let found = try gpu.buffer(16, label: "cuckaroo29 recovered count")
        let matches = try gpu.buffer(256 * 8, label: "cuckaroo29 recovered")
        var length = UInt32(cycle.count)
        try gpu.compute("cuckaroo29 recover") { encoder in
            encoder.setComputePipelineState(recoverPipeline)
            keys.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: 32, index: 0) }
            encoder.setBuffer(cycleBuffer, offset: 0, index: 1)
            encoder.setBytes(&length, length: 4, index: 2)
            encoder.setBuffer(found, offset: 0, index: 3)
            encoder.setBuffer(matches, offset: 0, index: 4)
            gpu.dispatch(encoder, recoverPipeline, threads: 1 << (edgeBits - 6), group: 256)
        }
        let count = min(256, Int(found.contents().load(as: UInt32.self)))
        let pairs = matches.contents().bindMemory(to: SIMD2<UInt32>.self, capacity: 256)
        var nonces = [UInt64?](repeating: nil, count: cycle.count)
        for i in 0 ..< count where nonces[Int(pairs[i].y)] == nil { nonces[Int(pairs[i].y)] = UInt64(pairs[i].x) }
        guard nonces.allSatisfy({ $0 != nil }) else { throw MinerError("cuckaroo29: nonce recovery missed cycle edges") }
        return nonces.map { $0! }.sorted()
    }

    /// The verified 42-cycles among one graph's surviving edges.
    func solutions(keys: [UInt64], survivors: [SIMD2<UInt32>]) throws -> [Solution] {
        let start = now()
        let found = Cuckaroo29CycleFinder.find(survivors, length: Cuckaroo29Reference.cycleLength)
        let findSeconds = now() - start
        var out: [Solution] = []
        for cycle in found.cycles {
            cyclesFound += 1
            let nonces = try recover(keys: keys, cycle: cycle)
            if let problem = Cuckaroo29Reference.verify(keys: keys, nonces: nonces, edgeBits: edgeBits) {
                throw MinerError("cuckaroo29: a found cycle fails verification (\(problem))")
            }
            let powData = Cuckaroo29Reference.pack(nonces, edgeBits: edgeBits)
            let hash = Cuckaroo29Reference.blake2b(powData)
            out.append(Solution(nonces: nonces, powData: powData, hash: hash,
                                difficulty: Cuckaroo29Reference.difficulty(hash: hash)))
        }
        if verbose && edgeBits > 22 {
            let ms = { (s: Double) in fmt(s * 1000, 1) }
            let counts = stats.contents().bindMemory(to: UInt32.self, capacity: rounds + 2)
            let marks = [1, 2, 3, 4, 5, 8, 16, 24, 32, 64, 96, 128, 160, 192, 256, 320, 384].filter { $0 <= rounds }
            print("   [c29] GPU ms per command buffer: \(lastGPUTimes.map(ms).joined(separator: " "))"
                + "; copy \(ms(lastCopySeconds)) ms; cycle finding \(ms(findSeconds)) ms over \(survivors.count) edges;"
                + " \(found.allCycles) cycles, \(found.cycles.count) of length 42; recovery+verify \(ms(now() - start - findSeconds)) ms")
            print("   [c29] edges into round: " + marks.map { "\($0): \(counts[$0])" }.joined(separator: ", "))
        }
        return out
    }

    // MARK: Mining

    /// One graph of a pool job: header nonce `nonce` under the job's 32-byte mining hash (Tari's
    /// BlockHeader::mining_hash, the job's "blob"). The siphash keys are Tari's: blake2b-256 of the nonce's 8 big-endian
    /// bytes followed by the mining hash. The GPU trims the graph, the CPU finds its 42-cycles, the GPU recovers their
    /// edge nonces and the CPU verifies each one. Returns every verified 42-cycle with its pow_data, proof hash and
    /// difficulty; the caller compares the difficulty with its share or block target.
    func solve(miningHash: [UInt8], nonce: UInt64) throws -> [Solution] {
        guard miningHash.count == 32 else {
            throw MinerError("cuckaroo29: a mining hash is 32 bytes, this one is \(miningHash.count)")
        }
        let keys = Cuckaroo29Reference.keys(miningHash: miningHash, nonce: nonce)
        let found = try solutions(keys: keys, survivors: try trim(keys: keys))
        graphs += 1
        return found
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        for i in 0 ..< count {
            let nonce = startNonce &+ UInt64(i)
            for solution in try solve(miningHash: miningHash, nonce: nonce) where solution.difficulty >= targetDifficulty {
                hits.append((nonce, solution))
            }
        }
        return Double(count)
    }

    // MARK: Checks against the CPU

    func crossCheck(samples: Int) throws -> String {
        guard checks else { return "skipped (--set check=0, a timing aid)" }
        var parts: [String] = []
        let known = Cuckaroo29Reference.knownGraphs(edgeBits: edgeBits)
        for graph in known {
            let survivors = try trim(keys: graph.keys)
            let found = try solutions(keys: graph.keys, survivors: survivors)
            guard let match = found.first(where: { $0.nonces == graph.nonces }) else {
                throw MinerError("\(graph.name): the GPU solver missed the published 42-cycle"
                    + " (\(survivors.count) edges left, \(found.count) other 42-cycles)")
            }
            if let want = graph.powHash, match.hash.hex != want {
                throw MinerError("\(graph.name): proof hash \(match.hash.hex), want \(want)")
            }
        }
        if !known.isEmpty {
            parts.append("solver finds the published 42-cycles of \(known.map { $0.name }.joined(separator: ", "))")
        }
        let graphsToCheck = max(1, samples / 16)
        var summary = ""
        for _ in 0 ..< graphsToCheck {
            summary = try stepwiseCheck(keys: (0 ..< 4).map { _ in UInt64.random(in: 0 ... .max) })
        }
        parts.append("\(graphsToCheck) random graph(s): \(summary)")
        if edgeBits <= 22 {
            let keys = (0 ..< 4).map { _ in UInt64.random(in: 0 ... .max) }
            let gpuEdges = Cuckaroo29Reference.sortedEdges(try trim(keys: keys))
            let cpuEdges = Cuckaroo29Reference.trimmed(keys: keys, edgeBits: edgeBits, rounds: rounds)
            guard gpuEdges == cpuEdges else {
                throw MinerError("trimmed graph differs: GPU \(gpuEdges.count) edges, whole-graph CPU trim \(cpuEdges.count)")
            }
            parts.append("whole-graph CPU trim leaves the same \(cpuEdges.count) edges")
        }
        guard droppedEdges == 0 else { throw MinerError("cuckaroo29: \(droppedEdges) edges dropped by full buckets") }
        return parts.joined(separator: "; ")
    }

    /// Seeds one graph and runs each trimming round on its own, checking every step on the CPU: seeding against the
    /// CPU's edge generation, and each round against the trimming rule applied to that round's GPU input (per-bucket
    /// edge counts and fingerprint sums).
    private func stepwiseCheck(keys: [UInt64]) throws -> String {
        resetCounts()
        try gpu.compute("cuckaroo29 seed") { encodeSeed($0, keys: keys) }
        try compare(Cuckaroo29Reference.seedTotals(keys: keys, edgeBits: edgeBits, zBits: zBits),
                    try bufferTotals(edgesA, countA, cap: capA), "seeding")
        var left = 1 << edgeBits
        for round in 1 ... rounds {
            let odd = round % 2 == 1
            let (source, sourceCounts, sourceCap) = odd ? (edgesA, countA, capA) : (edgesB, countB, capB)
            let (target, targetCounts, targetCap) = odd ? (edgesB, countB, capB) : (edgesA, countA, capA)
            let saved = Array(UnsafeBufferPointer(start: sourceCounts.contents().bindMemory(to: UInt32.self, capacity: buckets),
                                                  count: buckets))
            try gpu.compute("cuckaroo29 trim") { encodeTrim($0, round: round) }
            let got = try bufferTotals(target, targetCounts, cap: targetCap)
            try compare(roundTotals(source, counts: saved, cap: sourceCap), got, "round \(round)")
            left = got.counts.reduce(0) { $0 + Int($1) }
        }
        _ = takeSurvivors()
        return "seeding and all \(rounds) rounds (\(sparseFrom) bit-map, \(rounds - min(rounds, sparseFrom)) hash-table)"
            + " match the CPU (\(left) edges left)"
    }

    private func compare(_ want: (counts: [UInt32], sums: [UInt64]), _ got: (counts: [UInt32], sums: [UInt64]),
                         _ step: String) throws {
        for b in 0 ..< buckets where want.counts[b] != got.counts[b] || want.sums[b] != got.sums[b] {
            throw MinerError("cuckaroo29 \(step): GPU bucket \(b) has \(got.counts[b]) edges (sum \(String(got.sums[b], radix: 16))),"
                + " CPU expects \(want.counts[b]) (\(String(want.sums[b], radix: 16)))")
        }
    }

    /// Per-bucket edge count and fingerprint sum of a GPU edge buffer; throws on an overflowing bucket.
    private func bufferTotals(_ edges: MTLBuffer, _ countBuffer: MTLBuffer, cap: Int) throws -> (counts: [UInt32], sums: [UInt64]) {
        let counts = countBuffer.contents().bindMemory(to: UInt32.self, capacity: buckets)
        if let b = (0 ..< buckets).first(where: { Int(counts[$0]) > cap }) {
            throw MinerError("cuckaroo29: bucket \(b) overflowed (\(counts[b]) edges, capacity \(cap))")
        }
        let base = edges.contents().bindMemory(to: SIMD2<UInt32>.self, capacity: buckets * cap)
        let buckets = self.buckets
        let chunks = min(buckets, 64)
        return Cuckaroo29Reference.perBucketTotals(buckets: buckets, chunks: chunks) { c, counted, sums in
            for b in stride(from: c, to: buckets, by: chunks) {
                let e = base + b * cap
                var sum: UInt64 = 0
                for i in 0 ..< Int(counts[b]) { sum &+= Cuckaroo29Reference.fingerprint(e[i].x, e[i].y) }
                counted[b] = counts[b]
                sums[b] = sum
            }
        }
    }

    /// What a trimming round must write, from its GPU input: an edge survives when another edge in its bucket shares
    /// its node; it goes, swapped, to the bucket of its other node. Per output bucket count and fingerprint sum.
    private func roundTotals(_ edges: MTLBuffer, counts: [UInt32], cap: Int) -> (counts: [UInt32], sums: [UInt64]) {
        let base = edges.contents().bindMemory(to: SIMD2<UInt32>.self, capacity: buckets * cap)
        let zBits = self.zBits, buckets = self.buckets
        let zMask = UInt32((1 << zBits) - 1)
        let chunks = min(buckets, 64)
        return counts.withUnsafeBufferPointer { counts in
            Cuckaroo29Reference.perBucketTotals(buckets: buckets, chunks: chunks) { c, counted, sums in
                var degree = [UInt8](repeating: 0, count: 1 << zBits)
                for b in stride(from: c, to: buckets, by: chunks) {
                    let e = base + b * cap
                    let n = min(Int(counts[b]), cap)
                    for i in 0 ..< n where degree[Int(e[i].x & zMask)] < 2 { degree[Int(e[i].x & zMask)] += 1 }
                    for i in 0 ..< n where degree[Int(e[i].x & zMask)] == 2 {
                        let out = Int(e[i].y >> UInt32(zBits))
                        counted[out] &+= 1
                        sums[out] &+= Cuckaroo29Reference.fingerprint(e[i].y, e[i].x)
                    }
                    for i in 0 ..< n { degree[Int(e[i].x & zMask)] = 0 }
                }
            }
        }
    }
}
