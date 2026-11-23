import Foundation
import Metal

enum OctopusFamily {
    static let algorithms: [MiningAlgorithm.Type] = [Octopus.self]
    static let poolMiners: [PoolMiner.Type] = [OctopusPoolMiner.self]
}

/// Conflux mainnet height over time: pivot block 161,619,968 (0x9a22000) at 2026-11-19 21:16:32 UTC, and the
/// average time per height since block 134,217,728 (2025-11-08 07:12:52 UTC).
enum OctopusChain {
    static let referenceHeight = 161_619_968
    static let referenceTime = 1_795_122_992.0
    static let secondsPerHeight = 1.1874

    static var estimatedHeight: Int {
        referenceHeight + max(0, Int((Date().timeIntervalSince1970 - referenceTime) / secondsPerHeight))
    }
}

/// Octopus (Conflux, CFX). Options: --set height=N, --set stage=N, --set kernel=coop|simple (default coop),
/// --set group=N (threads per threadgroup, multiple of 32, at most 160), --set mulmod=float|shoup|wide
/// (polynomial arithmetic, default float), --set chains=N (points per Horner pass, divides 32, default 8),
/// --set par=N (hashes in flight per 16-lane group, divides 16, default 2), --set fastmod=1|0 (page index by
/// float reciprocal or integer %). Diagnostics only: --set phase=walk|poly|none skips the polynomial, the DAG
/// loads, or both (hashes are then wrong, so the GPU cross-check is skipped).
final class Octopus: MiningAlgorithm {
    static let id = "octopus"
    static let coins = ["CFX"]

    let gpu: GPU
    let stage: Int
    let quick: Bool
    let diagnostic: Bool
    let cache: [UInt32]
    let datasetBytes: Int
    let dag: MTLBuffer
    let group: Int
    let searchPipeline: MTLComputePipelineState
    let searchPipelines: [(name: String, pipeline: MTLComputePipelineState)]
    let hashPipelines: [(name: String, pipeline: MTLComputePipelineState)]
    let headerBuffer: MTLBuffer
    let pointBuffer: MTLBuffer
    let targetBuffer: MTLBuffer
    let output: MTLBuffer
    private(set) var header: [UInt8] = []
    let setupSummary: String
    var defaultBatch: Int { 1 << 18 }

    init(gpu: GPU, config: AlgoConfig) throws {
        let height = config.quick ? 0 : (config.int("height") ?? OctopusChain.estimatedHeight)
        let stage = config.int("stage") ?? OctopusReference.stage(height: height)
        let cacheBytes = config.quick ? OctopusReference.quickCacheBytes : OctopusReference.cacheSize(stage: stage)
        let datasetBytes = config.quick ? OctopusReference.quickDatasetBytes : OctopusReference.datasetSize(stage: stage)

        let kernel = config.options["kernel"] ?? "coop"
        guard kernel == "coop" || kernel == "simple" else { throw MinerError("kernel must be coop or simple") }
        let group = config.int("group") ?? 128
        guard group % 32 == 0, group >= 32, group <= 160 else {
            throw MinerError("group must be a multiple of 32, at most 160 (threadgroup memory)")
        }
        let mulmods = ["float": "0", "shoup": "1", "wide": "2"]
        let mulmod = config.options["mulmod"] ?? "float"
        guard let mulmodMacro = mulmods[mulmod] else { throw MinerError("mulmod must be float, shoup or wide") }
        let chains = config.int("chains") ?? 8
        guard chains > 0, 32 % chains == 0 else { throw MinerError("chains must divide 32") }
        let par = config.int("par") ?? 2
        guard par > 0, 16 % par == 0 else { throw MinerError("par must divide 16") }
        let fastmod = config.int("fastmod") ?? 1
        let phases = ["both": "0", "walk": "1", "poly": "2", "none": "3"]
        let phase = config.options["phase"] ?? "both"
        guard let phaseMacro = phases[phase] else { throw MinerError("phase must be both, walk, poly or none") }

        // The light cache and the DAG items are Ethash's; only the sizes differ.
        let t0 = now()
        let cache = EthashReference.makeCache(size: cacheBytes, seed: EthashReference.seed(iterations: stage))
        let cacheSeconds = now() - t0
        let (dag, dagSeconds) = try EthashDAG.build(gpu: gpu, cache: cache, datasetBytes: datasetBytes)

        let macros = ["OCTOPUS_GROUP": "\(group)", "OCTOPUS_MULMOD": mulmodMacro, "OCTOPUS_CHAINS": "\(chains)",
                      "OCTOPUS_PAR": "\(par)", "OCTOPUS_FASTMOD": "\(fastmod)", "OCTOPUS_PHASE": phaseMacro]
        let library = try gpu.library(["ethash.metal", "octopus.metal"], macros: macros)
        let pipelines = try ["coop", "simple"].map { name in
            (name: name, search: try gpu.pipeline(library, name == "coop" ? "octopus_search" : "octopus_search_simple"),
             hash: try gpu.pipeline(library, name == "coop" ? "octopus_hash" : "octopus_hash_simple"))
        }
        for p in pipelines where p.search.maxTotalThreadsPerThreadgroup < group || p.hash.maxTotalThreadsPerThreadgroup < group {
            throw MinerError("\(p.name) kernel allows at most \(min(p.search.maxTotalThreadsPerThreadgroup, p.hash.maxTotalThreadsPerThreadgroup)) threads per threadgroup; lower --set group")
        }

        self.gpu = gpu
        self.stage = stage
        self.quick = config.quick
        diagnostic = phase != "both"
        self.cache = cache
        self.datasetBytes = datasetBytes
        self.dag = dag
        self.group = group
        searchPipeline = pipelines.first { $0.name == kernel }!.search
        searchPipelines = pipelines.map { ($0.name, $0.search) }
        hashPipelines = pipelines.map { ($0.name, $0.hash) }
        headerBuffer = try gpu.buffer(32, label: "octopus header")
        pointBuffer = try gpu.buffer(16 * OctopusReference.coefficientCount, label: "octopus points")
        targetBuffer = try gpu.buffer(32, label: "octopus boundary")
        output = try gpu.buffer(512, label: "octopus hits")
        let sizes = config.quick ? "quick sizes" : "height \(height) · stage \(stage)"
        setupSummary = "\(sizes) · DAG \(formatBytes(datasetBytes)) built in \(fmt(dagSeconds, 1)) s"
            + " · cache \(formatBytes(cacheBytes)) in \(fmt(cacheSeconds, 1)) s · \(kernel) kernel, group \(group),"
            + " \(mulmod) mulmod, chains \(chains), par \(par), fastmod \(fastmod)"
            + (phase == "both" ? "" : " · DIAGNOSTIC phase=\(phase)")
        setJob(header: randomBytes(32))
        setTarget([0, 0, 0, 0])   // unreachable: the benchmark measures, it doesn't mine
    }

    /// A new job: the 32-byte PoW problem hash. Fills the header words and the 1024 evaluation points.
    func setJob(header: [UInt8]) {
        self.header = header
        let words = OctopusReference.headerWords(header)
        words.withUnsafeBytes { headerBuffer.contents().copyMemory(from: $0.baseAddress!, byteCount: 32) }
        let x = OctopusReference.points(OctopusReference.params(header: header))
        let table = pointBuffer.contents().bindMemory(to: UInt32.self, capacity: 4 * x.count)
        let p = OctopusReference.modulus
        for (k, xk) in x.enumerated() {
            table[4 * k] = Float(xk).bitPattern
            table[4 * k + 1] = Float(Double(xk) / Double(p)).bitPattern
            table[4 * k + 2] = xk
            table[4 * k + 3] = UInt32((UInt64(xk) << 32) / p)
        }
    }

    /// The share boundary as four 64-bit limbs, most significant first: a hit is a hash (read big-endian) below it.
    func setTarget(_ limbs: [UInt64]) {
        limbs.withUnsafeBytes { targetBuffer.contents().copyMemory(from: $0.baseAddress!, byteCount: 32) }
    }

    func knownAnswerTests() throws -> [String] {
        try OctopusReference.runVectors(cached: quick ? nil : (stage: stage, cache: cache))
    }

    /// DAG item `index` (16 words) as the GPU built it; the pool miner checks its hits on the CPU with these.
    func dagItem(_ index: UInt32) -> [UInt32] {
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        return Array(UnsafeBufferPointer(start: words + 16 * Int(index), count: 16))
    }

    /// One search dispatch over `threads` nonces from `start` (a multiple of 32). Returns the hits.
    @discardableResult
    func search(_ pipeline: MTLComputePipelineState, start: UInt64, threads: Int) throws -> [UInt64] {
        var start = start
        var pages = UInt32(datasetBytes / OctopusReference.pageBytes)
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("octopus search") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(pointBuffer, offset: 0, index: 2)
            encoder.setBytes(&start, length: 8, index: 3)
            encoder.setBuffer(targetBuffer, offset: 0, index: 4)
            encoder.setBytes(&pages, length: 4, index: 5)
            encoder.setBuffer(output, offset: 0, index: 6)
            gpu.dispatch(encoder, pipeline, threads: threads, group: group)
        }
        let count = Int(output.contents().load(as: UInt32.self))
        let nonces = output.contents().advanced(by: 8).bindMemory(to: UInt64.self, capacity: 62)
        return (0 ..< min(count, 62)).map { nonces[$0] }
    }

    /// Digest + final hash (64 bytes per nonce) for `count` nonces from `start`, from one of the hash kernels.
    private func gpuHashes(_ pipeline: MTLComputePipelineState, start: UInt64, count: Int) throws -> [[UInt8]] {
        var start = start
        var pages = UInt32(datasetBytes / OctopusReference.pageBytes)
        let results = try gpu.buffer(count * 64, label: "octopus results")
        try gpu.compute("octopus hash") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(pointBuffer, offset: 0, index: 2)
            encoder.setBytes(&start, length: 8, index: 3)
            encoder.setBytes(&pages, length: 4, index: 5)
            encoder.setBuffer(results, offset: 0, index: 6)
            gpu.dispatch(encoder, pipeline, threads: count, group: group)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: count * 16)
        return (0 ..< count).map { n in
            var bytes: [UInt8] = []
            for w in 0 ..< 16 { bytes.appendLE(words[16 * n + w]) }
            return bytes
        }
    }

    func crossCheck(samples: Int) throws -> String {
        let cacheItems = cache.count / 16
        // 1. DAG items built on the GPU against the CPU reference
        let itemCount = 16
        try cache.withUnsafeBufferPointer { c in
            for _ in 0 ..< itemCount {
                let i = UInt32.random(in: 0 ..< UInt32(datasetBytes / 64))
                let cpu = EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: cacheItems, index: i)
                guard cpu == dagItem(i) else { throw MinerError("DAG item \(i) differs from the CPU reference") }
            }
        }
        if diagnostic { return "\(itemCount) DAG items match; hash cross-check skipped (diagnostic phase)" }
        // 2. Both hash kernels against the CPU reference over the same DAG, on whole threadgroups of consecutive
        //    nonces from a random multiple of 32, with a fresh random header
        setJob(header: randomBytes(32))
        let count = max(group, (samples + group - 1) / group * group)
        let start = UInt64.random(in: 0 ... UInt64.max - UInt64(count)) & ~31
        let cpu = (0 ..< count).map { n in
            OctopusReference.hash(header: header, nonce: start + UInt64(n), datasetBytes: datasetBytes) { dagItem($0) }
        }
        for (name, pipeline) in hashPipelines {
            for (n, gpuBytes) in try gpuHashes(pipeline, start: start, count: count).enumerated()
            where gpuBytes != cpu[n].digest + cpu[n].final {
                throw MinerError("\(name) kernel, nonce \(String(start + UInt64(n), radix: 16)): GPU \(gpuBytes.hex) vs CPU \((cpu[n].digest + cpu[n].final).hex)")
            }
        }
        // 3. One hash entirely from the light cache, so the DAG isn't the only witness
        let light = cache.withUnsafeBufferPointer { c in
            OctopusReference.hash(header: header, nonce: start, datasetBytes: datasetBytes) {
                EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: cacheItems, index: $0)
            }
        }
        guard light.final == cpu[0].final else { throw MinerError("light-cache hash differs from the DAG hash") }
        // 4. Both search kernels: a boundary one above the lowest hash finds exactly that nonce; the lowest hash
        //    itself as the boundary finds nothing (the comparison is strict)
        let hashes = cpu.map { OctopusReference.limbs($0.final) }
        let best = hashes.indices.min { hashes[$0].lexicographicallyPrecedes(hashes[$1]) }!
        var above = hashes[best]
        var i = 3
        while above[i] == UInt64.max {
            above[i] = 0
            i -= 1
        }
        above[i] += 1
        defer { setTarget([0, 0, 0, 0]) }
        for (name, pipeline) in searchPipelines {
            setTarget(above)
            let hits = try search(pipeline, start: start, threads: count)
            guard hits == [start + UInt64(best)] else {
                throw MinerError("\(name) search with boundary just above nonce \(String(start + UInt64(best), radix: 16)) reported \(hits.map { String($0, radix: 16) })")
            }
            setTarget(hashes[best])
            let none = try search(pipeline, start: start, threads: count)
            guard none.isEmpty else { throw MinerError("\(name) search reported \(none.count) hits at boundary = lowest hash") }
        }
        return "\(itemCount) DAG items, \(count) hashes from each kernel (coop, simple), 1 light-cache hash and the"
            + " boundary check of both search kernels match the CPU reference"
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let threads = (count + group - 1) / group * group   // whole threadgroups, so warps and 16-lane groups stay intact
        try search(searchPipeline, start: startNonce & ~31, threads: threads)
        return Double(threads)
    }
}
