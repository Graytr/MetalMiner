import Foundation
import Metal

/// KawPow pool mining on the GPU: the DAG for a job's epoch (built only when it changes, spot-checked against the light
/// cache), the random program for its period (compiled when the period changes, every 3 blocks: about 3 minutes on
/// Ravencoin), the search kernel against the target's first 8 bytes, then each candidate re-hashed for its mix digest,
/// checked against the full 256-bit target, and recomputed on the CPU over the same DAG.
final class KawPowJobSearch: EthashPoolSearch {
    let gpu: GPU
    let group: Int
    var defaultBatch: Int { 1 << 20 }
    private(set) var epoch = -1
    private(set) var period: UInt64?

    private let commonSource: String
    private let kernelSource: String
    private let headerBuffer: MTLBuffer
    private let output: MTLBuffer
    private var dag: MTLBuffer?
    private var datasetBytes = 0
    private var items: UInt32 = 0
    /// The DAG's first 16 KiB (ProgPoW's L1 cache), for the CPU check.
    private var l1: [UInt32] = []
    /// Compiled programs for the last few periods. Compiled here rather than through GPU.library(source:key:), which
    /// keeps every library forever: a new period every 3 minutes would add about 480 libraries a day.
    private var programs: [UInt64: (search: MTLComputePipelineState, hash: MTLComputePipelineState)] = [:]
    private var header = [UInt8](repeating: 0, count: 32)
    private var height = 0
    private var target = [UInt8](repeating: 0, count: 32)

    init(gpu: GPU, group: Int = 256) throws {
        self.gpu = gpu
        self.group = group
        commonSource = try gpu.kernelSource("common.metal")
        kernelSource = try gpu.kernelSource("kawpow.metal")
        headerBuffer = try gpu.buffer(32, label: "kawpow pool header")
        output = try gpu.buffer(MemoryLayout<UInt64>.stride * 64, label: "kawpow pool hits")
    }

    func prepare(_ job: EthashPoolJob) throws -> String? {
        guard let height = job.height, height >= 0 else { throw MinerError("KawPow job \(job.id) has no block height") }
        var notes: [String] = []
        // The DAG follows the seed hash, as in kawpowminer; the program follows the height. They should agree.
        let heightEpoch = height / KawPowReference.epochLength
        var epoch = heightEpoch
        if let seedEpoch = EthashSeeds.iterations(of: job.seed) {
            if seedEpoch != heightEpoch { notes.append("seed hash is epoch \(seedEpoch) but block \(height) is epoch \(heightEpoch); using the seed's") }
            epoch = seedEpoch
        } else {
            notes.append("job \(job.id): unknown seed hash \(job.seed.hex.prefix(16))…; using epoch \(heightEpoch) from block \(height)")
        }
        if epoch != self.epoch || dag == nil { notes.append(try buildDAG(epoch: epoch)) }
        let period = UInt64(height / KawPowReference.periodLength)
        if period != self.period {
            let start = now()
            let cached = programs[period] != nil
            try program(period)
            self.period = period
            notes.append("program for period \(period) (block \(height)) " + (cached ? "reused" : "compiled in \(Int((now() - start) * 1000)) ms"))
        }
        header = job.header
        self.height = height
        target = job.target
        header.withUnsafeBytes { headerBuffer.contents().copyMemory(from: $0.baseAddress!, byteCount: 32) }
        return notes.isEmpty ? nil : notes.joined(separator: "; ")
    }

    private func buildDAG(epoch: Int) throws -> String {
        dag = nil   // free the old DAG before building the next
        l1 = []
        self.epoch = -1
        let start = now()
        let datasetBytes = EthashReference.datasetSize(epoch: epoch)
        let cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epoch), seed: EthashReference.seed(iterations: epoch))
        let (dag, gpuSeconds) = try EthashDAG.build(gpu: gpu, cache: cache, datasetBytes: datasetBytes, parents: KawPowReference.datasetParents)
        try EthashPoolKit.spotCheck(dag: dag, cache: cache, datasetBytes: datasetBytes, parents: KawPowReference.datasetParents)
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        l1 = Array(UnsafeBufferPointer(start: words, count: KawPowReference.cacheWords))
        self.dag = dag
        self.datasetBytes = datasetBytes
        self.epoch = epoch
        items = UInt32(datasetBytes / 256)
        return "KawPow DAG for epoch \(epoch) (\(formatBytes(datasetBytes))) built in \(fmt(now() - start, 1)) s (GPU \(fmt(gpuSeconds, 1)) s), spot-checked"
    }

    @discardableResult
    private func program(_ period: UInt64) throws -> (search: MTLComputePipelineState, hash: MTLComputePipelineState) {
        if let cached = programs[period] { return cached }
        let source = commonSource + "\n" + KawPowFamily.metalProgram(KawPowReference.program(period: period)) + "\n" + kernelSource
        let library: MTLLibrary
        do {
            library = try gpu.device.makeLibrary(source: source, options: MTLCompileOptions())
        } catch {
            throw MinerError("the KawPow program for period \(period) didn't compile: \(error)")
        }
        let pipelines = (search: try gpu.pipeline(library, "kawpow_search"), hash: try gpu.pipeline(library, "kawpow_hash"))
        if programs.count >= 3, let oldest = programs.keys.min() { programs[oldest] = nil }
        programs[period] = pipelines
        return pipelines
    }

    func search(startNonce: UInt64, count: Int) throws -> (hashes: Int, solutions: [EthashPoolSolution]) {
        guard let dag, let period, let pipelines = programs[period] else { throw MinerError("KawPow search before a job was prepared") }
        let threads = (count + group - 1) / group * group   // whole threadgroups keep the 16-lane groups intact
        var start = startNonce
        var target64 = EthashTarget.top64(target)
        var itemCount = items
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("kawpow pool search") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBytes(&target64, length: 8, index: 3)
            encoder.setBytes(&itemCount, length: 4, index: 4)
            encoder.setBuffer(output, offset: 0, index: 5)
            gpu.dispatch(encoder, pipelines.search, threads: threads, group: group)
        }
        let hits = min(Int(output.contents().load(as: UInt32.self)), 62)   // SEARCH_MAX_HITS
        guard hits > 0 else { return (threads, []) }
        let nonces = (0 ..< hits).map { output.contents().load(fromByteOffset: 8 + 8 * $0, as: UInt64.self) }
        let results = try hashes(nonces, dag, pipelines.hash)
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        var solutions: [EthashPoolSolution] = []
        for (nonce, result) in zip(nonces, results) where EthashTarget.meets(result.final, target) {
            let cpu = KawPowReference.hash(header: header, nonce: nonce, blockNumber: height, items: items, l1: l1) { index in
                Array(UnsafeBufferPointer(start: words + 64 * Int(index), count: 64))
            }
            guard cpu.mix == result.mix, cpu.final == result.final else {
                throw MinerError("the GPU's KawPow hash for nonce \(String(format: "%016llx", nonce)) differs from the CPU reference; nothing submitted")
            }
            solutions.append(EthashPoolSolution(nonce: nonce, mix: result.mix, final: result.final))
        }
        return (threads, solutions)
    }

    /// Mix digest and final hash for each nonce. kawpow_hash shares work across 16 lanes, so the dispatch is padded to
    /// whole SIMD groups.
    private func hashes(_ nonces: [UInt64], _ dag: MTLBuffer, _ pipeline: MTLComputePipelineState) throws -> [(mix: [UInt8], final: [UInt8])] {
        let count = (nonces.count + 31) / 32 * 32
        let padded = nonces + Array(repeating: nonces[nonces.count - 1], count: count - nonces.count)
        let nonceBuffer = try gpu.buffer(padded, label: "kawpow pool nonces")
        let results = try gpu.buffer(count * 64, label: "kawpow pool results")
        var itemCount = items
        try gpu.compute("kawpow pool hash") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBytes(&itemCount, length: 4, index: 3)
            encoder.setBuffer(results, offset: 0, index: 4)
            gpu.dispatch(encoder, pipeline, threads: count, group: 32)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: count * 16)
        return (0 ..< nonces.count).map { n in
            var mix: [UInt8] = [], final: [UInt8] = []
            for w in 0 ..< 8 {
                mix.appendLE(words[16 * n + w])
                final.appendLE(words[16 * n + 8 + w])
            }
            return (mix, final)
        }
    }
}
