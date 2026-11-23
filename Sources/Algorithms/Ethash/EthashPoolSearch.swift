import Foundation
import Metal

extension EthashChain {
    /// The size epoch (cache and DAG sizes) for a seed hash made with `k` keccak256 rounds. With 60,000-block epochs the
    /// seed still counts 30,000-block periods (core-geth's seedHash), so k = 2 x epoch; before the switch (ETC below
    /// block 11,700,000, k < 390) epochs were 30,000 blocks and k = epoch.
    func sizeEpoch(seedIterations k: Int) -> Int {
        guard let start = longEpochsFrom, k >= start / 30_000 else { return k }
        return k / 2
    }
}

/// Ethash pool mining on the GPU: the DAG for a job's seed hash (built only when the epoch changes, spot-checked against
/// the light cache), the cooperative search kernel against the target's first 8 bytes, then each candidate re-hashed
/// for its mix digest, checked against the full 256-bit target, and recomputed on the CPU over the same DAG.
final class EthashJobSearch: EthashPoolSearch {
    let gpu: GPU
    let chain: EthashChain
    let group = 128
    var defaultBatch: Int { 1 << 20 }
    private(set) var epoch = -1
    private let searchPipeline: MTLComputePipelineState
    private let hashPipeline: MTLComputePipelineState
    private let headerBuffer: MTLBuffer
    private let output: MTLBuffer
    private var dag: MTLBuffer?
    private var seed: [UInt8]?
    private var datasetBytes = 0
    private var header = [UInt8](repeating: 0, count: 32)
    private var target = [UInt8](repeating: 0, count: 32)

    init(gpu: GPU, chain: EthashChain) throws {
        self.gpu = gpu
        self.chain = chain
        let library = try gpu.library(["ethash.metal", "ethash_coop.metal"])
        searchPipeline = try gpu.pipeline(library, "ethash_search_coop")
        hashPipeline = try gpu.pipeline(library, "ethash_hash")
        headerBuffer = try gpu.buffer(32, label: "ethash pool header")
        output = try gpu.buffer(MemoryLayout<UInt64>.stride * 64, label: "ethash pool hits")
    }

    func prepare(_ job: EthashPoolJob) throws -> String? {
        var note: String?
        if job.seed != seed || dag == nil {
            guard let k = EthashSeeds.iterations(of: job.seed) else {
                throw MinerError("job \(job.id): seed hash \(job.seed.hex) isn't an Ethash seed within 8,192 epochs")
            }
            note = try buildDAG(epoch: chain.sizeEpoch(seedIterations: k), seed: job.seed, seedIterations: k, height: job.height)
        }
        header = job.header
        target = job.target
        header.withUnsafeBytes { headerBuffer.contents().copyMemory(from: $0.baseAddress!, byteCount: 32) }
        return note
    }

    private func buildDAG(epoch: Int, seed: [UInt8], seedIterations k: Int, height: Int?) throws -> String {
        dag = nil   // free the old DAG before building the next
        self.seed = nil
        let start = now()
        let datasetBytes = EthashReference.datasetSize(epoch: epoch)
        let cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epoch), seed: seed)
        let (dag, gpuSeconds) = try EthashDAG.build(gpu: gpu, cache: cache, datasetBytes: datasetBytes)
        try EthashPoolKit.spotCheck(dag: dag, cache: cache, datasetBytes: datasetBytes, parents: EthashReference.datasetParents)
        self.dag = dag
        self.seed = seed
        self.epoch = epoch
        self.datasetBytes = datasetBytes
        var note = "\(chain.id) DAG for epoch \(epoch) (seed hash \(k) rounds"
        if let height {
            let expected = chain.epochs(atHeight: height)
            note += expected.sizeEpoch == epoch ? ", matches block \(height)" : "; block \(height) would be epoch \(expected.sizeEpoch)"
        }
        return note + ", \(formatBytes(datasetBytes))) built in \(fmt(now() - start, 1)) s (GPU \(fmt(gpuSeconds, 1)) s), spot-checked"
    }

    func search(startNonce: UInt64, count: Int) throws -> (hashes: Int, solutions: [EthashPoolSolution]) {
        guard let dag else { throw MinerError("Ethash search before a job was prepared") }
        let threads = (count + group - 1) / group * group   // whole threadgroups keep the 8-lane groups intact
        var start = startNonce
        var target64 = EthashTarget.top64(target)
        var pages = UInt32(datasetBytes / 128)
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("ethash pool search") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBytes(&target64, length: 8, index: 3)
            encoder.setBytes(&pages, length: 4, index: 4)
            encoder.setBuffer(output, offset: 0, index: 5)
            gpu.dispatch(encoder, searchPipeline, threads: threads, group: group)
        }
        let hits = min(Int(output.contents().load(as: UInt32.self)), 62)   // SEARCH_MAX_HITS
        guard hits > 0 else { return (threads, []) }
        let nonces = (0 ..< hits).map { output.contents().load(fromByteOffset: 8 + 8 * $0, as: UInt64.self) }
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        var solutions: [EthashPoolSolution] = []
        let results = try hashes(nonces, dag)
        for (nonce, result) in zip(nonces, results) where EthashTarget.meets(result.final, target) {
            let cpu = EthashReference.hashimoto(header: header, nonce: nonce, datasetBytes: datasetBytes) { index in
                Array(UnsafeBufferPointer(start: words + 16 * Int(index), count: 16))
            }
            guard cpu.mix == result.mix, cpu.final == result.final else {
                throw MinerError("the GPU's hash for nonce \(String(format: "%016llx", nonce)) differs from the CPU reference; nothing submitted")
            }
            solutions.append(EthashPoolSolution(nonce: nonce, mix: result.mix, final: result.final))
        }
        return (threads, solutions)
    }

    /// Mix digest and final hash for each nonce, from the simple hash kernel.
    private func hashes(_ nonces: [UInt64], _ dag: MTLBuffer) throws -> [(mix: [UInt8], final: [UInt8])] {
        let nonceBuffer = try gpu.buffer(nonces, label: "ethash pool nonces")
        let results = try gpu.buffer(nonces.count * 64, label: "ethash pool results")
        var pages = UInt32(datasetBytes / 128)
        try gpu.compute("ethash pool hash") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBytes(&pages, length: 4, index: 3)
            encoder.setBuffer(results, offset: 0, index: 4)
            gpu.dispatch(encoder, hashPipeline, threads: nonces.count, group: 32)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: nonces.count * 16)
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
