import Foundation
import Metal

enum EthashFamily {
    static let algorithms: [MiningAlgorithm.Type] = [Etchash.self, EthashETHW.self, EthashOcta.self]
}

final class Etchash: EthashBase { override class var chain: EthashChain { .ethereumClassic } }
final class EthashETHW: EthashBase { override class var chain: EthashChain { .ethereumPoW } }
final class EthashOcta: EthashBase { override class var chain: EthashChain { .octaSpace } }

/// What differs between Ethash-family coins: epoch length and today's height.
struct EthashChain {
    let id: String
    let coins: [String]
    /// Height from which epochs are 60,000 blocks (ECIP-1099): ETC from 11,700,000. nil: 30,000-block epochs throughout.
    let longEpochsFrom: Int?
    /// Height on 2026-11-19 21:00 UTC (Kryptex's DAG size calculator) and the average block time.
    let referenceHeight: Int
    let blockSeconds: Double

    static let referenceTime = 1_795_122_000.0

    /// The epoch that sets the cache and DAG sizes, and how many keccak256 rounds make the seed.
    /// With 60,000-block epochs the seed still counts 30,000-block periods (core-geth's seedHash).
    func epochs(atHeight height: Int) -> (sizeEpoch: Int, seedIterations: Int) {
        if let start = longEpochsFrom, height >= start {
            return (height / 60_000, 2 * (height / 60_000))
        }
        return (height / 30_000, height / 30_000)
    }

    var estimatedHeight: Int {
        referenceHeight + max(0, Int((Date().timeIntervalSince1970 - EthashChain.referenceTime) / blockSeconds))
    }

    static let ethereumClassic = EthashChain(id: "etchash", coins: ["ETC"], longEpochsFrom: 11_700_000,
                                             referenceHeight: 25_766_650, blockSeconds: 13.374)
    static let ethereumPoW = EthashChain(id: "ethash", coins: ["ETHW"], longEpochsFrom: nil,
                                         referenceHeight: 25_494_818, blockSeconds: 13.227)
    /// Standard 30,000-block epochs, as in go-octa's consensus/ethash (and Kryptex's own OCTA miner settings, plain
    /// Ethash). Kryptex's DAG size calculator assumes 60,000-block epochs for OCTA; that gives the wrong DAG.
    static let octaSpace = EthashChain(id: "ethash-octa", coins: ["OCTA"], longEpochsFrom: nil,
                                       referenceHeight: 10_783_465, blockSeconds: 13.02)
}

/// Shared implementation. Options: --set height=N, --set epoch=N,
/// --set kernel=coop|simple (default coop), --set group=N (threads per threadgroup, multiple of 32, max 256).
class EthashBase: MiningAlgorithm {
    class var chain: EthashChain { fatalError("subclasses set chain") }
    class var id: String { chain.id }
    class var coins: [String] { chain.coins }

    let gpu: GPU
    let cache: [UInt32]
    let datasetBytes: Int
    let dag: MTLBuffer
    let header: [UInt8]
    let headerBuffer: MTLBuffer
    let output: MTLBuffer
    let searchPipeline: MTLComputePipelineState
    let hashPipelines: [(name: String, pipeline: MTLComputePipelineState)]
    let cooperative: Bool
    let group: Int
    let setupSummary: String
    var defaultBatch: Int { 1 << 20 }

    required init(gpu: GPU, config: AlgoConfig) throws {
        let chain = Self.chain
        let height = config.quick ? 0 : (config.int("height") ?? chain.estimatedHeight)
        var epochs = chain.epochs(atHeight: height)
        if let epoch = config.int("epoch") { epochs = (epoch, chain.longEpochsFrom == nil ? epoch : 2 * epoch) }

        let t0 = now()
        let cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epochs.sizeEpoch),
                                              seed: EthashReference.seed(iterations: epochs.seedIterations))
        let cacheSeconds = now() - t0
        let datasetBytes = EthashReference.datasetSize(epoch: epochs.sizeEpoch)

        let library = try gpu.library(["ethash.metal", "ethash_coop.metal"], macros: config.options["par"].map { ["ETHASH_PAR": $0] } ?? [:])
        let (dag, dagSeconds) = try EthashDAG.build(gpu: gpu, cache: cache, datasetBytes: datasetBytes)

        cooperative = (config.options["kernel"] ?? "coop") != "simple"
        let group = config.int("group") ?? 128
        guard group % 32 == 0, group <= 256 else { throw MinerError("group must be a multiple of 32, at most 256") }
        self.group = group
        let header = randomBytes(32)
        self.gpu = gpu
        self.cache = cache
        self.datasetBytes = datasetBytes
        self.dag = dag
        self.header = header
        headerBuffer = try gpu.buffer((0 ..< 4).map { header.le64(at: 8 * $0) }, label: "ethash header")
        output = try gpu.buffer(MemoryLayout<UInt64>.stride * 64, label: "ethash hits")
        searchPipeline = try gpu.pipeline(library, cooperative ? "ethash_search_coop" : "ethash_search")
        hashPipelines = [("simple", try gpu.pipeline(library, "ethash_hash")),
                         ("coop", try gpu.pipeline(library, "ethash_hash_coop"))]
        setupSummary = "height \(height) · epoch \(epochs.sizeEpoch) · DAG \(formatBytes(datasetBytes)) built in \(fmt(dagSeconds, 1)) s"
            + " · cache \(formatBytes(cache.count * 4)) in \(fmt(cacheSeconds, 1)) s · \(cooperative ? "coop" : "simple") kernel, group \(group)"
    }

    func knownAnswerTests() throws -> [String] { try EthashReference.runVectors() }

    private func dagItem(_ index: UInt32) -> [UInt32] {
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: datasetBytes / 4)
        return Array(UnsafeBufferPointer(start: words + 16 * Int(index), count: 16))
    }

    /// Mix digest + final hash (64 bytes per nonce) from one of the hash kernels.
    private func gpuHashes(_ pipeline: MTLComputePipelineState, _ nonces: [UInt64]) throws -> [[UInt8]] {
        let nonceBuffer = try gpu.buffer(nonces, label: "nonces")
        let results = try gpu.buffer(nonces.count * 64, label: "ethash results")
        var pages = UInt32(datasetBytes / 128)
        try gpu.compute("ethash hash") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBytes(&pages, length: 4, index: 3)
            encoder.setBuffer(results, offset: 0, index: 4)
            gpu.dispatch(encoder, pipeline, threads: nonces.count, group: 32)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: nonces.count * 16)
        return (0 ..< nonces.count).map { n in
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
        // 2. Both hash kernels against CPU hashimoto over the same DAG (count kept a multiple of 32 for the coop kernel)
        let count = max(32, (samples + 31) / 32 * 32)
        let nonces = (0 ..< count).map { _ in UInt64.random(in: 0 ... UInt64.max) }
        let cpu = nonces.map { nonce in
            EthashReference.hashimoto(header: header, nonce: nonce, datasetBytes: datasetBytes) { dagItem($0) }
        }
        for (name, pipeline) in hashPipelines {
            for (n, gpuBytes) in try gpuHashes(pipeline, nonces).enumerated() where gpuBytes != cpu[n].mix + cpu[n].final {
                throw MinerError("\(name) kernel, nonce \(String(nonces[n], radix: 16)): GPU \(gpuBytes.hex) vs CPU \((cpu[n].mix + cpu[n].final).hex)")
            }
        }
        // 3. One hash entirely from the light cache, so the DAG isn't the only witness
        let light = cache.withUnsafeBufferPointer { c in
            EthashReference.hashimoto(header: header, nonce: nonces[0], datasetBytes: datasetBytes) {
                EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: cacheItems, index: $0)
            }
        }
        guard light.final == cpu[0].final else { throw MinerError("light-cache hash differs from the DAG hash") }
        return "\(itemCount) DAG items, \(count) hashes from each kernel (simple, coop) and 1 light-cache hash match the CPU reference"
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let threads = (count + group - 1) / group * group   // whole threadgroups, so 8-lane groups stay intact
        var start = startNonce
        var target: UInt64 = 0   // unreachable: the benchmark measures, it doesn't mine
        var pages = UInt32(datasetBytes / 128)
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("ethash search") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBytes(&target, length: 8, index: 3)
            encoder.setBytes(&pages, length: 4, index: 4)
            encoder.setBuffer(output, offset: 0, index: 5)
            gpu.dispatch(encoder, searchPipeline, threads: threads, group: group)
        }
        return Double(threads)
    }
}

/// Builds an Ethash DAG on the GPU from a light cache. Shared by the Ethash coins and KawPow.
enum EthashDAG {
    static func build(gpu: GPU, cache: [UInt32], datasetBytes: Int, parents: Int = 256) throws -> (buffer: MTLBuffer, seconds: Double) {
        let pipeline = try gpu.pipeline(try gpu.library(["ethash.metal"]), "ethash_dag")
        let dag = try gpu.buffer(datasetBytes, label: "ethash DAG")
        let cacheBuffer = try gpu.buffer(cache, label: "ethash cache")
        let start = now()
        let items = datasetBytes / 64
        var first = 0
        while first < items {   // chunks keep each command buffer well under the GPU watchdog
            let chunk = min(1 << 20, items - first)
            var cacheItems = UInt32(cache.count / 16)
            var firstItem = UInt32(first)
            var parentCount = UInt32(parents)
            try gpu.compute("ethash DAG") { encoder in
                encoder.setBuffer(cacheBuffer, offset: 0, index: 0)
                encoder.setBuffer(dag, offset: 0, index: 1)
                encoder.setBytes(&cacheItems, length: 4, index: 2)
                encoder.setBytes(&firstItem, length: 4, index: 3)
                encoder.setBytes(&parentCount, length: 4, index: 4)
                gpu.dispatch(encoder, pipeline, threads: chunk, group: 128)
            }
            first += chunk
        }
        return (dag, now() - start)
    }
}
