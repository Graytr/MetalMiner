import Foundation
import Metal

enum KawPowFamily {
    static let algorithms: [MiningAlgorithm.Type] = [KawPowRavencoin.self]

    /// Metal source for one period's random program: `kawpow_program(mix, cache, data)`, every register index
    /// and selector baked in as constants, exactly the sequence KawPowReference.hashMix runs per round.
    static func metalProgram(_ program: KawPowReference.Program) -> String {
        func merge(_ dst: Int, _ b: String, _ sel: UInt32) -> String {
            let a = "mix[\(dst)]"
            let x = (sel >> 16) % 31 + 1
            switch sel % 4 {
            case 0: return "\(a) = \(a) * 33u + (\(b));"
            case 1: return "\(a) = (\(a) ^ (\(b))) * 33u;"
            case 2: return "\(a) = rotate(\(a), \(x)u) ^ (\(b));"
            default: return "\(a) = rotate(\(a), \(32 - x)u) ^ (\(b));"
            }
        }
        func math(_ a: String, _ b: String, _ sel: UInt32) -> String {
            switch sel % 11 {
            case 0: return "\(a) + \(b)"
            case 1: return "\(a) * \(b)"
            case 2: return "mulhi(\(a), \(b))"
            case 3: return "min(\(a), \(b))"
            case 4: return "rotate(\(a), \(b) & 31u)"
            case 5: return "rotate(\(a), (32u - (\(b) & 31u)) & 31u)"
            case 6: return "\(a) & \(b)"
            case 7: return "\(a) | \(b)"
            case 8: return "\(a) ^ \(b)"
            case 9: return "clz(\(a)) + clz(\(b))"
            default: return "popcount(\(a)) + popcount(\(b))"
            }
        }
        var source = "static inline void kawpow_program(thread uint *mix, threadgroup const uint *cache, uint4 data) {\n"
        for op in program.ops {
            switch op {
            case let .cache(src, dst, sel):
                source += "    " + merge(dst, "cache[mix[\(src)] & 4095u]", sel) + "\n"
            case let .math(src1, src2, sel1, dst, sel2):
                source += "    " + merge(dst, math("mix[\(src1)]", "mix[\(src2)]", sel1), sel2) + "\n"
            }
        }
        for (i, word) in ["data.x", "data.y", "data.z", "data.w"].enumerated() {
            source += "    " + merge(program.dagDst[i], word, program.dagSel[i]) + "\n"
        }
        return source + "}\n"
    }
}

/// KawPow as Ravencoin defines it. Options: --set height=N (the program and DAG follow it), --set group=N (multiple of 32).
final class KawPowRavencoin: MiningAlgorithm {
    static let id = "kawpow"
    /// Quai merge-mines KawPow on Ravencoin "donor" headers (go-quai consensus/kawpow), so it is the same work.
    static let coins = ["RVN", "QUAI"]
    /// Height on 2026-11-19 21:00 UTC (Kryptex DAG calculator) and the one-minute block time.
    static let referenceHeight = 4_632_847
    static let blockSeconds = 60.0

    let gpu: GPU
    let height: Int
    let cache: [UInt32]
    let items: UInt32
    let dag: MTLBuffer
    let header: [UInt8]
    let headerBuffer: MTLBuffer
    let output: MTLBuffer
    let searchPipeline: MTLComputePipelineState
    let hashPipeline: MTLComputePipelineState
    let group: Int
    let setupSummary: String
    var defaultBatch: Int { 1 << 18 }

    init(gpu: GPU, config: AlgoConfig) throws {
        let estimated = Self.referenceHeight + max(0, Int((Date().timeIntervalSince1970 - EthashChain.referenceTime) / Self.blockSeconds))
        let height = config.quick ? 0 : (config.int("height") ?? estimated)
        let epoch = height / KawPowReference.epochLength
        let t0 = now()
        let cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epoch), seed: EthashReference.seed(iterations: epoch))
        let cacheSeconds = now() - t0
        let datasetBytes = EthashReference.datasetSize(epoch: epoch)
        let (dag, dagSeconds) = try EthashDAG.build(gpu: gpu, cache: cache, datasetBytes: datasetBytes,
                                                    parents: KawPowReference.datasetParents)

        let period = UInt64(height / KawPowReference.periodLength)
        let source = KawPowFamily.metalProgram(KawPowReference.program(period: period)) + "\n" + (try gpu.kernelSource("kawpow.metal"))
        let t1 = now()
        let library = try gpu.library(source: source, key: "kawpow period \(period)")
        let compileSeconds = now() - t1

        let group = config.int("group") ?? 256
        guard group % 32 == 0, group <= 1024 else { throw MinerError("group must be a multiple of 32") }
        let header = randomBytes(32)
        self.gpu = gpu
        self.height = height
        self.cache = cache
        self.items = UInt32(datasetBytes / 128 / 2)
        self.dag = dag
        self.header = header
        self.group = group
        headerBuffer = try gpu.buffer((0 ..< 8).map { header.le32(at: 4 * $0) }, label: "kawpow header")
        output = try gpu.buffer(MemoryLayout<UInt64>.stride * 64, label: "kawpow hits")
        searchPipeline = try gpu.pipeline(library, "kawpow_search")
        hashPipeline = try gpu.pipeline(library, "kawpow_hash")
        setupSummary = "height \(height) · epoch \(epoch) · period \(period) · DAG \(formatBytes(datasetBytes)) built in \(fmt(dagSeconds, 1)) s"
            + " · cache in \(fmt(cacheSeconds, 1)) s · program compiled in \(fmt(compileSeconds, 2)) s · group \(group)"
    }

    func knownAnswerTests() throws -> [String] { try KawPowReference.runVectors() }

    /// 2048-bit DAG item i (64 words) read back from the GPU DAG.
    private func dagItem(_ index: UInt32) -> [UInt32] {
        let words = dag.contents().bindMemory(to: UInt32.self, capacity: dag.length / 4)
        return Array(UnsafeBufferPointer(start: words + 64 * Int(index), count: 64))
    }

    func crossCheck(samples: Int) throws -> String {
        let count = max(32, (samples + 31) / 32 * 32)
        let nonces = (0 ..< count).map { _ in UInt64.random(in: 0 ... UInt64.max) }
        let nonceBuffer = try gpu.buffer(nonces, label: "nonces")
        let results = try gpu.buffer(count * 64, label: "kawpow results")
        var itemCount = items
        try gpu.compute("kawpow hash") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBuffer(nonceBuffer, offset: 0, index: 2)
            encoder.setBytes(&itemCount, length: 4, index: 3)
            encoder.setBuffer(results, offset: 0, index: 4)
            gpu.dispatch(encoder, hashPipeline, threads: count, group: 32)
        }
        let words = results.contents().bindMemory(to: UInt32.self, capacity: count * 16)
        let dagWords = dag.contents().bindMemory(to: UInt32.self, capacity: 4096)
        let l1 = Array(UnsafeBufferPointer(start: dagWords, count: KawPowReference.cacheWords))
        var first: (mix: [UInt8], final: [UInt8])?
        for (n, nonce) in nonces.enumerated() {
            let cpu = KawPowReference.hash(header: header, nonce: nonce, blockNumber: height, items: items, l1: l1, item: dagItem)
            var gpuBytes: [UInt8] = []
            for w in 0 ..< 16 { gpuBytes.appendLE(words[16 * n + w]) }
            guard gpuBytes == cpu.mix + cpu.final else {
                throw MinerError("nonce \(String(nonce, radix: 16)): GPU \(gpuBytes.hex) vs CPU \((cpu.mix + cpu.final).hex)")
            }
            if n == 0 { first = cpu }
        }
        // One hash from the light cache alone, so the GPU DAG isn't the only witness.
        let lightL1 = cache.withUnsafeBufferPointer { c in
            (0 ..< UInt32(KawPowReference.cacheWords / 16)).flatMap {
                EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: $0, parents: KawPowReference.datasetParents)
            }
        }
        let light = KawPowReference.hash(header: header, nonce: nonces[0], blockNumber: height, items: items, l1: lightL1) { index in
            cache.withUnsafeBufferPointer { c in
                (0 ..< 4).flatMap { EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: 4 * index + UInt32($0), parents: KawPowReference.datasetParents) }
            }
        }
        guard let firstCPU = first, light.final == firstCPU.final else { throw MinerError("light-cache hash differs from the DAG hash") }
        return "\(count) GPU hashes and 1 light-cache hash match the CPU reference"
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let threads = (count + group - 1) / group * group   // whole threadgroups keep 16-lane groups intact
        var start = startNonce
        var target: UInt64 = 0
        var itemCount = items
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        try gpu.compute("kawpow search") { encoder in
            encoder.setBuffer(dag, offset: 0, index: 0)
            encoder.setBuffer(headerBuffer, offset: 0, index: 1)
            encoder.setBytes(&start, length: 8, index: 2)
            encoder.setBytes(&target, length: 8, index: 3)
            encoder.setBytes(&itemCount, length: 4, index: 4)
            encoder.setBuffer(output, offset: 0, index: 5)
            gpu.dispatch(encoder, searchPipeline, threads: threads, group: group)
        }
        return Double(threads)
    }
}
