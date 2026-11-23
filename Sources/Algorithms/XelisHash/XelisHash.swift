import Foundation
import Metal

enum XelisHashFamily {
    static let algorithms: [MiningAlgorithm.Type] = [XelisHashV3.self]
    static let poolMiners: [PoolMiner.Type] = [XelisHashPoolMiner.self]
}

/// XELIS (XEL): XelisHash v3, the mainnet proof of work since height 3,282,150 (block version V3).
/// One GPU thread per nonce, each with its own 531 KiB scratchpad in device memory.
/// Options: --set height=N (must be >= 3,282,150) · --set slots=N (scratchpads, = nonces per dispatch;
/// default 2048 = 1.04 GiB) · --set group=N (threads per threadgroup, multiple of 32, default 64)
/// · --set kernel=pipelined|simple · --set trace=1 (print each dispatch's GPU time)
/// · --set check=N (nonces in the GPU/CPU cross-check) · --set m.NAME=VALUE (Metal macro, e.g. m.XH_FAST_DIV=0).
final class XelisHashV3: MiningAlgorithm {
    static let id = "xelishash"
    static let coins = ["XEL"]

    /// xelis_daemon/src/config.rs: BlockVersion V3 ("Smart Contracts, xelis-hash v3, 5s block time").
    static let v3Height = 3_282_150
    /// Mainnet height on 2026-11-19 21:02 UTC (explorer.xelis.io), block version V7, still v3.
    static let referenceHeight = 8_682_175

    let gpu: GPU
    let searchPipeline: MTLComputePipelineState
    let primitivePipeline: MTLComputePipelineState
    let scratch: MTLBuffer
    let output: MTLBuffer
    let hashes: MTLBuffer
    let slots: Int
    let group: Int
    let trace: Bool
    let checkSamples: Int
    let work: [UInt8]
    let setupSummary: String
    var defaultBatch: Int { slots }

    init(gpu: GPU, config: AlgoConfig) throws {
        let height = config.int("height") ?? Self.referenceHeight
        guard height >= Self.v3Height else {
            throw MinerError("xelishash: height \(height) predates xelis-hash v3 (mainnet height \(Self.v3Height)); only v3 is ported")
        }
        let requested = config.int("slots") ?? (config.quick ? 256 : 2048)
        let slots = max(32, (requested + 31) / 32 * 32)
        let group = config.int("group") ?? 64
        guard group % 32 == 0, group >= 32, group <= 1024 else { throw MinerError("group must be a multiple of 32, 32...1024") }
        let kernel = config.options["kernel"] ?? "pipelined"
        guard ["simple", "pipelined"].contains(kernel) else { throw MinerError("kernel must be pipelined or simple") }
        var macros: [String: String] = [:]
        for (key, value) in config.options where key.hasPrefix("m.") { macros[String(key.dropFirst(2))] = value }

        let library = try gpu.library(["xelishash.metal"], macros: macros)
        let search = try gpu.pipeline(library, "xelishash_search_\(kernel)")
        self.gpu = gpu
        self.slots = slots
        self.group = group
        trace = config.options["trace"] != nil
        checkSamples = config.int("check") ?? 0
        searchPipeline = search
        primitivePipeline = try gpu.pipeline(library, "xelishash_primitives")
        scratch = try gpu.privateBuffer(slots * XelisHashReference.V3.memoryBytes, label: "xelishash scratchpads")
        output = try gpu.buffer(8 + 8 * 62, label: "xelishash hits")
        hashes = try gpu.buffer(slots * 32, label: "xelishash hashes")
        work = randomBytes(112)
        let macroNote = macros.isEmpty ? "" : " · " + macros.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
        setupSummary = "xelis-hash v3 at height \(height) · \(kernel) kernel · \(slots) scratchpads x 531 KiB = "
            + "\(formatBytes(slots * XelisHashReference.V3.memoryBytes)) · group \(group)\(macroNote)"
    }

    func knownAnswerTests() throws -> [String] { try XelisHashReference.runVectors() }

    // MARK: - GPU plumbing

    /// XhParams in xelishash.metal: work[28] u32, target[8] big-endian u32, startNonce, count, flags (160 bytes).
    func params(work: [UInt8], target: [UInt8], start: UInt64, count: Int, storeHashes: Bool) -> [UInt8] {
        var p = work
        for k in 0 ..< 8 {
            p.appendLE((0 ..< 4).reduce(UInt32(0)) { $0 << 8 | UInt32(target[4 * k + $1]) })
        }
        p.appendLE(start)
        p.appendLE(UInt32(count))
        p.appendLE(UInt32(storeHashes ? 1 : 0))
        return p
    }

    func encodeSearch(_ encoder: MTLComputeCommandEncoder, _ params: [UInt8], count: Int) {
        params.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: $0.count, index: 0) }
        encoder.setBuffer(scratch, offset: 0, index: 1)
        encoder.setBuffer(output, offset: 0, index: 2)
        encoder.setBuffer(hashes, offset: 0, index: 3)
        gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
    }

    func resetHits() {
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
    }

    func hits() -> [UInt64] {
        let count = min(Int(output.contents().load(as: UInt32.self)), 62)
        return (0 ..< count).map { output.contents().load(fromByteOffset: 8 + 8 * $0, as: UInt64.self) }
    }

    /// One dispatch of `count` <= slots nonces, returning every hash and the hit list.
    func search(work: [UInt8], target: [UInt8], start: UInt64, count: Int) throws -> (hashes: [[UInt8]], hits: [UInt64]) {
        precondition(count <= slots)
        resetHits()
        let p = params(work: work, target: target, start: start, count: count, storeHashes: true)
        try gpu.compute("xelishash check") { encoder in encodeSearch(encoder, p, count: count) }
        let words = hashes.contents().bindMemory(to: UInt32.self, capacity: count * 8)
        let list = (0 ..< count).map { k -> [UInt8] in
            var bytes: [UInt8] = []
            for w in 0 ..< 8 { bytes.appendLE(words[8 * k + w]) }
            return bytes
        }
        return (list, hits())
    }

    // MARK: - Mining batch

    /// Mines whole dispatches of `slots` nonces: `count` is rounded up (as Ethash rounds up to whole
    /// threadgroups) because one hash is ~0.3 s of serial latency, so a dispatch takes about that long
    /// whatever its size and smaller batches leave the GPU idle. Returns the hashes actually computed.
    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let target = [UInt8](repeating: 0, count: 32)   // unreachable: hash <= 0
        let total = max(1, (count + slots - 1) / slots) * slots
        resetHits()
        var done = 0
        while done < total {   // one command buffer per dispatch keeps each well under the GPU watchdog
            let p = params(work: work, target: target, start: startNonce &+ UInt64(done), count: slots, storeHashes: false)
            let seconds = try gpu.compute("xelishash search") { encoder in encodeSearch(encoder, p, count: slots) }
            if trace { print("   trace   \(slots) nonces in \(fmt(seconds * 1000, 1)) ms GPU = \(fmt(Double(slots) / seconds, 0)) H/s") }
            done += slots
        }
        return Double(total)
    }
}
