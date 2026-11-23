import Foundation
import Metal

enum Poseidon2Family {
    static let algorithms: [MiningAlgorithm.Type] = [Poseidon2Quantus.self]
    static let poolMiners: [PoolMiner.Type] = [Poseidon2PoolMiner.self]
}

/// Quantus (QTC): Poseidon2-Goldilocks over the 32-byte pre-seal header hash and a 64-byte nonce.
/// A job fixes the header and the nonce's first 56 bytes; the GPU walks the last 8 bytes as a big-endian
/// 64-bit counter, so each nonce costs 2 permutations (3 in the ~2^-64 case where the top 64 hash bits
/// don't settle the comparison), plus 2 per job on the CPU.
/// Options: --set height=N (recorded only), --set difficulty=N (network difficulty in the summary),
/// --set group=N (threads per threadgroup), --set squeeze=always (finish every hash, no early reject),
/// --set m.NAME=VALUE (Metal macro, for the tuning switches in Kernels/poseidon2.metal).
final class Poseidon2Quantus: MiningAlgorithm {
    typealias R = Poseidon2Reference
    static let id = "poseidon2"
    static let coins = ["QTC"]

    /// Mainnet on 2026-11-19 at about 21:00 UTC: height 438,893 (explorer.quantus.com); Kryptex Pool showed
    /// network difficulty 379.16 T and a static share difficulty of 18,253,611,008.
    static let referenceHeight = 438_893
    static let referenceDifficulty: UInt64 = 379_160_000_000_000
    static let shareDifficulty: UInt64 = 18_253_611_008
    /// POSEIDON2_MAX_HITS in Kernels/poseidon2.metal; each hit is a counter and 8 hash words.
    static let maxHits = 64

    let gpu: GPU
    let searchPipeline: MTLComputePipelineState
    let walkPipeline: MTLComputePipelineState
    let hashPipeline: MTLComputePipelineState
    let output: MTLBuffer
    let header: [UInt8]
    let noncePrefix: [UInt8]
    let jobState: [UInt64]
    let group: Int
    let setupSummary: String
    var defaultBatch: Int { 1 << 22 }

    init(gpu: GPU, config: AlgoConfig) throws {
        let height = config.int("height") ?? Self.referenceHeight
        let difficulty = config.options["difficulty"].flatMap { UInt64($0) } ?? Self.referenceDifficulty
        guard difficulty > 0 else { throw MinerError("difficulty must be a positive integer below 2^64") }
        let group = config.int("group") ?? 256
        guard group > 0, group % 32 == 0, group <= 1024 else { throw MinerError("group must be a multiple of 32, at most 1024") }
        var macros: [String: String] = [:]
        if config.options["squeeze"] == "always" { macros["POSEIDON2_ALWAYS_SQUEEZE"] = "1" }
        for (key, value) in config.options where key.hasPrefix("m.") { macros[String(key.dropFirst(2))] = value }
        let library = try gpu.library(["poseidon2.metal"], macros: macros)
        self.gpu = gpu
        searchPipeline = try gpu.pipeline(library, "poseidon2_search")
        walkPipeline = try gpu.pipeline(library, "poseidon2_walk")
        hashPipeline = try gpu.pipeline(library, "poseidon2_hash")
        self.group = min(group, searchPipeline.maxTotalThreadsPerThreadgroup)
        output = try gpu.buffer(8 + Self.maxHits * 72, label: "poseidon2 hits")
        header = randomBytes(32)
        noncePrefix = randomBytes(56)
        jobState = Self.jobState(header: header, noncePrefix: noncePrefix)
        let blockTarget = R.target(difficulty: difficulty)
        setupSummary = "height \(height) · difficulty \(difficulty) (target \(String(format: "%016llx", blockTarget[0]))…)"
            + " · share difficulty \(Self.shareDifficulty) · Goldilocks Poseidon2 t=12, 2 permutations per nonce"
            + " · group \(self.group) (pipeline max \(searchPipeline.maxTotalThreadsPerThreadgroup))"
            + (macros.isEmpty ? "" : " · " + macros.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))
            + (config.quick ? " · quick changes nothing (no size parameters)" : "")
    }

    /// The sponge after the header and nonce bytes 0..31, plus nonce bytes 32..55 as six more felts.
    static func jobState(header: [UInt8], noncePrefix: [UInt8]) -> [UInt64] {
        var s = R.midstate(header: header, nonceHigh: Array(noncePrefix[0 ..< 32]))
        for i in 0 ..< 6 { s[i] = R.add(s[i], UInt64(noncePrefix.le32(at: 32 + 4 * i))) }
        return s
    }

    /// The 64-byte nonce for a counter: the job's 56-byte prefix, then the counter big-endian.
    func nonce(_ counter: UInt64) -> [UInt8] {
        var bytes = noncePrefix
        bytes.appendLE(counter.byteSwapped)
        return bytes
    }

    func knownAnswerTests() throws -> [String] { try Poseidon2Vectors.run() }

    /// Poseidon2Job in the kernel: state[12], target[8], start, count (low half of the last word).
    private func params(state: [UInt64], start: UInt64, count: Int, target: [UInt64]) -> [UInt64] {
        state + target + [start, UInt64(count)]
    }

    private func setParams(_ encoder: MTLComputeCommandEncoder, _ params: [UInt64]) {
        params.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: $0.count, index: 0) }
    }

    /// One search dispatch over a job state (this instance's benchmark job unless `state` is given, as pool jobs do):
    /// the number of hits and the first maxHits of them (counter, hash words).
    func search(state: [UInt64]? = nil, start: UInt64, count: Int, target: [UInt64]) throws -> (total: Int, hits: [(counter: UInt64, hash: [UInt64])]) {
        output.contents().storeBytes(of: UInt32(0), as: UInt32.self)
        let p = params(state: state ?? jobState, start: start, count: count, target: target)
        try gpu.compute("poseidon2 search") { encoder in
            setParams(encoder, p)
            encoder.setBuffer(output, offset: 0, index: 1)
            gpu.dispatch(encoder, searchPipeline, threads: count, group: group)
        }
        let total = Int(output.contents().load(as: UInt32.self))
        let words = output.contents().advanced(by: 8).bindMemory(to: UInt64.self, capacity: Self.maxHits * 9)
        let hits = (0 ..< min(total, Self.maxHits)).map { h in (counter: words[9 * h], hash: (1 ... 8).map { words[9 * h + $0] }) }
        return (total, hits)
    }

    /// The search kernel's per-nonce path for `count` counters from `start`, with every full hash.
    private func walk(start: UInt64, count: Int) throws -> [[UInt64]] {
        let out = try gpu.buffer(count * 64, label: "poseidon2 walk")
        let p = params(state: jobState, start: start, count: count, target: [UInt64](repeating: 0, count: 8))
        try gpu.compute("poseidon2 walk") { encoder in
            setParams(encoder, p)
            encoder.setBuffer(out, offset: 0, index: 1)
            gpu.dispatch(encoder, walkPipeline, threads: count, group: group)
        }
        let words = out.contents().bindMemory(to: UInt64.self, capacity: count * 8)
        return (0 ..< count).map { n in (0 ..< 8).map { words[8 * n + $0] } }
    }

    /// The whole sponge on the GPU over arbitrary 96-byte inputs (header || nonce).
    private func hashes(_ inputs: [[UInt8]]) throws -> [[UInt64]] {
        let flat = inputs.flatMap { $0 }
        let inBuffer = try gpu.buffer(flat, label: "poseidon2 inputs")
        let out = try gpu.buffer(inputs.count * 64, label: "poseidon2 hashes")
        var n = UInt32(inputs.count)
        try gpu.compute("poseidon2 hash") { encoder in
            encoder.setBuffer(inBuffer, offset: 0, index: 0)
            encoder.setBuffer(out, offset: 0, index: 1)
            encoder.setBytes(&n, length: 4, index: 2)
            gpu.dispatch(encoder, hashPipeline, threads: inputs.count, group: 32)
        }
        let words = out.contents().bindMemory(to: UInt64.self, capacity: inputs.count * 8)
        return (0 ..< inputs.count).map { k in (0 ..< 8).map { words[8 * k + $0] } }
    }

    func crossCheck(samples: Int) throws -> String {
        let n = max(samples, 8)
        // 1. The plain sponge kernel: the official golden vectors, then random headers and full random nonces.
        var inputs: [[UInt8]] = []
        var want: [[UInt64]] = []
        for v in Poseidon2Vectors.nonceHash {
            inputs.append(try Poseidon2Vectors.bytes(v.header) + Poseidon2Vectors.bytes(v.nonce))
            want.append(R.words(try Poseidon2Vectors.bytes(v.hash)))
        }
        for _ in 0 ..< n {
            let h = randomBytes(32), nonce = randomBytes(64)
            inputs.append(h + nonce)
            want.append(R.words(R.nonceHash(header: h, nonce: nonce)))
        }
        for (k, got) in try hashes(inputs).enumerated() where got != want[k] {
            throw MinerError("hash kernel, input \(inputs[k].hex): GPU \(R.hex(got)) vs CPU \(R.hex(want[k]))")
        }

        // 2. The mining path the benchmark runs, over consecutive counters carrying from bit 31 into bit 32.
        let start = UInt64.random(in: 0 ..< (1 << 31)) << 32 | (0x1_0000_0000 - UInt64(n / 2))
        for (k, got) in try walk(start: start, count: n).enumerated() {
            let counter = start &+ UInt64(k)
            let cpu = R.words(R.nonceHash(header: header, nonce: nonce(counter)))
            guard got == cpu else {
                throw MinerError("mining path, counter \(String(counter, radix: 16)): GPU \(R.hex(got)) vs CPU \(R.hex(cpu))")
            }
        }

        // 3. The search kernel's comparison at the target boundaries (hash < target, strict).
        let m = Self.maxHits
        let base = UInt64.random(in: 0 ..< (1 << 62))
        let cpu = (0 ..< m).map { R.words(R.nonceHash(header: header, nonce: nonce(base &+ UInt64($0)))) }
        var best = 0
        for k in 1 ..< m where R.less(cpu[k], cpu[best]) { best = k }
        let none = try search(start: base, count: m, target: cpu[best])
        guard none.total == 0 else { throw MinerError("search: \(none.total) hits with target = the smallest hash") }
        let one = try search(start: base, count: m, target: R.plusOne(cpu[best]))
        guard one.total == 1, one.hits[0].counter == base &+ UInt64(best), one.hits[0].hash == cpu[best] else {
            throw MinerError("search: target = smallest hash + 1 should hit only counter +\(best), got \(one.total) hits")
        }
        let all = try search(start: base, count: m, target: [UInt64](repeating: .max, count: 8))
        guard all.total == m else { throw MinerError("search: difficulty 1 should hit all \(m) nonces, got \(all.total)") }
        for hit in all.hits {
            let k = hit.counter &- base
            guard k < UInt64(m), hit.hash == cpu[Int(k)] else { throw MinerError("search: hit at counter \(hit.counter) has the wrong hash") }
        }
        return "\(Poseidon2Vectors.nonceHash.count) golden + \(n) random hashes (sponge kernel), \(n) mining-path hashes across a 32-bit carry,"
            + " search hits at target = min, min+1, MAX over \(m) nonces: all 512 bits match the CPU"
    }

    func runBatch(startNonce: UInt64, count: Int) throws -> Double {
        let unreachable = [UInt64](repeating: 0, count: 8)   // hash < 0 never holds: the benchmark measures, it doesn't mine
        var done = 0
        while done < count {
            let start = startNonce &+ UInt64(done)
            let untilWrap = start == 0 ? Int.max : Int(min(UInt64(Int.max), 0 &- start))   // the counter must not wrap mid-dispatch
            let n = min(count - done, untilWrap, Int(UInt32.max))
            let result = try search(start: start, count: n, target: unreachable)
            guard result.total == 0 else { throw MinerError("search reported \(result.total) hits against an unreachable target") }
            done += n
        }
        return Double(count)
    }
}
