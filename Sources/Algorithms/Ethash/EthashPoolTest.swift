import Foundation

/// The pool side of the Ethash selfTests. `stratum` answers like NiceHash's EthereumStratum/1.0.0 spec and Kryptex (2-byte
/// extranonce, set_difficulty, 4-field notify); `proxy` refuses mining.subscribe and serves ETHPROXY; `silentProxy` ignores
/// mining.subscribe (as some pools do) and serves ETHPROXY. Every share is checked with EthashReference over the mock's
/// own light caches: job, nonce format and extranonce, mix digest (ETHPROXY sends it), full 256-bit target, duplicates.
final class EthashMockPool {
    enum Mode { case stratum, proxy, silentProxy }

    struct Job {
        let id: String
        let header: [UInt8]
        let seed: [UInt8]
        let height: Int
        let datasetBytes: Int
        let cache: [UInt32]
        let difficulty: Double
        let target: [UInt8]
    }

    static let extranonce = "c3d5"   // 2 bytes, like the extranonces Kryptex's Ethash pools sent in the handshake
    let mode: Mode
    private let lock = NSLock()
    private var jobs: [String: Job] = [:]
    private var current: Job?
    private var seen = Set<String>()
    private var acceptedByJob: [String: Int] = [:]
    private var rejected: [String] = []
    private var loginCount = 0
    private var subscribeCount = 0

    init(mode: Mode) { self.mode = mode }

    func accepted(_ job: String) -> Int { lock.withLock { acceptedByJob[job] ?? 0 } }
    var acceptedTotal: Int { lock.withLock { acceptedByJob.values.reduce(0, +) } }
    var rejections: [String] { lock.withLock { rejected } }
    var logins: Int { lock.withLock { loginCount } }
    var subscribes: Int { lock.withLock { subscribeCount } }

    /// A job for `chain` at `height`: the seed, cache and DAG size come from the chain's height rules, independently of
    /// how the miner reads the seed hash.
    static func job(_ id: String, header: String, height: Int, chain: EthashChain, difficulty: Double,
                    caches: inout [Int: [UInt32]]) -> Job {
        let epochs = chain.epochs(atHeight: height)
        let seed = EthashReference.seed(iterations: epochs.seedIterations)
        if caches[epochs.sizeEpoch] == nil {
            caches[epochs.sizeEpoch] = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epochs.sizeEpoch), seed: seed)
        }
        return Job(id: id, header: [UInt8](hex: header)!, seed: seed, height: height,
                   datasetBytes: EthashReference.datasetSize(epoch: epochs.sizeEpoch), cache: caches[epochs.sizeEpoch]!,
                   difficulty: difficulty, target: EthashTarget.fromDifficulty(difficulty, diff1: EthashTarget.stratumDiff1))
    }

    /// Makes `job` current; pushes it now when `mock` is given, otherwise it goes out after the next login.
    func send(_ job: Job, to mock: MockPool?) {
        let previous: Job? = lock.withLock {
            defer {
                jobs[job.id] = job
                current = job
            }
            return current
        }
        guard let mock else { return }
        for message in announce(job, after: previous) { mock.push(message) }
    }

    private func announce(_ job: Job, after previous: Job?) -> [[String: Any]] {
        switch mode {
        case .stratum:
            var messages: [[String: Any]] = []
            if previous?.difficulty != job.difficulty {
                messages.append(["id": NSNull(), "method": "mining.set_difficulty", "params": [job.difficulty]])
            }
            messages.append(["id": NSNull(), "method": "mining.notify", "params": [job.id, job.seed.hex, job.header.hex, true] as [Any]])
            return messages
        case .proxy, .silentProxy:
            return [["id": 0, "jsonrpc": "2.0", "result": work(job)]]
        }
    }

    /// ETHPROXY work: header, seed, target, and the height as hex (as ethermine-style proxies add it).
    private func work(_ job: Job) -> [Any] {
        ["0x" + job.header.hex, "0x" + job.seed.hex, "0x" + job.target.hex, String(format: "0x%x", job.height)]
    }

    func respond(_ message: [String: Any], _ mock: MockPool) -> [[String: Any]] {
        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [Any] ?? []
        func ok(_ result: Any) -> [String: Any] { ["id": id, "result": result, "error": NSNull()] }
        func refuse(_ code: Int, _ text: String) -> [String: Any] { ["id": id, "result": NSNull(), "error": [code, text, NSNull()] as [Any]] }
        switch message["method"] as? String {
        case "mining.subscribe"?:
            lock.withLock { subscribeCount += 1 }
            switch mode {
            case .stratum:
                let result: [Any] = [["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f", "EthereumStratum/1.0.0"], Self.extranonce]
                return [ok(result)]
            case .proxy: return [refuse(20, "unsupported method")]
            case .silentProxy: return []
            }
        case "mining.authorize"? where mode == .stratum, "eth_submitLogin"? where mode != .stratum:
            let job: Job? = lock.withLock {
                loginCount += 1
                return current
            }
            guard params.first as? String == EthashPoolTestRun.login else { return [refuse(24, "unauthorized worker")] }
            if mode == .stratum, let job { return [ok(true)] + announce(job, after: nil) }
            return [ok(true)]
        case "eth_getWork"? where mode != .stratum:
            guard let job = lock.withLock({ current }) else { return [refuse(0, "no work yet")] }
            return [["id": id, "jsonrpc": "2.0", "result": work(job)]]
        case "mining.submit"? where mode == .stratum, "eth_submitWork"? where mode != .stratum:
            let problem = mode == .stratum ? checkStratum(params) : checkProxy(params)
            if let problem {
                lock.withLock { rejected.append(problem) }
                return [refuse(20, problem)]
            }
            return [ok(true)]
        default:
            return [refuse(20, "unknown method")]
        }
    }


    /// mining.submit [login, job id, miner nonce]: the nonce is the extranonce followed by these 12 hex digits.
    private func checkStratum(_ params: [Any]) -> String? {
        guard params.count == 3, params[0] as? String == EthashPoolTestRun.login, let jobID = params[1] as? String,
              let minerNonce = params[2] as? String else { return "malformed submit" }
        guard let job = lock.withLock({ jobs[jobID] }) else { return "unknown job" }
        guard minerNonce.count == 16 - Self.extranonce.count, let nonce = UInt64(Self.extranonce + minerNonce, radix: 16) else {
            return "bad miner nonce \(minerNonce)"
        }
        return verify(job, nonce: nonce, mix: nil)
    }

    /// eth_submitWork [0x nonce, 0x header hash, 0x mix digest]: the job is the one with that header.
    private func checkProxy(_ params: [Any]) -> String? {
        guard params.count == 3, let nonceText = params[0] as? String, let headerText = params[1] as? String,
              let mixText = params[2] as? String, nonceText.count == 18, nonceText.hasPrefix("0x"),
              let nonce = UInt64(nonceText.dropFirst(2), radix: 16), mixText.hasPrefix("0x") else { return "malformed submit" }
        guard let job = lock.withLock({ jobs.values.first { "0x" + $0.header.hex == headerText } }) else { return "unknown header" }
        return verify(job, nonce: nonce, mix: String(mixText.dropFirst(2)))
    }

    private func verify(_ job: Job, nonce: UInt64, mix: String?) -> String? {
        guard lock.withLock({ seen.insert(job.id + String(nonce)).inserted }) else { return "duplicate share" }
        let result = job.cache.withUnsafeBufferPointer { c in
            EthashReference.hashimoto(header: job.header, nonce: nonce, datasetBytes: job.datasetBytes) { index in
                EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: index)
            }
        }
        if let mix, mix != result.mix.hex { return "bad mix hash" }
        guard EthashTarget.meets(result.final, job.target) else { return "low difficulty share" }
        lock.withLock { acceptedByJob[job.id, default: 0] += 1 }
        return nil
    }
}

/// The Ethash pool miners' offline round trips. ETC talks EthereumStratum/1.0.0 to its mock, ETHW meets a pool that
/// refuses it and falls back to ETHPROXY, OCTA one that ignores it (5 s timeout) and falls back too. Jobs use
/// chfast/ethash vector header hashes; job 3 moves to another epoch with a 4x higher difficulty: ETC's first
/// 60,000-block epoch (block 11,700,000: epoch 195, seed of 390 rounds), and for ETHW and OCTA block 2,683,077 (epoch 89).
enum EthashPoolTest {
    static let headers = [
        "2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce",   // block 0
        "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",   // block 2
        "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512",   // block 2683077
    ]

    static func run(_ type: EthashPoolMinerBase.Type, gpu: GPU) throws -> [String] {
        let started = now()
        let chain = type.chain
        let mode: EthashMockPool.Mode = chain.id == EthashChain.ethereumClassic.id ? .stratum
            : chain.id == EthashChain.ethereumPoW.id ? .proxy : .silentProxy
        var lines: [String] = []
        if chain.id == EthashChain.ethereumPoW.id { lines.append(try niceHashExample()) }

        let pool = EthashMockPool(mode: mode)
        let mock = try MockPool { message, mock in pool.respond(message, mock) }
        defer { mock.close() }
        var caches: [Int: [UInt32]] = [:]
        let easy = 1.0 / 256, hard = 4.0 / 256   // about 16.8 M and 67 M hashes per share
        let laterHeight = chain.longEpochsFrom ?? 2_683_077
        let job1 = EthashMockPool.job("1", header: headers[0], height: 0, chain: chain, difficulty: easy, caches: &caches)
        let job2 = EthashMockPool.job("2", header: headers[1], height: 2, chain: chain, difficulty: easy, caches: &caches)
        let job3 = EthashMockPool.job("3", header: headers[2], height: laterHeight, chain: chain, difficulty: hard, caches: &caches)
        let job4 = EthashMockPool.job("4", header: headers[2], height: laterHeight, chain: chain, difficulty: hard, caches: &caches)
        switch mode {
        case .stratum: lines.append("mock pool: EthereumStratum/1.0.0 (extranonce \(EthashMockPool.extranonce)); shares checked by EthashReference over its own light caches")
        case .proxy: lines.append("mock pool: refuses mining.subscribe, serves ETHPROXY; shares checked by EthashReference over its own light caches")
        case .silentProxy: lines.append("mock pool: ignores mining.subscribe, serves ETHPROXY; shares checked by EthashReference over its own light caches")
        }

        let harness = EthashPoolTestRun()
        let miner = try type.init(gpu: gpu, endpoint: mock.endpoint, login: EthashPoolTestRun.login, events: harness.events)
        miner.session.rateInterval = 2

        pool.send(job1, to: nil)
        harness.start(miner)
        defer { _ = try? harness.stop() }

        try harness.waitFor("2 accepted shares on job 1", timeout: 90) { pool.accepted("1") >= 2 }
        let dialect = harness.lines.first { $0.hasPrefix("logged in") } ?? "(no login line)"
        let built = harness.lines.first { $0.contains("DAG for epoch 0") } ?? "(no DAG line)"
        lines.append("job 1 (header of block 0, \(formatRate(EthashTarget.work(job1.target), "")) hashes per share): "
                     + "\(dialect) after \(pool.subscribes) subscribe(s); \(pool.accepted("1")) shares accepted; \(built)")

        pool.send(job2, to: mock)
        try harness.waitFor("2 accepted shares on job 2", timeout: 60) { pool.accepted("2") >= 2 }
        lines.append("job 2 (header of block 2, same epoch): \(pool.accepted("2")) shares accepted")

        miner.session.corruptNextShare()
        try harness.waitFor("the corrupted share's rejection", timeout: 60) {
            !pool.rejections.isEmpty && harness.shares.contains { !$0.accepted }
        }
        let refusal = harness.shares.first { !$0.accepted }?.note ?? ""
        lines.append("corrupted share (nonce changed after the CPU check): refused by the pool (\(pool.rejections[0])) and reported as \"\(refusal)\"")

        pool.send(job3, to: mock)
        try harness.waitFor("2 accepted shares on job 3", timeout: 120) { pool.accepted("3") >= 2 }
        let expected = chain.epochs(atHeight: laterHeight)
        let rebuilt = harness.lines.first { $0.contains("DAG for epoch \(expected.sizeEpoch)") } ?? "(no DAG line for epoch \(expected.sizeEpoch))"
        lines.append("difficulty x4 + job 3 (block \(laterHeight)'s seed): \(pool.accepted("3")) shares accepted at the new target; \(rebuilt)")

        if mode == .stratum {
            pool.send(job4, to: nil)   // goes out after the miner logs in again
            mock.push(["id": NSNull(), "method": "client.reconnect", "params": [] as [Any]])
            try harness.waitFor("a share after client.reconnect", timeout: 60) { pool.logins >= 2 && pool.accepted("4") >= 1 }
            lines.append("client.reconnect: logged in again (\(pool.logins) logins), job 4: \(pool.accepted("4")) share accepted")
        }

        let reports = harness.rates.count
        try harness.waitFor("2 more rate reports", timeout: 30) { harness.rates.count >= reports + 2 }
        let steady = harness.rates.last ?? 0
        try harness.stop()

        let shares = harness.shares
        let accepted = shares.filter { $0.accepted }
        let refused = shares.filter { !$0.accepted }
        guard accepted.count == pool.acceptedTotal, refused.count == 1, pool.rejections.count == 1 else {
            throw MinerError("reported \(accepted.count) accepted / \(refused.count) refused, the pool counted \(pool.acceptedTotal) / \(pool.rejections.count): \(pool.rejections)")
        }
        let easyWork = EthashTarget.work(job1.target), hardWork = EthashTarget.work(job3.target)
        let atEasy = accepted.filter { abs($0.work - easyWork) < easyWork * 1e-9 }.count
        let atHard = accepted.filter { abs($0.work - hardWork) < hardWork * 1e-9 }.count
        guard atEasy == pool.accepted("1") + pool.accepted("2"), atHard == pool.accepted("3") + pool.accepted("4") else {
            throw MinerError("share work values don't follow the difficulty: \(atEasy) easy, \(atHard) hard")
        }
        let raw = try EthashPoolTestRun.rawRate(miner.session.search, seconds: 2)
        let loginRefusal = try EthashPoolTestRun.refusedLogin(type, gpu: gpu, endpoint: mock.endpoint)
        lines.append("refused login: run() stopped with PoolLoginRefused (\"\(loginRefusal.reason)\")")
        lines.append("\(accepted.count) shares accepted and 1 refused, as the pool counted; work per share followed the difficulty "
                     + "(\(formatRate(easyWork, "")) then \(formatRate(hardWork, "")) hashes); rate \(formatRate(steady, "H/s")) in the "
                     + "loop (2 s window) vs \(formatRate(raw, "H/s")) searching alone; \(fmt(now() - started, 1)) s")
        return lines
    }

    /// NiceHash's EthereumStratum/1.0.0 spec ends with a worked example: extranonce a2eea0 plus miner nonce cfae7df760
    /// on its header and seed hash is "a share with difficulty of 1.863". Recomputing it checks the nonce layout
    /// (extranonce first, hashed little-endian) and difficulty 1 = 0x00000000ffff00…00 with the light cache alone.
    static func niceHashExample() throws -> String {
        let seed = [UInt8](hex: "abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c")!
        let header = [UInt8](hex: "fc12eb20c58158071c956316cdcd12a22dd8bf126ac4aee559f0ffe4df11f279")!
        guard let epoch = EthashSeeds.iterations(of: seed) else { throw MinerError("the NiceHash example's seed hash isn't an Ethash seed") }
        let nonce = UInt64("a2eea0" + "cfae7df760", radix: 16)!
        let cache = EthashReference.makeCache(size: EthashReference.cacheSize(epoch: epoch), seed: seed)
        let result = cache.withUnsafeBufferPointer { c in
            EthashReference.hashimoto(header: header, nonce: nonce, datasetBytes: EthashReference.datasetSize(epoch: epoch)) { index in
                EthashReference.datasetItem(cache: c.baseAddress!, cacheItems: c.count / 16, index: index)
            }
        }
        let difficulty = EthashTarget.stratumDiff1 / EthashTarget.value(result.final)
        guard abs(difficulty - 1.863) < 0.0005 else {
            throw MinerError("NiceHash example share: difficulty \(difficulty) (final hash \(result.final.hex)), the spec says 1.863")
        }
        return "NiceHash EthereumStratum/1.0.0 spec example (seed of epoch \(epoch), nonce a2eea0 + cfae7df760): share difficulty "
            + String(format: "%.3f", difficulty) + ", as the spec says"
    }
}
