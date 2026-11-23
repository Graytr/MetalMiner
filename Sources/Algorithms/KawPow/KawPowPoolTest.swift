import Foundation

/// The pool side of KawPowPoolMiner's selfTest: answers mining.subscribe as Kryptex's RVN pool did in the handshake
/// ([null, 3-byte extranonce]), then set_target and the 7-field notify of kawpowminer and MiningCore after login, and checks
/// every share with KawPowReference over its own light cache: header, extranonce prefix, mix digest, full 256-bit target,
/// duplicates.
final class KawPowMockPool {
    struct Job {
        let id: String
        let header: [UInt8]
        let height: Int
        let target: [UInt8]
    }

    static let extranonce = "a3f1c2"   // 3 bytes, as Kryptex's RVN pool sent in the handshake
    let light: KawPowReference.Light
    private let lock = NSLock()
    private var jobs: [String: Job] = [:]
    private var current: Job?
    private var seen = Set<String>()
    private var acceptedByJob: [String: Int] = [:]
    private var rejected: [String] = []
    private var loginCount = 0

    init(light: KawPowReference.Light) { self.light = light }

    func accepted(_ job: String) -> Int { lock.withLock { acceptedByJob[job] ?? 0 } }
    var acceptedTotal: Int { lock.withLock { acceptedByJob.values.reduce(0, +) } }
    var rejections: [String] { lock.withLock { rejected } }
    var logins: Int { lock.withLock { loginCount } }

    /// Makes `job` current; pushes it now when `mock` is given (with mining.set_target first when `newTarget`),
    /// otherwise it goes out after the next login.
    func send(_ job: Job, to mock: MockPool?, newTarget: Bool = false) {
        lock.withLock {
            jobs[job.id] = job
            current = job
        }
        guard let mock else { return }
        if newTarget { mock.push(Self.setTarget(job.target)) }
        mock.push(Self.notify(job))
    }

    static func setTarget(_ target: [UInt8]) -> [String: Any] {
        ["id": NSNull(), "method": "mining.set_target", "params": [target.hex]]
    }

    static func notify(_ job: Job) -> [String: Any] {
        let seed = EthashReference.seed(iterations: job.height / KawPowReference.epochLength)
        return ["id": NSNull(), "method": "mining.notify",
                "params": [job.id, job.header.hex, seed.hex, job.target.hex, true, job.height, "1b00f0ff"] as [Any]]
    }

    func respond(_ message: [String: Any], _ mock: MockPool) -> [[String: Any]] {
        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.subscribe"?:
            let result: [Any] = [NSNull(), Self.extranonce]   // Kryptex's shape
            return [["id": id, "result": result, "error": NSNull()]]
        case "mining.authorize"?:
            let job: Job? = lock.withLock {
                loginCount += 1
                return current
            }
            guard params.first as? String == EthashPoolTestRun.login else {
                return [["id": id, "result": NSNull(), "error": [24, "unauthorized worker", NSNull()] as [Any]]]
            }
            var replies: [[String: Any]] = [["id": id, "result": true, "error": NSNull()]]
            if let job { replies += [Self.setTarget(job.target), Self.notify(job)] }
            return replies
        case "mining.submit"?:
            let problem = check(params)
            lock.withLock {
                if let problem { rejected.append(problem) } else if let job = params[1] as? String { acceptedByJob[job, default: 0] += 1 }
            }
            if let problem { return [["id": id, "result": NSNull(), "error": [20, problem, NSNull()] as [Any]]] }
            return [["id": id, "result": true, "error": NSNull()]]
        default:
            return [["id": id, "result": NSNull(), "error": [20, "unknown method", NSNull()] as [Any]]]
        }
    }

    /// nil for a good share, else what's wrong with it.
    private func check(_ params: [Any]) -> String? {
        guard params.count == 5, params[0] as? String == EthashPoolTestRun.login, let jobID = params[1] as? String,
              let nonceText = params[2] as? String, let headerText = params[3] as? String, let mixText = params[4] as? String else {
            return "malformed submit"
        }
        guard let job = lock.withLock({ jobs[jobID] }) else { return "unknown job" }
        guard nonceText.count == 18, nonceText.hasPrefix("0x"), let nonce = UInt64(nonceText.dropFirst(2), radix: 16) else { return "bad nonce" }
        guard nonceText.dropFirst(2).hasPrefix(Self.extranonce) else { return "nonce without the extranonce" }
        guard headerText == "0x" + job.header.hex else { return "wrong header hash" }
        guard lock.withLock({ seen.insert(jobID + nonceText).inserted }) else { return "duplicate share" }
        let cpu = KawPowReference.hash(header: job.header, nonce: nonce, blockNumber: job.height, items: light.items, l1: light.l1,
                                       item: light.item)
        guard mixText == "0x" + cpu.mix.hex else { return "bad mix hash" }
        guard EthashTarget.meets(cpu.final, job.target) else { return "low difficulty share" }
        return nil
    }
}

/// KawPowPoolMiner's offline round trip. Jobs are cpp-kawpow vector header hashes at their heights (epoch 0, so a
/// 1 GiB DAG): blocks 49 and 50 share period 16, block 99 is period 33, so the program is recompiled mid-run.
enum KawPowPoolTest {
    static let blocks: [(height: Int, header: String)] = [
        (49, "63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b"),
        (50, "9e7248f20914913a73d80a70174c331b1d34f260535ac3631d770e656b5dd922"),
        (99, "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d"),
    ]

    static func run(gpu: GPU) throws -> [String] {
        let started = now()
        var lines: [String] = []
        let pool = KawPowMockPool(light: KawPowReference.Light(epoch: 0))
        let mock = try MockPool { message, mock in pool.respond(message, mock) }
        defer { mock.close() }
        let easy = EthashTarget.bytes(0x1p234)   // about 4.2 M hashes per share
        let hard = EthashTarget.bytes(0x1p232)   // 4 times harder
        func job(_ id: String, _ block: Int, _ target: [UInt8]) -> KawPowMockPool.Job {
            KawPowMockPool.Job(id: id, header: [UInt8](hex: blocks[block].header)!, height: blocks[block].height, target: target)
        }
        lines.append("mock pool: subscribe answered as Kryptex does ([null, \"\(KawPowMockPool.extranonce)\"]), then set_target and 7-field notify; "
                     + "every share checked by KawPowReference over its own epoch-0 light cache")

        let harness = EthashPoolTestRun()
        let miner = try KawPowPoolMiner(gpu: gpu, endpoint: mock.endpoint, login: EthashPoolTestRun.login, events: harness.events)
        miner.session.rateInterval = 2
        pool.send(job("1", 0, easy), to: nil)
        harness.start(miner)
        defer { _ = try? harness.stop() }

        try harness.waitFor("2 accepted shares on job 1", timeout: 90) { pool.accepted("1") >= 2 }
        let built = harness.lines.first { $0.contains("DAG") } ?? "(no DAG line)"
        lines.append("job 1 (block 49, period 16, \(formatRate(EthashTarget.work(easy), "")) hashes per share): \(pool.accepted("1")) shares accepted; \(built)")

        pool.send(job("2", 1, easy), to: mock)
        try harness.waitFor("2 accepted shares on job 2", timeout: 60) { pool.accepted("2") >= 2 }
        lines.append("job 2 (block 50, same period, program reused): \(pool.accepted("2")) shares accepted")

        miner.session.corruptNextShare()
        try harness.waitFor("the corrupted share's rejection", timeout: 60) {
            !pool.rejections.isEmpty && harness.shares.contains { !$0.accepted }
        }
        let refusal = harness.shares.first { !$0.accepted }?.note ?? ""
        lines.append("corrupted share (nonce changed after the CPU check): refused by the pool (\(pool.rejections[0])) and reported as \"\(refusal)\"")

        pool.send(job("3", 2, hard), to: mock, newTarget: true)
        try harness.waitFor("2 accepted shares on job 3", timeout: 90) { pool.accepted("3") >= 2 }
        let recompiled = harness.lines.first { $0.contains("period 33") } ?? "(no period 33 line)"
        lines.append("set_target 4x harder + job 3 (block 99): \(pool.accepted("3")) shares accepted at the new target; \(recompiled)")

        pool.send(job("4", 2, hard), to: nil)   // goes out after the miner logs in again
        mock.push(["id": NSNull(), "method": "client.reconnect", "params": [] as [Any]])
        try harness.waitFor("a share after client.reconnect", timeout: 60) { pool.logins >= 2 && pool.accepted("4") >= 1 }
        lines.append("client.reconnect: logged in again (\(pool.logins) logins), job 4: \(pool.accepted("4")) share accepted")

        let reports = harness.rates.count
        try harness.waitFor("2 rate reports after the reconnect", timeout: 30) { harness.rates.count >= reports + 2 }
        let steady = harness.rates.last ?? 0
        try harness.stop()

        // What the miner reported has to match what the pool decided.
        let shares = harness.shares
        let accepted = shares.filter { $0.accepted }
        let refused = shares.filter { !$0.accepted }
        guard accepted.count == pool.acceptedTotal, refused.count == 1, pool.rejections.count == 1 else {
            throw MinerError("reported \(accepted.count) accepted / \(refused.count) refused, the pool counted \(pool.acceptedTotal) / \(pool.rejections.count): \(pool.rejections)")
        }
        let hardWork = EthashTarget.work(hard), easyWork = EthashTarget.work(easy)
        let atHard = accepted.filter { abs($0.work - hardWork) < hardWork * 1e-9 }.count
        let atEasy = accepted.filter { abs($0.work - easyWork) < easyWork * 1e-9 }.count
        guard atHard == pool.accepted("3") + pool.accepted("4"), atEasy == pool.accepted("1") + pool.accepted("2") else {
            throw MinerError("share work values don't follow the targets: \(atEasy) easy, \(atHard) hard")
        }
        let raw = try EthashPoolTestRun.rawRate(miner.session.search, seconds: 2)
        let loginRefusal = try EthashPoolTestRun.refusedLogin(KawPowPoolMiner.self, gpu: gpu, endpoint: mock.endpoint)
        lines.append("refused login: run() stopped at once with PoolLoginRefused (\"\(loginRefusal.reason)\")")
        lines.append("\(accepted.count) shares accepted and 1 refused, as the pool counted; work per share followed set_target "
                     + "(\(formatRate(easyWork, "")) then \(formatRate(hardWork, "")) hashes); every nonce began with the extranonce; "
                     + "rate \(formatRate(steady, "H/s")) in the loop (2 s window) vs \(formatRate(raw, "H/s")) searching alone; \(fmt(now() - started, 1)) s")
        return lines
    }
}
