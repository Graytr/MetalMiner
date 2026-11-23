import Foundation

/// The pool side of Poseidon2PoolMiner.selfTest: the XMRig-style Quantus stratum on MockPool. Jobs use the official
/// golden vectors' headers as mining hashes with easy share targets; every share is re-hashed with the CPU reference.
final class Poseidon2MockServer {
    typealias R = Poseidon2Reference

    struct Job {
        let id: String
        let header: [UInt8]
        let extraNonce: String
        let difficulty: UInt64
        var target: [UInt64] { R.target(difficulty: difficulty) }
        /// The job object as the pool sends it.
        var payload: [String: Any] {
            ["job_id": id, "mining_hash": header.hex, "extranonce": extraNonce, "difficulty": difficulty, "target": R.hex(target)]
        }
    }

    struct Share {
        let job: String
        let nonce: String
        let accepted: Bool
        let reason: String
    }

    let login: String
    let session = "mock-qtc-session"
    let jobs: [Job]
    private let lock = NSLock()
    private var stageValue = 0
    private var seen: Set<String> = []
    private var sharesValue: [Share] = []
    private var keepalivesValue = 0
    private var loginValue: [String: Any] = [:]

    /// The scenario: jobs[0] comes with the login reply; after 3 shares are accepted on a job, the next one is pushed
    /// (clean_jobs); 3 accepted on the last job ends it.
    init(login: String, jobs: [Job]) {
        self.login = login
        self.jobs = jobs
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    /// The index of the job in force; jobs.count once the scenario is done.
    var stage: Int { locked { stageValue } }
    var shares: [Share] { locked { sharesValue } }
    var keepalives: Int { locked { keepalivesValue } }
    var loginParams: [String: Any] { locked { loginValue } }

    /// MockPool's responder: the answer to `message`, then anything the pool pushes after it.
    func handle(_ message: [String: Any]) -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [String: Any] ?? [:]
        switch message["method"] as? String {
        case "login"?:
            loginValue = params
            guard params["login"] as? String == login else { return [refusal(id, "invalid login")] }
            return [["id": id, "jsonrpc": "2.0", "error": NSNull(),
                     "result": ["id": session, "job": jobs[0].payload, "status": "OK", "extensions": ["keepalive"]]]]
        case "keepalived"?:
            keepalivesValue += 1
            return [["id": id, "jsonrpc": "2.0", "error": NSNull(), "result": ["status": "KEEPALIVED"]]]
        case "submit"?:
            let share = check(params)
            sharesValue.append(share)
            guard share.accepted else { return [refusal(id, share.reason)] }
            var replies: [[String: Any]] = [["id": id, "jsonrpc": "2.0", "error": NSNull(), "result": ["status": "OK"]]]
            if stageValue < jobs.count, share.job == jobs[stageValue].id,
               sharesValue.filter({ $0.accepted && $0.job == share.job }).count >= 3 {
                stageValue += 1
                if stageValue < jobs.count {
                    replies.append(["jsonrpc": "2.0", "method": "job", "params": ["clean_jobs": true, "job": jobs[stageValue].payload]])
                }
            }
            return replies
        default:
            return [refusal(id, "Unsupported request \(message["method"] as? String ?? "?")")]
        }
    }

    private func refusal(_ id: Any, _ reason: String) -> [String: Any] {
        ["id": id, "jsonrpc": "2.0", "error": ["code": -1, "message": reason], "result": NSNull()]
    }

    /// The pool's share check: this session, a known job, a 64-byte nonce starting with the job's extranonce, no
    /// duplicates, `result` equal to the CPU reference's hash, and that hash < the job's target.
    private func check(_ params: [String: Any]) -> Share {
        let jobID = params["job_id"] as? String ?? ""
        let nonceHex = (params["nonce"] as? String ?? "").lowercased()
        func verdict(_ accepted: Bool, _ reason: String) -> Share {
            Share(job: jobID, nonce: nonceHex, accepted: accepted, reason: reason)
        }
        guard params["id"] as? String == session else { return verdict(false, "Unauthenticated") }
        guard let job = jobs.first(where: { $0.id == jobID }) else { return verdict(false, "Block expired") }
        guard let nonce = [UInt8](hex: nonceHex), nonce.count == 64 else { return verdict(false, "Malformed nonce") }
        guard nonceHex.hasPrefix(job.extraNonce) else { return verdict(false, "Invalid nonce prefix") }
        guard seen.insert(jobID + "/" + nonceHex).inserted else { return verdict(false, "Duplicate share") }
        let hash = R.words(R.nonceHash(header: job.header, nonce: nonce))
        if let result = params["result"] as? String, result.lowercased() != R.hex(hash) { return verdict(false, "Bad hash") }
        guard R.less(hash, job.target) else { return verdict(false, "Low difficulty share") }
        return verdict(true, "")
    }
}

/// What the miner reported during selfTest.
final class Poseidon2TestRecord {
    var shares: [(accepted: Bool, work: Double, note: String?)] = []
    var rates: [Double] = []
    var logs: [String] = []
}

extension Poseidon2PoolMiner {
    /// A made-up login for the offline test; it never leaves 127.0.0.1.
    static let testLogin = "qzSelfTestPlaceholder/selftest"

    static func selfTest(gpu: GPU) throws -> [String] {
        let vectors = Poseidon2Vectors.nonceHash
        let jobs = [
            Poseidon2MockServer.Job(id: "j1", header: try Poseidon2Vectors.bytes(vectors[1].header), extraNonce: "5a17c0de",
                                    difficulty: 1 << 22),
            Poseidon2MockServer.Job(id: "j2", header: try Poseidon2Vectors.bytes(vectors[3].header), extraNonce: "a1b2c3d4",
                                    difficulty: 1 << 21),
        ]
        let server = Poseidon2MockServer(login: testLogin, jobs: jobs)
        let mock = try MockPool { message, _ in server.handle(message) }
        defer { mock.close() }
        let record = Poseidon2TestRecord()
        let events = PoolEvents(share: { record.shares.append(($0, $1, $2)) },
                                hashrate: { record.rates.append($0) },
                                log: { record.logs.append($0) })
        let miner = try Poseidon2PoolMiner(gpu: gpu, endpoint: mock.endpoint, login: testLogin, events: events,
                                           config: AlgoConfig(quick: true))

        // 1. The job path on quantus-miner's golden vector 2 (header 00..1f, nonce = 56 zero bytes + 1234567890abcdef):
        //    job fields -> job state -> search kernel must give the official 512-bit hash for that nonce.
        let golden = vectors[2]
        let goldenNonce = try Poseidon2Vectors.bytes(golden.nonce)
        let goldenJob = try job(from: ["job_id": "golden", "mining_hash": golden.header,
                                       "extranonce": Array(goldenNonce[0 ..< 4]).hex, "difficulty": 1],
                                fill: Array(goldenNonce[0 ..< 56]))
        let counter = goldenNonce[56 ..< 64].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let probe = try miner.hasher.search(state: goldenJob.state, start: counter, count: 1, target: goldenJob.target)
        let want = R.words(try Poseidon2Vectors.bytes(golden.hash))
        guard goldenJob.nonce(counter) == goldenNonce, probe.total == 1, probe.hits.first?.counter == counter,
              probe.hits.first?.hash == want else {
            throw MinerError("golden vector 2 through the job path: got \(probe.hits.first.map { R.hex($0.hash) } ?? "no hit"), want \(R.hex(want))")
        }

        // 2. The round trip.
        miner.testCorruptShare = 2
        miner.rateInterval = 0.25
        miner.keepaliveInterval = 0   // a keepalived before every dispatch, so the test always exercises it
        let started = now()
        try miner.run(shouldStop: { server.stage >= jobs.count || now() - started > 100 })
        let seconds = now() - started
        let shares = server.shares
        let accepted = shares.filter(\.accepted)
        guard server.stage >= jobs.count else {
            throw MinerError("stopped at mock stage \(server.stage) after \(fmt(seconds, 1)) s; the mock saw \(shares.count) shares "
                + "(\(accepted.count) accepted); miner log: \(record.logs.suffix(4).joined(separator: " | "))")
        }
        let loginParams = server.loginParams
        guard loginParams["login"] as? String == testLogin, loginParams["pass"] as? String == "x",
              loginParams["agent"] as? String == agent else {
            throw MinerError("login params \(compact(loginParams))")
        }
        let first = accepted.filter { $0.job == "j1" }, second = accepted.filter { $0.job == "j2" }
        guard first.count >= 3, second.count >= 3 else { throw MinerError("accepted \(first.count) on j1, \(second.count) on j2") }

        // The deliberately invalid share: refused by the mock's CPU check, reported as rejected.
        let refused = shares.filter { !$0.accepted }
        let reported = record.shares.filter { !$0.accepted }
        guard refused.count == 1, refused[0].reason == "Low difficulty share", reported.count == 1,
              reported[0].note?.contains("Low difficulty share") == true else {
            throw MinerError("invalid share: mock refused \(refused.map { "\($0.job) \($0.reason)" }), miner reported \(reported.map { $0.note ?? "" })")
        }

        // Every accepted share reported with its job's difficulty as its work.
        let expected = accepted.compactMap { share in jobs.first { $0.id == share.job }.map { Double($0.difficulty) } }.sorted()
        let got = record.shares.filter { $0.accepted }.map { $0.work }.sorted()
        guard expected == got else { throw MinerError("share work reported \(got), the mock accepted \(expected)") }
        guard server.keepalives > 0 else { throw MinerError("no keepalived reached the pool") }
        guard let rate = record.rates.last else { throw MinerError("no hashrate report") }

        // A refused login: run() ends with PoolLoginRefused carrying the pool's own words.
        let refusing = Poseidon2MockServer(login: testLogin, jobs: jobs)
        let refusingPool = try MockPool { message, _ in refusing.handle(message) }
        defer { refusingPool.close() }
        let stranger = try Poseidon2PoolMiner(gpu: gpu, endpoint: refusingPool.endpoint, login: "qzSomeoneElse/selftest",
                                              events: PoolEvents(), config: AlgoConfig(quick: true))
        let refusalStart = now()
        do {
            try stranger.run(shouldStop: { now() - refusalStart > 20 })
            throw MinerError("a refused login ended run() without an error")
        } catch let refused as PoolLoginRefused {
            guard refused.reason == "invalid login" else { throw MinerError("refused login reported as \(refused.reason)") }
        }

        return [
            "job path: quantus-miner golden vector 2 (mining_hash 00..1f, nonce 56 zero bytes + 1234567890abcdef) as a pool job"
                + " -> job state -> search kernel = the official 512-bit hash \(R.hex(want).prefix(16))…",
            "login {login, pass, agent} -> session + job j1 (mining_hash = vector 1's header, extranonce 5a17c0de,"
                + " difficulty 2^22 with its U512 target)",
            "job j1: \(first.count) shares (64-byte nonce = extranonce + session bytes + counter), each re-hashed by the mock"
                + " with the CPU reference and accepted",
            "deliberate invalid share \(refused[0].nonce.prefix(16))… on \(refused[0].job): the mock's CPU check refused it"
                + " (Low difficulty share); the miner reported it rejected",
            "mid-run job j2 (clean_jobs, mining_hash = vector 3's header, extranonce a1b2c3d4, difficulty 2^21):"
                + " \(second.count) shares accepted at the new target",
            "events: \(got.count) accepted, work = each job's difficulty, 1 rejected; \(server.keepalives) keepalived answered;"
                + " \(record.rates.count) hashrate reports, last \(formatRate(rate, "H/s")); \(fmt(seconds, 1)) s",
            "refused login (login -> error \"invalid login\"): run() throws PoolLoginRefused with the pool's words",
        ]
    }
}
