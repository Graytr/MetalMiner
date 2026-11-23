import Foundation

/// The pool side of XelisHashPoolMiner.selfTest: a XELIS stratum server on MockPool that hands out jobs built from two
/// real mainnet blocks, re-hashes every share with the CPU reference, and changes difficulty, extra nonce and job mid-run.
final class XelisHashMockServer {
    struct Job {
        /// MinerWork as the pool rebuilds it (nonce bytes zero) and the share difficulty in force for this job.
        let work: [UInt8]
        let difficulty: Double
    }

    struct Share {
        let job: String
        let nonce: String
        let accepted: Bool
        let code: Int
        let reason: String
    }

    let login: String
    let session = "mock-xel-session"
    let pingID = 77
    private let blocks: [[UInt8]]
    private let networkDifficulty: Double
    private let lock = NSLock()
    private var jobs: [String: Job] = [:]
    private var seen: Set<String> = []
    private var stageValue = 0
    private var sharesValue: [Share] = []
    private var subscribeValue: [Any] = []
    private var authorizeValue: [Any] = []
    private var pongValue: Any?

    /// `blocks`: the MinerWork of real mainnet blocks (block 0 first, at `networkDifficulty`).
    init(login: String, blocks: [[UInt8]], networkDifficulty: Double) {
        self.login = login
        self.blocks = blocks
        self.networkDifficulty = networkDifficulty
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    /// 0 before authorize; 1 block 0 at its network difficulty; 2 the same block at difficulty 64; 3 block 1 (new extra
    /// nonce and key) at difficulty 128; 4 done (3 shares accepted on block 1).
    var stage: Int { locked { stageValue } }
    var shares: [Share] { locked { sharesValue } }
    var subscribeParams: [Any] { locked { subscribeValue } }
    var authorizeParams: [Any] { locked { authorizeValue } }
    var pong: Any? { locked { pongValue } }
    func difficulty(of job: String) -> Double? { locked { jobs[job]?.difficulty } }

    /// MockPool's responder: the answer to `message`, then anything the pool pushes after it.
    func handle(_ message: [String: Any]) -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.subscribe"?:
            subscribeValue = params
            return [["id": id, "result": [session, Array(blocks[0][48 ..< 80]).hex, 32, Array(blocks[0][80 ..< 112]).hex],
                     "error": NSNull()]]
        case "mining.authorize"?:
            authorizeValue = params
            guard params.first as? String == login else { return [refusal(id, 24, "unauthorized worker")] }
            stageValue = 1
            return [["id": id, "result": true, "error": NSNull()]] + issue("b0", block: 0, difficulty: networkDifficulty, clean: true)
        case "mining.submit"?:
            let share = check(params)
            sharesValue.append(share)
            guard share.accepted else { return [refusal(id, share.code, share.reason)] }
            return [["id": id, "result": true, "error": NSNull()]] + advance(after: share)
        case "mining.pong"?:
            pongValue = message["id"]
            return []
        default:
            return [refusal(id, 20, "unknown method")]
        }
    }

    private func refusal(_ id: Any, _ code: Int, _ reason: String) -> [String: Any] {
        ["id": id, "result": false, "error": ["code": code, "message": reason]]
    }

    /// mining.set_difficulty, then mining.notify for a job on one of the real blocks (its header work hash and timestamp).
    private func issue(_ jobID: String, block k: Int, difficulty: Double, clean: Bool) -> [[String: Any]] {
        var work = blocks[k]
        work.replaceSubrange(40 ..< 48, with: [UInt8](repeating: 0, count: 8))
        jobs[jobID] = Job(work: work, difficulty: difficulty)
        let timestamp = blocks[k][32 ..< 40].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        return [["id": NSNull(), "method": "mining.set_difficulty", "params": [difficulty]],
                ["id": NSNull(), "method": "mining.notify",
                 "params": [jobID, String(timestamp, radix: 16, uppercase: true), Array(blocks[k][0 ..< 32]).hex, "xel/v3", clean]]]
    }

    /// The scenario: the real block's share -> easy job on the same block -> after 3 shares, ping, new extra nonce and key,
    /// harder difficulty, second block -> after 3 shares, done.
    private func advance(after share: Share) -> [[String: Any]] {
        let count = sharesValue.filter { $0.accepted && $0.job == share.job }.count
        switch (stageValue, share.job) {
        case (1, "b0"):
            stageValue = 2
            return issue("b0e", block: 0, difficulty: 64, clean: false)
        case (2, "b0e") where count >= 3:
            stageValue = 3
            return [["id": pingID, "method": "mining.ping"],
                    ["id": NSNull(), "method": "mining.set_extranonce",
                     "params": [Array(blocks[1][48 ..< 80]).hex, 32, Array(blocks[1][80 ..< 112]).hex]]]
                + issue("b1", block: 1, difficulty: 128, clean: true)
        case (3, "b1") where count >= 3:
            stageValue = 4
            return []
        default:
            return []
        }
    }

    /// The pool's share check: the worker name that was authorized (submit's first parameter in the spec), a known job,
    /// the 8 nonce bytes placed at MinerWork bytes 40..<48 as sent, no duplicates, and the CPU reference's v3 hash
    /// <= (2^256 - 1) / the job's difficulty.
    private func check(_ params: [Any]) -> Share {
        let jobID = params.count > 1 ? params[1] as? String ?? "" : ""
        let nonceHex = params.count > 2 ? params[2] as? String ?? "" : ""
        func verdict(_ accepted: Bool, _ code: Int, _ reason: String) -> Share {
            Share(job: jobID, nonce: nonceHex, accepted: accepted, code: code, reason: reason)
        }
        let worker = authorizeValue.count > 1 ? authorizeValue[1] as? String : nil
        guard worker != nil, params.first as? String == worker else { return verdict(false, 24, "unauthorized worker") }
        guard let job = jobs[jobID] else { return verdict(false, 21, "job not found") }
        guard nonceHex.count == 16, let nonce = [UInt8](hex: nonceHex) else { return verdict(false, 20, "malformed nonce") }
        guard seen.insert(jobID + "/" + nonceHex.lowercased()).inserted else { return verdict(false, 22, "duplicate share") }
        var work = job.work
        work.replaceSubrange(40 ..< 48, with: nonce)
        let hash = XelisHashReference.V3.hash(work)
        guard XelisHashReference.meets(hash, XelisHashReference.target(difficulty: UInt64(job.difficulty))) else {
            return verdict(false, 23, "low difficulty share")
        }
        return verdict(true, 0, "")
    }
}

/// What the miner reported during selfTest.
final class XelisHashTestRecord {
    var shares: [(accepted: Bool, work: Double, note: String?)] = []
    var rates: [Double] = []
    var logs: [String] = []
}

extension XelisHashPoolMiner {
    /// A made-up login for the offline test; it never leaves 127.0.0.1.
    static let testLogin = "xel:selftest-placeholder/selftest"

    static func selfTest(gpu: GPU) throws -> [String] {
        let blocks = XelisHashReference.mainnetBlocks
        let works = try blocks.map { try $0.minerWork() }
        let server = XelisHashMockServer(login: testLogin, blocks: works, networkDifficulty: Double(blocks[0].difficulty))
        let mock = try MockPool { message, _ in server.handle(message) }
        defer { mock.close() }
        let record = XelisHashTestRecord()
        let events = PoolEvents(share: { record.shares.append(($0, $1, $2)) },
                                hashrate: { record.rates.append($0) },
                                log: { record.logs.append($0) })
        let miner = try XelisHashPoolMiner(gpu: gpu, endpoint: mock.endpoint, login: testLogin, events: events,
                                           config: AlgoConfig(quick: true))
        miner.testStartNonce = blocks[0].nonce &- 8   // the first dispatch covers the real block's nonce
        miner.testCorruptShare = 3
        miner.rateInterval = 1
        let started = now()
        try miner.run(shouldStop: { server.stage >= 4 || now() - started > 100 })
        let seconds = now() - started
        let shares = server.shares
        let accepted = shares.filter(\.accepted)
        guard server.stage >= 4 else {
            throw MinerError("stopped at mock stage \(server.stage) after \(fmt(seconds, 1)) s; the mock saw \(shares.count) shares "
                + "(\(accepted.count) accepted); miner log: \(record.logs.suffix(4).joined(separator: " | "))")
        }

        // Subscribe and authorize as specified.
        let subscribe = server.subscribeParams, authorize = server.authorizeParams
        guard subscribe.first as? String == agent, subscribe.count > 1, subscribe[1] as? [String] == ["xel/v3"] else {
            throw MinerError("mining.subscribe params \(compact(subscribe))")
        }
        guard authorize.count == 3, authorize[0] as? String == testLogin, authorize[1] as? String == "selftest" else {
            throw MinerError("mining.authorize params \(compact(authorize))")
        }

        // The real block: exactly its own nonce, found under its network target.
        let blockNonce = nonceHex(blocks[0].nonce)
        guard let blockShare = shares.first(where: { $0.job == "b0" }), blockShare.accepted, blockShare.nonce == blockNonce,
              shares.filter({ $0.job == "b0" }).count == 1 else {
            throw MinerError("block \(blocks[0].height): expected one share with nonce \(blockNonce), got \(shares.filter { $0.job == "b0" }.map(\.nonce))")
        }
        let easy = accepted.filter { $0.job == "b0e" }
        let second = accepted.filter { $0.job == "b1" }

        // The deliberately invalid share: refused by the mock's CPU check and reported as rejected.
        let refused = shares.filter { !$0.accepted }
        let reported = record.shares.filter { !$0.accepted }
        guard refused.count == 1, refused[0].code == 23, reported.count == 1,
              reported[0].note?.contains("low difficulty share") == true else {
            throw MinerError("invalid share: mock refused \(refused.map { "\($0.job) \($0.code) \($0.reason)" }), "
                + "miner reported \(reported.map { $0.note ?? "" })")
        }

        // Mid-run messages and the second block.
        guard (server.pong as? NSNumber)?.intValue == server.pingID else { throw MinerError("no mining.pong for ping \(server.pingID)") }
        guard second.count >= 3 else { throw MinerError("only \(second.count) shares on the second block") }

        // Every accepted share reported with its job's difficulty as its work.
        let expected = accepted.compactMap { server.difficulty(of: $0.job) }.sorted()
        let got = record.shares.filter { $0.accepted }.map { $0.work }.sorted()
        guard expected == got else { throw MinerError("share work reported \(got), the mock accepted \(expected)") }
        guard let rate = record.rates.last else { throw MinerError("no hashrate report") }

        // A refused login: run() ends with PoolLoginRefused carrying the pool's own words.
        let refusing = XelisHashMockServer(login: testLogin, blocks: works, networkDifficulty: Double(blocks[0].difficulty))
        let refusingPool = try MockPool { message, _ in refusing.handle(message) }
        defer { refusingPool.close() }
        let stranger = try XelisHashPoolMiner(gpu: gpu, endpoint: refusingPool.endpoint, login: "xel:someone-else/selftest",
                                              events: PoolEvents(), config: AlgoConfig(quick: true))
        let refusalStart = now()
        do {
            try stranger.run(shouldStop: { now() - refusalStart > 20 })
            throw MinerError("a refused login ended run() without an error")
        } catch let refused as PoolLoginRefused {
            guard refused.reason == "unauthorized worker" else { throw MinerError("refused login reported as \(refused.reason)") }
        }

        return [
            "subscribe [\(agent), [xel/v3]] -> session, extra nonce and pool key of block \(blocks[0].height);"
                + " authorize [\(testLogin), selftest, x] -> true",
            "job b0 = block \(blocks[0].height)'s header work hash and timestamp at its network difficulty \(blocks[0].difficulty):"
                + " the GPU found the block's own nonce \(blockNonce), the mock's CPU re-hash accepted it",
            "job b0e (same block, difficulty 64): \(easy.count) shares, each re-hashed by the mock with the CPU reference and accepted",
            "deliberate invalid share \(refused[0].nonce) on \(refused[0].job): the mock's CPU check refused it"
                + " (23 low difficulty share); the miner reported it rejected",
            "mid-run: ping -> pong; set_extranonce to block \(blocks[1].height)'s extra nonce and key, difficulty 128, job b1:"
                + " \(second.count) shares accepted at the new target",
            "events: \(got.count) accepted, work = each job's difficulty (\(format(got.last ?? 0)) max), 1 rejected;"
                + " \(record.rates.count) hashrate reports, last \(formatRate(rate, "H/s")) (256 scratchpads); \(fmt(seconds, 1)) s",
            "refused login (mining.authorize -> error 24 unauthorized worker): run() throws PoolLoginRefused with the pool's words",
        ]
    }
}
