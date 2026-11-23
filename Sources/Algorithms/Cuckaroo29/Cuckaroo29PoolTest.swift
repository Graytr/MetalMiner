import Foundation

extension Cuckaroo29PoolMiner {
    /// `metalminer pooltest`: the dialect's encoding on the CPU, then a full round trip against a mock pool on 127.0.0.1
    /// that checks every share with the CPU reference (Cuckaroo29PoolSelfTest).
    static func selfTest(gpu: GPU) throws -> [String] { try Cuckaroo29PoolSelfTest().run(gpu: gpu) }
}

/// The mock pool's side of the C29 dialect. It answers a login with the next prepared job, checks every submit with the
/// CPU reference (session, job, nonce and extra nonce, 42 edges, the "result" hash, the cycle itself, the difficulty,
/// duplicates) and answers keepalived and getjob.
final class Cuckaroo29MockPoolState {
    struct Verdict {
        let job: String
        let nonce: String
        let pow: [UInt64]
        let accepted: Bool
        let note: String?
        let difficulty: UInt64?
    }

    let session = "mock-session-7"
    private let lock = NSLock()
    private var jobs: [String: Cuckaroo29PoolJob] = [:]
    private var current: Cuckaroo29PoolJob?
    private var loginJobs: [Cuckaroo29PoolJob]
    private var seen = Set<String>()
    private var verdictList: [Verdict] = []
    private var loginList: [(params: [String: Any], time: Double)] = []
    private var unknownList: [String] = []
    private var acceptedCount = 0

    init(loginJobs: [Cuckaroo29PoolJob]) {
        self.loginJobs = loginJobs
        for job in loginJobs { jobs[job.id] = job }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    var verdicts: [Verdict] { locked { verdictList } }
    var logins: [(params: [String: Any], time: Double)] { locked { loginList } }
    var unknown: [String] { locked { unknownList } }

    func register(_ job: Cuckaroo29PoolJob) { locked { () -> Void in jobs[job.id] = job } }

    /// Registers `job` as the current one and returns its "job" notification.
    func announce(_ job: Cuckaroo29PoolJob) -> [String: Any] {
        locked { () -> Void in
            jobs[job.id] = job
            current = job
        }
        return ["jsonrpc": "2.0", "method": "job", "params": job.json]
    }

    func respond(_ message: [String: Any]) -> [[String: Any]] {
        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [String: Any] ?? [:]
        func answer(_ result: Any) -> [[String: Any]] { [["id": id, "jsonrpc": "2.0", "error": NSNull(), "result": result]] }
        func refuse(_ text: String) -> [[String: Any]] {
            [["id": id, "jsonrpc": "2.0", "error": ["code": -1, "message": text], "result": NSNull()]]
        }
        switch message["method"] as? String {
        case "login"?:
            guard let login = params["login"] as? String, !login.isEmpty else { return refuse("Invalid address provided") }
            let next = locked { () -> Cuckaroo29PoolJob? in
                loginList.append((params, now()))
                guard !loginJobs.isEmpty else { return nil }
                current = loginJobs.removeFirst()
                return current
            }
            guard let next else { return refuse("No work") }
            return answer(["id": session, "job": next.json, "status": "OK"])
        case "submit"?:
            let verdict = check(params)
            guard verdict.accepted else { return refuse(verdict.note ?? "Rejected") }
            // Pools answer a good share with {"status": "OK"} or with true: the first share gets one, the rest the other.
            let first = locked { () -> Bool in
                acceptedCount += 1
                return acceptedCount == 1
            }
            return first ? answer(["status": "OK"]) : answer(true)
        case "keepalived"?:
            return answer(["status": "KEEPALIVED"])
        case "getjob"?:
            guard let job = locked({ current }) else { return refuse("No work") }
            return answer(job.json)
        default:
            locked { () -> Void in unknownList.append(Cuckaroo29Stratum.describe(message)) }
            return refuse("Unknown method")
        }
    }

    /// The pool's share check, all on the CPU reference.
    func check(_ params: [String: Any]) -> Verdict {
        let jobID = params["job_id"] as? String ?? ""
        let nonceText = params["nonce"] as? String ?? ""
        let powList = params["pow"] as? [Any] ?? []
        let pow = powList.compactMap { ($0 as? NSNumber)?.uint64Value }
        func verdict(_ accepted: Bool, _ note: String?, _ difficulty: UInt64? = nil) -> Verdict {
            let result = Verdict(job: jobID, nonce: nonceText, pow: pow, accepted: accepted, note: note, difficulty: difficulty)
            locked { () -> Void in verdictList.append(result) }
            return result
        }
        guard params["id"] as? String == session else { return verdict(false, "Unauthenticated") }
        guard let job = locked({ jobs[jobID] }) else { return verdict(false, "Invalid job id") }
        guard nonceText.count == 16, nonceText == nonceText.lowercased(), let nonce = UInt64(nonceText, radix: 16) else {
            return verdict(false, "Invalid nonce")
        }
        guard nonceText.hasPrefix(job.extraNonce.hex) else { return verdict(false, "Invalid extra nonce") }
        guard pow.count == Cuckaroo29Reference.cycleLength, powList.count == pow.count else {
            return verdict(false, "Invalid proof size")
        }
        let hash = Cuckaroo29Reference.blake2b(Cuckaroo29Reference.pack(pow, edgeBits: 29))
        if let result = params["result"] as? String, result != hash.hex { return verdict(false, "Result hash mismatch") }
        let keys = Cuckaroo29Reference.keys(miningHash: job.miningHash, nonce: nonce)
        if let problem = Cuckaroo29Reference.verify(keys: keys, nonces: pow, edgeBits: 29) {
            return verdict(false, "Invalid proof: \(problem)")
        }
        let difficulty = Cuckaroo29Reference.difficulty(hash: hash)
        guard difficulty >= job.difficulty else {
            return verdict(false, "Low difficulty share (\(difficulty) < \(job.difficulty))", difficulty)
        }
        let key = nonceText + ":" + pow.map { String($0) }.joined(separator: ",")
        guard locked({ seen.insert(key).inserted }) else { return verdict(false, "Duplicate share", difficulty) }
        return verdict(true, nil, difficulty)
    }
}

/// The offline round trip. Jobs carry the mining hashes of two real Tari C29 blocks (the proofs in Tari's
/// cuckaroo_pow.rs tests) at share difficulty 1, with the top two bytes of each block's nonce as the extra nonce and the
/// nonce counter started at the block's nonce, so the GPU finds the published proof on the first graph of each job.
/// Random graphs then supply a share nobody published. Along the way: a difficulty change, a new job at the next
/// height, a deliberately corrupted share, and a reconnect request.
final class Cuckaroo29PoolSelfTest {
    private let lock = NSLock()
    private var shares: [(accepted: Bool, work: Double, note: String?)] = []
    private var rates: [(time: Double, rate: Double)] = []
    private var logs: [String] = []
    private var stopping = false
    private var failure: Error?
    private var corrupted = Set<String>()

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    func run(gpu: GPU) throws -> [String] {
        [try encodingCheck()] + (try roundTrip(gpu: gpu))
    }

    /// Serializes and parses `object`, as the wire would.
    private func wire(_ object: [String: Any]) throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: object)
        guard let back = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw MinerError("JSON round trip failed")
        }
        return back
    }

    /// The dialect's encoding, on the CPU: targets, nonces, job fields, the answers pools give, and proof 1's submit
    /// through the mock's checks.
    private func encodingCheck() throws -> String {
        func expect(_ ok: Bool, _ what: @autoclosure () -> String) throws {
            if !ok { throw MinerError("encoding: \(what())") }
        }
        let target20 = Cuckaroo29Stratum.target(difficulty: 20)
        try expect(target20 == "cccccccccccccc0c", "difficulty 20 encodes as target \(target20)")
        try expect(Cuckaroo29Stratum.difficulty(target: target20) == 20, "target \(target20) doesn't decode as difficulty 20")
        try expect(Cuckaroo29Stratum.difficulty(target: "ffffffffffffffff") == 1, "the 8-byte target for difficulty 1")
        try expect(Cuckaroo29Stratum.difficulty(target: "ffffffff") == 1, "the 4-byte target for difficulty 1")
        try expect(Cuckaroo29Stratum.difficulty(target: "0011") == nil && Cuckaroo29Stratum.difficulty(target: "zz") == nil,
                   "malformed targets accepted")
        let nonceText = Cuckaroo29Stratum.nonceHex(Cuckaroo29Reference.proof1Nonce)
        try expect(nonceText == "9d589ed597ed42d0", "nonce 0x9D589ED597ED42D0 written as \(nonceText)")

        // A job as go-tari-c29-solo-stratum and MoneroOcean's XTM-C pool send it, then one that leaves target and xn out.
        let sample: [String: Any] = [
            "algo": "cuckaroo", "blob": Cuckaroo29Reference.proof1Hash, "height": 391_750, "job_id": "96c2b726aaebc0e2",
            "target": target20, "xn": "9d58", "id": "e0b5baa28cb125ed", "proofsize": 42, "noncebytes": 8, "nonceoffset": 0,
        ]
        let job = try Cuckaroo29Stratum.job(try wire(sample), previous: nil)
        try expect(job.id == "96c2b726aaebc0e2" && job.difficulty == 20 && job.extraNonce == [0x9D, 0x58]
                   && job.height == 391_750 && job.miningHash.hex == Cuckaroo29Reference.proof1Hash,
                   "sample job read as \(job.summary)")
        let next = try Cuckaroo29Stratum.job(try wire(["blob": Cuckaroo29Reference.proof1Hash, "job_id": 7, "height": "391751"]),
                                             previous: job)
        try expect(next.id == "7" && next.difficulty == 20 && next.extraNonce == job.extraNonce && next.height == 391_751,
                   "follow-up job read as \(next.summary)")
        let unusable: [[String: Any]] = [
            ["blob": "00ff", "job_id": "x", "target": target20],
            ["blob": Cuckaroo29Reference.proof1Hash, "target": target20],
            ["blob": Cuckaroo29Reference.proof1Hash, "job_id": "x"],
            ["blob": Cuckaroo29Reference.proof1Hash, "job_id": "x", "target": target20, "xn": "0011223344556677"],
        ]
        for object in unusable {
            let read = try? Cuckaroo29Stratum.job(try wire(object), previous: nil)
            try expect(read == nil, "unusable job accepted: \(Cuckaroo29Stratum.describe(object))")
        }

        // Answers to a submit, as the references send them.
        let good: [[String: Any]] = [
            ["id": 4, "jsonrpc": "2.0", "result": true],
            ["id": 4, "jsonrpc": "2.0", "error": NSNull(), "result": ["status": "OK"]],
            ["id": 4, "jsonrpc": "2.0", "error": "", "result": true],
            ["id": "4", "result": "ok"],
        ]
        let bad: [[String: Any]] = [
            ["id": 4, "jsonrpc": "2.0", "error": ["code": -1, "message": "Low difficulty share"], "result": NSNull()],
            ["id": 4, "jsonrpc": "2.0", "error": "Invalid job id", "result": false],
            ["id": 4, "result": false],
            ["id": 4, "error": [21, "Job not found", NSNull()], "result": NSNull()],
        ]
        for reply in good {
            let read = try wire(reply)
            try expect(Cuckaroo29Stratum.verdict(read).accepted && Cuckaroo29Stratum.requestID(read["id"]) == 4,
                       "\(Cuckaroo29Stratum.describe(reply)) read as refused")
        }
        for reply in bad {
            try expect(!Cuckaroo29Stratum.verdict(try wire(reply)).accepted, "\(Cuckaroo29Stratum.describe(reply)) read as accepted")
        }
        let note = Cuckaroo29Stratum.verdict(try wire(bad[0])).note
        try expect(note == "Low difficulty share", "error message read as \(note ?? "nothing")")

        // Proof 1 as a submit: the mock's CPU check takes it at its own difficulty, not one above, and not corrupted.
        let nonces = Cuckaroo29Reference.proof1Nonces
        let powData = Cuckaroo29Reference.pack(nonces, edgeBits: 29)
        let hash = Cuckaroo29Reference.blake2b(powData)
        let proof = Cuckaroo29Miner.Solution(nonces: nonces, powData: powData, hash: hash,
                                             difficulty: Cuckaroo29Reference.difficulty(hash: hash))
        let probe = Cuckaroo29MockPoolState(loginJobs: [])
        var verdicts: [Bool] = []
        for difficulty in [proof.difficulty, proof.difficulty + 1] {
            let probeJob = Cuckaroo29PoolJob(id: "probe\(difficulty)", miningHash: [UInt8](hex: Cuckaroo29Reference.proof1Hash)!,
                                             height: nil, difficulty: difficulty, target: nil, extraNonce: [0x9D, 0x58])
            probe.register(probeJob)
            let params = Cuckaroo29Stratum.submitParams(session: probe.session, job: probeJob.id,
                                                        nonce: Cuckaroo29Reference.proof1Nonce, solution: proof)
            try expect(params["result"] as? String == Cuckaroo29Reference.proof1PowHash, "proof 1's result hash")
            verdicts.append(probe.check(try wire(params)).accepted)
        }
        try expect(verdicts == [true, false], "the mock's check gives \(verdicts) for proof 1 at difficulty"
                   + " \(proof.difficulty) and \(proof.difficulty + 1)")
        let broken = probe.check(try wire(Cuckaroo29Stratum.submitParams(
            session: probe.session, job: "probe\(proof.difficulty)", nonce: Cuckaroo29Reference.proof1Nonce,
            solution: Cuckaroo29PoolMiner.corrupted(proof))))
        try expect(!broken.accepted && broken.note?.hasPrefix("Invalid proof") == true, "corrupted proof 1 got \(broken)")
        return "encoding: difficulty 20 <-> target \(target20) (8 bytes little-endian, (2^64 - 1) / 20); nonce"
            + " \(nonceText) (8 bytes big-endian); job fields (blob, job_id, target, height, xn; target and xn carry over;"
            + " \(unusable.count) unusable jobs refused); \(good.count + bad.count) answer forms; Tari proof 1 as a submit"
            + " passes the mock's CPU check at difficulty \(proof.difficulty), fails at \(proof.difficulty + 1), and"
            + " fails corrupted (\(broken.note ?? ""))"
    }

    private func roundTrip(gpu: GPU) throws -> [String] {
        let header1 = [UInt8](hex: Cuckaroo29Reference.proof1Hash)!
        let header2 = [UInt8](hex: Cuckaroo29Reference.keyVectors[1].0)!
        let nonce1 = Cuckaroo29Reference.proof1Nonce
        let nonce2 = Cuckaroo29Reference.keyVectors[1].1
        let low48: UInt64 = (1 << 48) - 1
        func top2(_ nonce: UInt64) -> [UInt8] { [UInt8(nonce >> 56), UInt8((nonce >> 48) & 0xFF)] }
        let height: UInt64 = 391_750   // mainnet height on 2026-11-20 (Kryptex's pool info); not part of the proof
        let job1 = Cuckaroo29PoolJob(id: "a1", miningHash: header1, height: height, difficulty: 1, target: nil,
                                     extraNonce: top2(nonce1))
        let job1b = Cuckaroo29PoolJob(id: "a2", miningHash: header1, height: height, difficulty: 1000, target: nil,
                                      extraNonce: top2(nonce1))
        let job2 = Cuckaroo29PoolJob(id: "b1", miningHash: header2, height: height + 1, difficulty: 1, target: nil,
                                     extraNonce: top2(nonce2))
        let job3 = Cuckaroo29PoolJob(id: "c1", miningHash: header1, height: height + 2, difficulty: 1, target: nil,
                                     extraNonce: [])
        let starts = ["a1": nonce1 & low48, "a2": nonce1 & low48, "b1": nonce2 & low48]

        let pool = Cuckaroo29MockPoolState(loginJobs: [job1, job3])
        let mock = try MockPool { message, _ in pool.respond(message) }
        defer { mock.close() }

        let events = PoolEvents(
            share: { accepted, work, note in self.locked { () -> Void in self.shares.append((accepted, work, note)) } },
            hashrate: { rate in self.locked { () -> Void in self.rates.append((now(), rate)) } },
            log: { line in self.locked { () -> Void in self.logs.append(line) } })
        let login = "selftest-wallet/selftest"
        let start = now()
        let miner = try Cuckaroo29PoolMiner(gpu: gpu, endpoint: mock.endpoint, login: login, events: events)
        let setup = now() - start
        miner.rateInterval = 1
        miner.logCycles = true
        miner.counterStart = { starts[$0.id] }
        miner.corruptShare = { job in
            job.id == "b1" && self.locked { () -> Bool in self.corrupted.insert(job.id).inserted }
        }

        let finished = DispatchSemaphore(value: 0)
        let thread = Thread {
            do {
                try miner.run(shouldStop: { self.locked { self.stopping } })
            } catch {
                self.locked { () -> Void in self.failure = error }
            }
            finished.signal()
        }
        thread.start()
        var running = true
        defer {
            if running {
                locked { () -> Void in stopping = true }
                _ = finished.wait(timeout: .now() + 60)
            }
        }
        func wait(for what: String, seconds: Double, until done: () -> Bool) throws {
            let deadline = now() + seconds
            while !done() {
                if finished.wait(timeout: .now()) == .success {
                    running = false
                    let reason = locked { failure.map { "\($0)" } } ?? "no error"
                    throw MinerError("the miner stopped while waiting for \(what): \(reason)")
                }
                guard now() < deadline else { throw MinerError("no \(what) within \(Int(seconds)) s") }
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        var lines: [String] = []

        // 1. Login. Job a1 carries Tari proof 1's mining hash: the first graph is the block's own nonce.
        try wait(for: "share on job a1", seconds: 30) { pool.verdicts.contains { $0.job == "a1" } }
        let found1 = pool.verdicts.first(where: { $0.job == "a1" })!
        guard found1.accepted, found1.nonce == Cuckaroo29Stratum.nonceHex(nonce1), found1.pow == Cuckaroo29Reference.proof1Nonces,
              let difficulty1 = found1.difficulty else {
            throw MinerError("job a1: the first share was \(found1), not Tari proof 1 accepted")
        }
        lines.append("login, job a1 (Tari proof 1's mining hash \(header1.hex.prefix(8))..., extra nonce \(job1.extraNonce.hex),"
            + " difficulty 1): the GPU found proof 1 on the first graph (nonce \(found1.nonce)); the mock's CPU check"
            + " accepted it at difficulty \(difficulty1)")

        // 2. Difficulty change: job a2 is the same header at difficulty 1000. Proof 1 turns up again and stays home.
        mock.push(pool.announce(job1b))
        let held = Cuckaroo29PoolMiner.cycleName(nonce: nonce1, difficulty: difficulty1)
            + ": held back, below the share difficulty 1000"
        try wait(for: "proof 1 held back under job a2", seconds: 30) { self.locked { self.logs.contains(held) } }
        lines.append("difficulty change, job a2 (same header, target \(Cuckaroo29Stratum.target(difficulty: 1000))):"
            + " proof 1 found again and held back (\(difficulty1) < 1000)")

        // 3. New job b1 at the next height: Tari proof 2's mining hash. Its first share goes out corrupted on purpose.
        mock.push(pool.announce(job2))
        try wait(for: "share on job b1", seconds: 30) { pool.verdicts.contains { $0.job == "b1" } }
        let bad = pool.verdicts.first(where: { $0.job == "b1" })!
        guard !bad.accepted, bad.nonce == Cuckaroo29Stratum.nonceHex(nonce2), let reason = bad.note,
              reason.hasPrefix("Invalid proof") else {
            throw MinerError("job b1: the corrupted share got \(bad)")
        }
        try wait(for: "the miner's report of the refused share", seconds: 10) {
            self.locked { self.shares.contains { !$0.accepted } }
        }
        lines.append("new job b1 (Tari proof 2's mining hash \(header2.hex.prefix(8))..., next height, extra nonce"
            + " \(job2.extraNonce.hex)): the GPU found proof 2 at nonce \(bad.nonce); its corrupted copy was refused"
            + " by the mock (\(reason)) and reported as rejected")

        // 4. Random graphs on job b1 until one holds a 42-cycle: at difficulty 1 every 42-cycle is a share.
        let searching = now()
        try wait(for: "share from a random graph on job b1", seconds: 150) {
            pool.verdicts.contains { $0.job == "b1" && $0.accepted }
        }
        let lucky = pool.verdicts.first(where: { $0.job == "b1" && $0.accepted })!
        let graphsAfter = (UInt64(lucky.nonce, radix: 16) ?? nonce2) &- nonce2
        lines.append("random graphs on job b1: a share at nonce \(lucky.nonce), \(graphsAfter) graphs after proof 2"
            + " (\(fmt(now() - searching, 1)) s), difficulty \(lucky.difficulty ?? 0), accepted by the mock's CPU check")

        // 5. Reconnect request: the miner reconnects to its endpoint, logs in again (job c1, no extra nonce), mines on.
        mock.push(["jsonrpc": "2.0", "method": "client.reconnect", "params": ["127.0.0.1", Int(mock.port), 0]])
        try wait(for: "second login", seconds: 20) { pool.logins.count >= 2 }
        let relogin = pool.logins[1].time
        try wait(for: "rate report after the reconnect", seconds: 20) {
            self.locked { self.rates.contains { $0.time > relogin } }
        }
        lines.append("client.reconnect: the miner reconnected, logged in again (job c1, no extra nonce) and kept mining")

        locked { () -> Void in stopping = true }
        guard finished.wait(timeout: .now() + 30) == .success else { throw MinerError("the miner didn't stop within 30 s") }
        running = false
        if let failure = locked({ failure }) { throw MinerError("the miner failed: \(failure)") }

        let verdicts = pool.verdicts
        let reported = locked { shares }
        let refused = verdicts.filter { !$0.accepted }
        guard refused.count == 1 else { throw MinerError("the mock refused \(refused.count) shares: \(refused.map { $0.note ?? "" })") }
        guard !verdicts.contains(where: { $0.job == "a2" }) else { throw MinerError("a share went out for job a2 (difficulty 1000)") }
        guard reported.count >= 3, reported.count <= verdicts.count,
              zip(reported, verdicts).allSatisfy({ $0.accepted == $1.accepted }) else {
            throw MinerError("the miner reported \(reported.map { $0.accepted }), the mock decided \(verdicts.map { $0.accepted })")
        }
        guard reported.allSatisfy({ $0.work == 42 }) else {
            throw MinerError("share work \(reported.map { $0.work }), want 42 graphs (42 x difficulty 1)")
        }
        let first = pool.logins[0].params
        guard first["login"] as? String == login, first["pass"] as? String == "x", (first["agent"] as? String)?.isEmpty == false else {
            throw MinerError("login params \(Cuckaroo29Stratum.describe(first))")
        }
        guard pool.unknown.isEmpty else { throw MinerError("the miner sent methods the dialect lacks: \(pool.unknown)") }
        let rateValues = locked { rates.map { $0.rate } }.sorted()
        guard !rateValues.isEmpty, rateValues.allSatisfy({ $0 > 0 }) else { throw MinerError("rate reports \(rateValues)") }
        lines.append("\(verdicts.count) shares submitted (\(verdicts.count - 1) accepted, 1 refused); the miner's"
            + " \(reported.count) share reports match the mock's verdicts, each worth 42 graphs (42 x difficulty 1);"
            + " \(rateValues.count) rate reports, median \(fmt(rateValues[rateValues.count / 2])) G/s; solver setup"
            + " \(fmt(setup, 1)) s, round trip \(fmt(now() - start - setup, 1)) s")
        return lines
    }
}
