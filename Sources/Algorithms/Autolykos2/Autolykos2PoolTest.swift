import Foundation

/// The ERG pool miner's offline round trip against a MockPool (`metalminer pooltest erg`).
extension Autolykos2PoolMiner {
    /// The mock pool's side: jobs from real mainnet blocks, every share checked with the CPU reference.
    fileprivate final class Mock {
        typealias Ref = Autolykos2Reference
        struct MockJob {
            var header: Ref.Header
            var targets: [[UInt8]]
        }
        let lock = NSLock()
        let n: Int
        let extranonce1 = "c0de"
        var jobs: [String: MockJob] = [:]
        var current = "1"
        var phase = 0
        var logins = 0
        var accepted: [String: Int] = [:]          // per job
        var firstPhase = 0, hardShares = 0, softAfterChange = 0, staleAfterJob2 = 0
        var rejected: [(nonce: String, reason: String)] = []
        var seen = Set<String>()
        var wantInvalid = false
        var corrupted: String?
        var done = false
        var elements: [UInt32: Ref.Elements] = [:]
        var badLayout = 0

        init(n: Int) { self.n = n }

        func notify(_ id: String, clean: Bool) -> [String: Any] {
            let job = jobs[id]!
            return ["id": NSNull(), "method": "mining.notify",
                    "params": [id, Int(job.header.height), job.header.msg.hex, "", "", Int(job.header.version),
                               Ref.decimal(job.targets.last!), "", clean]]
        }

        func respond(_ message: [String: Any], _ pool: MockPool) -> [[String: Any]] {
            lock.lock()
            defer { lock.unlock() }
            let id = message["id"] ?? NSNull()
            let params = message["params"] as? [Any] ?? []
            switch message["method"] as? String {
            case "mining.subscribe"?:
                return [["id": id, "result": [[["mining.set_difficulty", "1"], ["mining.notify", "1"]], extranonce1, 6], "error": NSNull()]]
            case "mining.authorize"?:
                guard params.first as? String == "selftest/worker" else {
                    return [["id": id, "result": false, "error": [24, "unauthorized worker", NSNull()]]]
                }
                logins += 1
                return [["id": id, "result": true, "error": NSNull()],
                        ["id": NSNull(), "method": "mining.set_difficulty", "params": [1]], notify(current, clean: true)]
            case "mining.submit"?:
                return [submit(id, params, pool)]
            default:
                return [["id": id, "result": NSNull(), "error": [20, "unknown method", NSNull()]]]
            }
        }

        private func refuse(_ id: Any, _ nonce: String, _ code: Int, _ reason: String) -> [String: Any] {
            rejected.append((nonce, reason))
            return ["id": id, "result": NSNull(), "error": [code, reason, NSNull()]]
        }

        private func submit(_ id: Any, _ params: [Any], _ pool: MockPool) -> [String: Any] {
            guard params.count == 5, let jobID = params[1] as? String, let en2 = params[2] as? String,
                  let ntime = params[3] as? String, let nonceHex = params[4] as? String, let job = jobs[jobID] else {
                return refuse(id, "?", 21, "job not found or malformed submit")
            }
            guard nonceHex.count == 16, nonceHex.hasPrefix(extranonce1), String(nonceHex.dropFirst(4)) == en2, !ntime.isEmpty,
                  let nonce = [UInt8](hex: nonceHex) else {
                badLayout += 1
                return refuse(id, nonceHex, 20, "incorrect nonce layout")
            }
            guard seen.insert(jobID + nonceHex).inserted else { return refuse(id, nonceHex, 22, "duplicate share") }
            let height = job.header.height
            if elements[height] == nil { elements[height] = Ref.Elements(height: height) }
            let hit = Ref.evaluate(msg: job.header.msg, nonce: nonce, n: n, element: elements[height]!.element).hit
            guard job.targets.contains(where: { Ref.less(hit, $0) }) else {
                return refuse(id, nonceHex, 23, "low difficulty share")
            }
            let latest = Ref.less(hit, job.targets.last!)
            accepted[jobID, default: 0] += 1
            switch phase {
            case 0 where jobID == "1":
                firstPhase += 1
                if firstPhase >= 3 {
                    // Difficulty change: job 1 again with a 64 times harder b (as MiningCore re-sends a job on vardiff).
                    phase = 1
                    jobs["1"]!.targets.append(Autolykos2PoolMiner.pow2(231))
                    pool.push(["id": NSNull(), "method": "mining.set_difficulty", "params": [1]])
                    pool.push(notify("1", clean: false))
                }
            case 1 where jobID == "1":
                if latest { hardShares += 1 } else { softAfterChange += 1 }
                if hardShares >= 3 {
                    phase = 2
                    current = "2"
                    pool.push(notify("2", clean: true))
                }
            case 2 where jobID == "1", 3 where jobID == "1":
                staleAfterJob2 += 1
            case 2 where jobID == "2" && accepted["2"]! >= 3:
                phase = 3
                wantInvalid = true
            case 4 where jobID == "3":
                phase = 5
                done = true
            default:
                break
            }
            return ["id": id, "result": true, "error": NSNull()]
        }

        /// The miner's hook: once asked, the next verified share goes out with the low bit of its nonce flipped.
        func replace(_ nonce: UInt64) -> UInt64? {
            lock.lock()
            defer { lock.unlock() }
            guard wantInvalid else { return nil }
            wantInvalid = false
            corrupted = Autolykos2.be64(nonce ^ 1).hex
            return nonce ^ 1
        }

        /// After the invalid share's refusal: ask the miner to reconnect, then mine job 3 on the new connection.
        func afterRefusal(_ pool: MockPool) {
            lock.lock()
            defer { lock.unlock() }
            guard phase == 3, rejected.contains(where: { $0.nonce == corrupted }) else { return }
            phase = 4
            current = "3"
            pool.push(["id": NSNull(), "method": "client.reconnect", "params": ["127.0.0.1", Int(pool.port), 0]])
        }
    }

    static func selfTest(gpu: GPU) throws -> [String] {
        typealias Ref = Autolykos2Reference
        let mock = Mock(n: Autolykos2.quickN)
        // Real mainnet blocks: job 1 = 1,920,429, job 2 = 1,000,000, job 3 (after the reconnect) = 417,792.
        mock.jobs = ["1": Mock.MockJob(header: Ref.mainnet[2].header, targets: [pow2(237)]),
                     "2": Mock.MockJob(header: Ref.mainnet[1].header, targets: [pow2(236)]),
                     "3": Mock.MockJob(header: Ref.mainnet[0].header, targets: [pow2(231)])]
        let pool = try MockPool { message, pool in
            let replies = mock.respond(message, pool)
            if message["method"] as? String == "mining.submit" {
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { mock.afterRefusal(pool) }
            }
            return replies
        }
        defer { pool.close() }

        // A login the pool doesn't know is refused with PoolLoginRefused, so the engine stops retrying it.
        let stranger = try Autolykos2PoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "nobody/worker", events: PoolEvents())
        var refusal = "no refusal"
        let t0 = now()
        do {
            try stranger.run(shouldStop: { now() - t0 > 10 })
        } catch let error as PoolLoginRefused {
            refusal = error.reason
        }
        guard refusal.contains("unauthorized") else { throw MinerError("an unknown login wasn't refused as PoolLoginRefused: \(refusal)") }

        var accepted = 0, rejected: [String] = [], rates: [Double] = [], logs: [String] = []
        let events = PoolEvents(share: { ok, _, note in if ok { accepted += 1 } else { rejected.append(note ?? "") } },
                                hashrate: { rates.append($0) }, log: { logs.append($0) })
        let miner = try Autolykos2PoolMiner(gpu: gpu, endpoint: pool.endpoint, login: "selftest/worker", events: events)
        miner.quick = true
        miner.batch = 1 << 20
        miner.replaceShare = { mock.replace($0) }
        let started = now()
        var finished: Double?
        try miner.run(shouldStop: {
            mock.lock.lock()
            let done = mock.done
            mock.lock.unlock()
            if done, finished == nil { finished = now() }
            return (finished.map { now() - $0 > 0.2 } ?? false) || now() - started > 120
        })
        let seconds = now() - started

        mock.lock.lock()
        defer { mock.lock.unlock() }
        guard mock.done else {
            throw MinerError("stalled in phase \(mock.phase) after \(Int(seconds)) s: accepted \(mock.accepted), refused \(mock.rejected.map { $0.reason }); miner log: \(logs.suffix(4))")
        }
        guard mock.badLayout == 0 else { throw MinerError("\(mock.badLayout) shares had a wrong nonce layout") }
        guard mock.rejected.count == 1, let refused = mock.rejected.first, refused.nonce == mock.corrupted else {
            throw MinerError("the mock refused \(mock.rejected.map { "\($0.nonce): \($0.reason)" }), expected only the corrupted share")
        }
        guard rejected.count == 1, rejected[0].contains("low difficulty") else { throw MinerError("the miner reported refusals \(rejected)") }
        guard mock.softAfterChange <= 24, mock.staleAfterJob2 <= 24 else {
            throw MinerError("\(mock.softAfterChange) shares at the old b after the change, \(mock.staleAfterJob2) for job 1 after job 2: the miner didn't switch")
        }
        guard mock.logins == 2 else { throw MinerError("expected one reconnect, saw \(mock.logins) logins") }
        let total = mock.accepted.values.reduce(0, +)
        guard accepted >= 10, accepted <= total else { throw MinerError("miner counted \(accepted) accepted shares, the mock \(total)") }
        let rate = rates.max().map { " · \(formatRate($0, "H/s"))" } ?? ""
        return [
            "unknown login: mining.authorize refused (\(refusal)) → PoolLoginRefused",
            "login: mining.subscribe gave extranonce1 c0de and 6 bytes of extranonce2; mining.authorize accepted",
            "job 1 = mainnet block 1,920,429 (its msg and height; quick table N \(Autolykos2.quickN)), b = 2^237: \(mock.firstPhase) shares"
                + " found on the GPU, each recomputed by the mock with the CPU reference (hit < b) and accepted",
            "difficulty change (job 1 re-sent with b = 2^231, 64x harder): \(mock.hardShares) shares below the new b,"
                + " \(mock.softAfterChange) in flight at the old one",
            "new clean job 2 = block 1,000,000 (table rebuilt for that height): \(mock.accepted["2"] ?? 0) shares accepted",
            "invalid share (a found nonce with its low bit flipped, \(refused.nonce)) refused by the mock: \(refused.reason); the miner reported it rejected",
            "client.reconnect: the miner reconnected, logged in again and got \(mock.accepted["3"] ?? 0) share(s) accepted on job 3 = block 417,792",
            "every nonce was extranonce1 + extranonce2 (8 bytes, big-endian); miner counted \(accepted) accepted, 1 rejected"
                + " in \(fmt(seconds, 1)) s\(rate)",
        ]
    }
}
