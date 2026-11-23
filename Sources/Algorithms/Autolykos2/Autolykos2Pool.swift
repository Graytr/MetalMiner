import Foundation

/// Real Ergo mining on Kryptex's ERG pool (slug "erg"), in the Stratum dialect of MiningCore's Ergo support and the
/// ErgoStratumServer (see docs/specs/autolykos2.md, "Pool protocol"):
///
///     > mining.subscribe [agent]            < [[subscriptions], extranonce1 hex, extranonce2 size]
///     > mining.authorize [login, "x"]       < true
///     < mining.set_difficulty [d]           < mining.notify [job, height, msg, "", "", version, b, ntime, clean]
///     > mining.submit [login, job, extranonce2 hex, ntime, nonce hex]   < true, or an error
///
/// The nonce is 8 bytes, big-endian: extranonce1, then the extranonce2 the miner counts. The share target is b from
/// the job (a decimal number; a share's hit is below it); a job without b gets it from the difficulty.
/// The offline round trip (selfTest) is in Autolykos2PoolTest.swift.
final class Autolykos2PoolMiner: PoolMiner {
    static let pools = ["erg"]
    static let algorithm = "autolykos2"
    static let agent = "metalminer/1.0"

    let gpu: GPU
    let endpoint: PoolEndpoint
    let login: String
    let events: PoolEvents
    /// Test settings (selfTest): the small --quick table, the nonces per GPU batch, and a hook that may replace a
    /// verified nonce just before it is submitted (to send a deliberately invalid share).
    var quick = false
    var batch = 1 << 22
    var replaceShare: ((UInt64) -> UInt64?)?

    private var autolykos: Autolykos2?
    private var loaded: Job?
    private var elements: (height: Int, table: Autolykos2Reference.Elements)?

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        self.gpu = gpu
        self.endpoint = endpoint
        self.login = login
        self.events = events
    }

    struct Job: Equatable {
        var id: String
        var height: Int
        var msg: [UInt8]
        /// The share target b, 32 big-endian bytes.
        var target: [UInt8]
        var ntime: String
        /// Counts clean jobs: shares found on an older generation are stale and dropped.
        var generation: Int
    }

    struct Reconnect {
        var host: String
        var port: UInt16
        var wait: Double
    }

    /// One connection's state.
    private final class Session {
        let host: String
        let port: UInt16
        var extranonce1: [UInt8] = []
        var nextExtranonce1: [UInt8]?
        var difficulty: Double?
        var job: Job?
        var generation = 0
        var counter: UInt64 = 0
        var exhausted = false
        var pending: [Int: Double] = [:]
        var nextID = 100
        init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
        /// Bits of nonce under extranonce1.
        var counterBits: Int { 64 - 8 * extranonce1.count }
        var prefix: UInt64 { extranonce1.reduce(UInt64(0)) { $0 << 8 | UInt64($1) } << UInt64(counterBits & 63) }
    }

    // MARK: Mining

    func run(shouldStop: () -> Bool) throws {
        var host = endpoint.host, port = endpoint.port
        while !shouldStop() {
            let connection = try StratumConnection(host: host, port: port, tls: endpoint.tls)
            let move: Reconnect?
            do {
                move = try mine(connection, Session(host: host, port: port), shouldStop: shouldStop)
            } catch {
                connection.close()
                throw error
            }
            connection.close()
            guard let move else { return }
            events.log("pool asked to reconnect to \(move.host):\(move.port) in \(Int(move.wait)) s")
            let resume = now() + move.wait
            while now() < resume {
                if shouldStop() { return }
                Thread.sleep(forTimeInterval: 0.1)
            }
            (host, port) = (move.host, move.port)
        }
    }

    private func logIn(_ connection: StratumConnection, _ session: Session) throws {
        let subscribe = try connection.call("mining.subscribe", params: [Self.agent])
        if let error = stratumError(subscribe) { throw MinerError("\(connection.label) refused mining.subscribe: \(error)") }
        guard let result = subscribe["result"] as? [Any], result.count >= 2, let hex = result[1] as? String,
              let extranonce1 = [UInt8](hex: hex), extranonce1.count < 8 else {
            throw MinerError("can't read the mining.subscribe reply: \(Self.json(subscribe))")
        }
        if result.count > 2, let size = Self.integer(result[2]), size != 8 - extranonce1.count {
            events.log("extranonce2 size \(size) doesn't fill the 8-byte nonce after extranonce1 \(hex); using \(8 - extranonce1.count)")
        }
        session.extranonce1 = extranonce1
        let authorize = try connection.call("mining.authorize", params: [login, "x"])
        guard Self.accepted(authorize) else {
            throw PoolLoginRefused(login: login, reason: stratumError(authorize) ?? "mining.authorize answered \(Self.json(authorize["result"] ?? NSNull()))")
        }
        events.log("logged in to \(connection.label) as \(login); extranonce1 \(hex), \(8 - extranonce1.count) bytes of nonce to search")
    }

    private func mine(_ connection: StratumConnection, _ session: Session, shouldStop: () -> Bool) throws -> Reconnect? {
        try logIn(connection, session)
        let deadline = now() + 60
        var lastReport = now()
        var hashes = 0.0
        while !shouldStop() {
            // Everything the pool sent since the last batch; wait a little when there is nothing to mine.
            var wait = session.job == nil || session.exhausted ? 0.2 : 0
            while let message = try connection.nextNotification(timeout: wait) {
                if let move = try handle(message, session, connection) { return move }
                wait = 0
            }
            guard let job = session.job, !session.exhausted else {
                if session.job == nil, now() > deadline { throw MinerError("no job from \(connection.label) within 60 s of logging in") }
                continue
            }
            let built = autolykos == nil
            let alg = try prepare(job)
            if built {   // the first job built the table: start the rate from here (later rebuilds count as mining time)
                lastReport = now()
                hashes = 0
            }
            let remaining = session.counterBits >= 64 ? UInt64.max : (UInt64(1) << UInt64(session.counterBits)) - session.counter
            let count = Int(min(UInt64(batch), remaining))
            let found = try alg.searchJob(start: session.prefix | session.counter, count: count)
            hashes += Double(count)
            session.counter += UInt64(count)
            if UInt64(count) == remaining {
                session.exhausted = true
                events.log("job \(job.id): every nonce under extranonce1 searched; waiting for the next job")
            }
            if found.hits > found.nonces.count { events.log("\(found.hits) hits in one batch; the first 62 are submitted") }
            // Replies and new jobs that arrived during the batch, then the shares (dropped if a clean job replaced theirs).
            while let message = try connection.nextNotification(timeout: 0) {
                if let move = try handle(message, session, connection) { return move }
            }
            for nonce in found.nonces {
                if session.generation != job.generation {
                    events.log("job \(job.id) was replaced by a clean job; share dropped")
                    continue
                }
                try submit(nonce, job: job, n: alg.n, session, connection)
            }
            if now() - lastReport >= 5 {
                events.hashrate(hashes / (now() - lastReport))
                hashes = 0
                lastReport = now()
            }
        }
        return nil
    }

    /// The GPU state for a job: the first job builds the table at its height, later heights rebuild it in place.
    private func prepare(_ job: Job) throws -> Autolykos2 {
        if let autolykos, loaded == job { return autolykos }
        if let autolykos {
            let seconds = try autolykos.setJob(msg: job.msg, height: job.height, target: job.target)
            if seconds > 0 { events.log("table rebuilt for height \(job.height): N \(autolykos.n), \(fmt(seconds, 2)) GPU s") }
            loaded = job
            return autolykos
        }
        events.log("building the Autolykos2 table for height \(job.height)…")
        let made = try Autolykos2(gpu: gpu, config: AlgoConfig(quick: quick, options: ["height": String(job.height)]))
        try made.setJob(msg: job.msg, height: job.height, target: job.target)
        events.log("table ready: \(made.setupSummary)")
        autolykos = made
        loaded = job
        return made
    }

    /// Checks a GPU hit with the CPU reference, then submits it.
    private func submit(_ nonce: UInt64, job: Job, n: Int, _ session: Session, _ connection: StratumConnection) throws {
        if elements?.height != job.height { elements = (job.height, Autolykos2Reference.Elements(height: UInt32(job.height))) }
        let trace = Autolykos2Reference.evaluate(msg: job.msg, nonce: Autolykos2.be64(nonce), n: n, element: elements!.table.element)
        guard Autolykos2Reference.less(trace.hit, job.target) else {
            events.log("GPU nonce \(Autolykos2.be64(nonce).hex) fails the CPU check (hit \(trace.hit.hex)); not submitted")
            return
        }
        let sent = replaceShare?(nonce) ?? nonce
        let bytes = Autolykos2.be64(sent)
        let ntime = job.ntime.isEmpty ? String(format: "%08x", UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))) : job.ntime
        let id = session.nextID
        session.nextID += 1
        session.pending[id] = Self.work(job.target)
        try connection.send(["id": id, "method": "mining.submit",
                             "params": [login, job.id, Array(bytes[session.extranonce1.count...]).hex, ntime, bytes.hex]])
    }

    /// One message from the pool. Returns where to reconnect when the pool asks for it.
    private func handle(_ message: [String: Any], _ session: Session, _ connection: StratumConnection) throws -> Reconnect? {
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.notify"?:
            notify(params, session)
        case "mining.set_difficulty"?:
            // Takes effect with the next job, which MiningCore sends right after it; b in the job wins anyway.
            if let d = Self.number(params.first), d > 0 { session.difficulty = d }
        case "mining.set_extranonce"?:
            if let hex = params.first as? String, let value = [UInt8](hex: hex), value.count < 8 { session.nextExtranonce1 = value }
        case "client.reconnect"?:
            let host = (params.first as? String).flatMap { $0.isEmpty ? nil : $0 } ?? session.host
            let port = params.count > 1 ? Self.integer(params[1]).flatMap { UInt16(exactly: $0) } : nil
            let wait = params.count > 2 ? Self.number(params[2]) ?? 0 : 0
            return Reconnect(host: host, port: port ?? session.port, wait: min(max(wait, 0), 600))
        case "client.show_message"?:
            events.log("pool says: \(params.first.map { "\($0)" } ?? "")")
        case "client.get_version"?:
            if let id = message["id"], !(id is NSNull) { try connection.send(["id": id, "result": Self.agent, "error": NSNull()]) }
        case nil:
            // A reply to a share.
            guard let id = Self.integer(message["id"]), let work = session.pending.removeValue(forKey: id) else { return nil }
            let ok = Self.accepted(message)
            events.share(ok, work, ok ? nil : stratumError(message) ?? "refused: \(Self.json(message))")
        default:
            break
        }
        return nil
    }

    private func notify(_ params: [Any], _ session: Session) {
        guard params.count >= 7, let id = Self.string(params[0]), let height = Self.integer(params[1]),
              height > 0, height <= Int(UInt32.max), let hex = params[2] as? String, let msg = [UInt8](hex: hex), msg.count == 32 else {
            events.log("ignored a mining.notify I can't read: \(Self.json(params))")
            return
        }
        guard let target = Self.shareTarget(b: Self.big(params[6]), difficulty: session.difficulty) else {
            events.log("job \(id) has neither a target b nor a difficulty; ignored")
            return
        }
        let ntime = params.count > 7 ? Self.string(params[7]) ?? "" : ""
        let clean = params.count > 8 ? Self.bool(params[8]) ?? false : false
        if clean { session.generation += 1 }
        var fresh = msg != session.job?.msg || height != session.job?.height
        if let next = session.nextExtranonce1 {
            session.extranonce1 = next
            session.nextExtranonce1 = nil
            fresh = true
        }
        if fresh {
            session.counter = 0
            session.exhausted = false
        }
        if target != session.job?.target {
            events.log("job \(id), height \(height): share target b = \(Autolykos2Reference.decimal(target))"
                       + " (\(Self.describeWork(Self.work(target))) hashes per share)")
        }
        session.job = Job(id: id, height: height, msg: msg, target: target, ntime: ntime, generation: session.generation)
    }

    // MARK: Numbers

    /// q, the secp256k1 group order Ergo divides by, and Bitcoin's difficulty-1 target 0xFFFF * 2^208 (MiningCore's Diff1).
    static let q = Autolykos2Reference.q
    static let diff1: [UInt8] = [0, 0, 0, 0, 0xff, 0xff] + [UInt8](repeating: 0, count: 26)

    /// The share target: b from the job when it has one; otherwise from the difficulty, read as hashes per share
    /// (b = q / d, Kryptex's 4,294,967,296) when it's 65,536 or more, else in Bitcoin units (b = Diff1 / d).
    static func shareTarget(b: [UInt8]?, difficulty: Double?) -> [UInt8]? {
        if let b, b.contains(where: { $0 != 0 }) { return b }
        guard let d = difficulty, d > 0, d.isFinite else { return nil }
        if d >= 65536 {
            if d < 0x1p63, d == d.rounded() { return Autolykos2Reference.divide(q, by: UInt64(d)) }
            return bytes(double(q) / d)
        }
        return bytes(double(diff1) / d)
    }

    /// Expected hashes per share at a target: 2^256 / b.
    static func work(_ target: [UInt8]) -> Double { 0x1p256 / max(double(target), 1) }

    static func describeWork(_ work: Double) -> String {
        work >= 1e15 ? String(format: "%.3g", work) : String(Int64(work.rounded()))
    }

    static func double(_ bytes: [UInt8]) -> Double { bytes.reduce(0.0) { $0 * 256 + Double($1) } }

    /// 2^k as 32 big-endian bytes.
    static func pow2(_ k: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        out[31 - k / 8] = 1 << UInt8(k % 8)
        return out
    }

    /// A non-negative double below 2^256 as 32 big-endian bytes (exact for its 53 significant bits).
    static func bytes(_ x: Double) -> [UInt8]? {
        guard x.isFinite, x >= 0, x < 0x1p256 else { return nil }
        var out = [UInt8](repeating: 0, count: 32)
        var rest = x
        for i in 0 ..< 32 {
            let scale = Double(sign: .plus, exponent: 8 * (31 - i), significand: 1)
            let digit = (rest / scale).rounded(.down)
            out[i] = UInt8(digit)
            rest -= digit * scale
        }
        return out
    }

    /// A 256-bit number from a pool: a decimal string (b), 0x-prefixed or bare hex, or a JSON number (approximate).
    static func big(_ value: Any?) -> [UInt8]? {
        if let text = value as? String {
            let s = text.trimmingCharacters(in: .whitespaces)
            if s.isEmpty { return nil }
            if s.hasPrefix("0x") || s.hasPrefix("0X") { return hexNumber(String(s.dropFirst(2))) }
            if s.allSatisfy({ ("0" ... "9").contains($0) }) { return decimalNumber(s) }
            return hexNumber(s)
        }
        if let number = value as? NSNumber { return bytes(number.doubleValue) }
        return nil
    }

    static func decimalNumber(_ s: String) -> [UInt8]? {
        var limbs = [UInt64](repeating: 0, count: 4)   // least significant first
        for ch in s {
            guard let digit = ch.wholeNumberValue else { return nil }
            var carry = UInt64(digit)
            for i in 0 ..< 4 {
                let (high, low) = limbs[i].multipliedFullWidth(by: 10)
                let (sum, overflow) = low.addingReportingOverflow(carry)
                limbs[i] = sum
                carry = high + (overflow ? 1 : 0)
            }
            if carry != 0 { return nil }
        }
        return (0 ..< 32).map { UInt8(truncatingIfNeeded: limbs[3 - $0 / 8] >> (56 - 8 * UInt64($0 % 8))) }
    }

    static func hexNumber(_ s: String) -> [UInt8]? {
        let digits = s.drop { $0 == "0" }
        guard digits.count <= 64, let bytes = [UInt8](hex: (digits.count % 2 == 1 ? "0" : "") + digits) else { return nil }
        return [UInt8](repeating: 0, count: 32 - bytes.count) + bytes
    }

    // MARK: JSON values

    static func integer(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) ?? (s.hasPrefix("0x") ? Int(s.dropFirst(2), radix: 16) : nil) }
        return nil
    }

    static func number(_ value: Any?) -> Double? {
        if let n = value as? NSNumber { return n.doubleValue }
        if let s = value as? String { return Double(s) }
        return nil
    }

    static func string(_ value: Any?) -> String? {
        if let s = value as? String { return s }
        if let n = value as? NSNumber { return n.stringValue }
        return nil
    }

    static func bool(_ value: Any?) -> Bool? {
        if let b = value as? Bool { return b }
        if let s = value as? String { return s.lowercased() == "true" }
        return nil
    }

    /// true, "true" or [true, ...] with no error.
    static func accepted(_ reply: [String: Any]) -> Bool {
        if stratumError(reply) != nil { return false }
        if let list = reply["result"] as? [Any] { return list.first.flatMap { bool($0) } ?? false }
        return bool(reply["result"]) ?? false
    }

    static func json(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject([value]),
              let data = try? JSONSerialization.data(withJSONObject: [value]), let text = String(data: data, encoding: .utf8) else {
            return "\(value)"
        }
        let inner = String(text.dropFirst().dropLast())
        return inner.count > 400 ? String(inner.prefix(400)) + "…" : inner
    }

    // MARK: Live check

    /// Connects to the real pool and sends mining.subscribe, the dialect's first message and not a login; reports the
    /// reply and anything else the pool sends within 3 s, then disconnects.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try StratumConnection(host: endpoint.host, port: endpoint.port, tls: endpoint.tls)
        defer { connection.close() }
        let reply = try connection.call("mining.subscribe", params: [agent], timeout: 10)
        var parts = ["mining.subscribe → \(json(reply))"]
        if let result = reply["result"] as? [Any], result.count >= 2, let hex = result[1] as? String {
            let size = result.count > 2 ? integer(result[2]).map { String($0) } ?? "?" : "?"
            parts.append("extranonce1 \(hex) (\(hex.count / 2) bytes), extranonce2 size \(size)")
        }
        var unsolicited: [String] = []
        let end = now() + 3
        do {
            while now() < end, let message = try connection.nextNotification(timeout: end - now()) { unsolicited.append(json(message)) }
        } catch {
            unsolicited.append("(connection closed: \(error))")
        }
        parts.append(unsolicited.isEmpty ? "nothing else within 3 s" : "then: " + unsolicited.joined(separator: " | "))
        return parts.joined(separator: "; ")
    }
}
