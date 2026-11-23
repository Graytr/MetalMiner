import Foundation

/// Ravencoin KawPow Stratum, as kawpowminer's client speaks it (its "stratum" mode, JSON-RPC 2.0) and MiningCore's
/// Progpow pool serves it:
///   mining.subscribe [agent] -> [[subscriptions], extranonce]   (extranonce: the nonce's first bytes; MiningCore uses 2)
///   mining.authorize [login, password] -> true
///   mining.set_target [target hex]                              (applies at once, as in kawpowminer)
///   mining.notify [job id, header hash, seed hash, target, clean, height, nbits]
///   mining.submit [login, job id, 0x nonce (16 digits), 0x header hash, 0x mix digest] -> true
/// Quai's KawPow pools serve the same messages: the work is a Ravencoin "donor" header, at the donor's height.
final class KawPowStratumDialect: EthashPoolDialect {
    let name = "KawPow stratum"
    private(set) var job: EthashPoolJob?
    private(set) var extranonce: [UInt8] = []
    private var target: [UInt8]?

    func login(_ connection: StratumConnection, login: String, log: (String) -> Void) throws {
        connection.requestFields = ["jsonrpc": "2.0"]
        let subscribed = try connection.call("mining.subscribe", params: [EthashPoolKit.agent], timeout: 15)
        if let error = stratumError(subscribed) { throw MinerError("mining.subscribe refused: \(error)") }
        if let result = subscribed["result"] as? [Any], result.count > 1 {
            extranonce = try EthashPoolValue.extranonce(result[1], maxBytes: 4)
        }
        let authorized = try connection.call("mining.authorize", params: [login, "x"], timeout: 15)
        if let error = stratumError(authorized) { throw PoolLoginRefused(login: login, reason: error) }
        if authorized["result"] as? Bool == false { throw PoolLoginRefused(login: login, reason: "mining.authorize returned false") }
        log("logged in with KawPow stratum, extranonce \(extranonce.isEmpty ? "none" : extranonce.hex)")
    }

    func handle(_ message: [String: Any], connection: StratumConnection, log: (String) -> Void) throws -> Bool {
        let params = message["params"] as? [Any] ?? []
        switch message["method"] as? String {
        case "mining.set_target"?:
            guard let target = (params.first as? String).flatMap(EthashTarget.parse) else {
                log("ignored mining.set_target \(EthashPoolKit.describe(params))")
                return true
            }
            self.target = target
            job?.target = target
            return true
        case "mining.set_difficulty"?:
            // kawpowminer doesn't read this; if a pool sends it, Ravencoin's difficulty 1 is MiningCore's.
            guard let difficulty = EthashPoolValue.double(params.first), difficulty > 0 else {
                log("ignored mining.set_difficulty \(EthashPoolKit.describe(params))")
                return true
            }
            let target = EthashTarget.fromDifficulty(difficulty, diff1: EthashTarget.ravencoinDiff1)
            self.target = target
            job?.target = target
            return true
        case "mining.notify"?:
            guard params.count >= 3, let id = EthashPoolValue.jobID(params[0]), let header = EthashPoolValue.hash(params[1]),
                  let seed = EthashPoolValue.hash(params[2]) else {
                log("ignored a malformed mining.notify")
                return true
            }
            let sent = params.count > 3 ? (params[3] as? String).flatMap(EthashTarget.parse) : nil
            guard let target = sent ?? target else {
                log("job \(id) came without a target; waiting for mining.set_target")
                return true
            }
            guard let height = params.count > 5 ? EthashPoolValue.int(params[5]) : nil else {
                log("job \(id) came without a block height, which KawPow needs; skipped")
                return true
            }
            job = EthashPoolJob(id: id, header: header, seed: seed, height: height, target: target, extranonce: extranonce)
            return true
        case "mining.set_extranonce"?:
            extranonce = try EthashPoolValue.extranonce(params.first, maxBytes: 4)
            log("extranonce now \(extranonce.isEmpty ? "none" : extranonce.hex)")
            return true
        default:
            return false
        }
    }

    func submit(_ solution: EthashPoolSolution, job: EthashPoolJob, login: String) -> [String: Any] {
        ["jsonrpc": "2.0", "method": "mining.submit",
         "params": [login, job.id, String(format: "0x%016llx", solution.nonce), "0x" + job.header.hex, "0x" + solution.mix.hex]]
    }

    func idle(_ connection: StratumConnection, log: (String) -> Void) throws {}
}

/// Real mining on Kryptex's KawPow pools: Ravencoin ("rvn") and Quai ("quai-kawpow"). Both speak the same KawPow
/// Stratum (Kryptex's own setup pages give the same plain kawpow miner settings for both).
final class KawPowPoolMiner: PoolMiner {
    static let pools = ["rvn", "quai-kawpow"]
    static let algorithm = KawPowRavencoin.id

    let session: EthashPoolSession

    init(gpu: GPU, endpoint: PoolEndpoint, login: String, events: PoolEvents) throws {
        session = EthashPoolSession(endpoint: endpoint, login: login, events: events, search: try KawPowJobSearch(gpu: gpu))
    }

    func run(shouldStop: () -> Bool) throws {
        try session.run(shouldStop: shouldStop) { endpoint in
            let connection = try EthashPoolKit.connect(endpoint)
            let dialect = KawPowStratumDialect()
            do {
                try dialect.login(connection, login: session.login, log: session.events.log)
            } catch {
                connection.close()
                throw error
            }
            return (connection, dialect)
        }
    }

    static func selfTest(gpu: GPU) throws -> [String] { try KawPowPoolTest.run(gpu: gpu) }

    /// Sends only mining.subscribe, reports the answer and whatever the pool pushes in the next 3 s (MiningCore-style
    /// pools send their target and a job before any login), and disconnects.
    static func handshake(endpoint: PoolEndpoint) throws -> String {
        let connection = try EthashPoolKit.connect(endpoint)
        defer { connection.close() }
        connection.requestFields = ["jsonrpc": "2.0"]
        let start = now()
        let reply = try connection.call("mining.subscribe", params: [EthashPoolKit.agent], timeout: 10)
        let ms = Int((now() - start) * 1000)
        var parts: [String] = []
        if let error = stratumError(reply) {
            parts.append("mining.subscribe refused in \(ms) ms: \(error)")
        } else {
            let result = reply["result"] as? [Any]
            let extranonce = (result?.count ?? 0) > 1 ? EthashPoolKit.describe(result?[1]) : "none"
            parts.append("mining.subscribe answered in \(ms) ms: \(EthashPoolKit.describe(reply["result"])) (extranonce \(extranonce))")
        }
        parts += EthashPoolKit.pushed(connection, seconds: 3)
        return parts.joined(separator: "; ")
    }
}

extension KawPowFamily {
    static let poolMiners: [PoolMiner.Type] = [KawPowPoolMiner.self]
}
