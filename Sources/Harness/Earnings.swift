import Foundation


/// One Kryptex pool's live economics, from its public API (pool.kryptex.com/api).
struct CoinEconomics: Codable {
    var pool: String              // Kryptex pool slug, e.g. "rvn", "quai-kawpow", "xtm-c29"
    var ticker: String
    var name: String
    var algorithm: String         // Kryptex's algorithm name
    var networkHashrate: Double   // per second, in the algorithm's unit
    var dailyEmission: Double     // coins per day (coin info; the pool's block_reward field can be stale)
    var poolEstimate: Double?     // Kryptex's estimated_profit_day: coins per day per unit/s (PPS+ pools only)
    var price: Double             // USD, last point of Kryptex's hourly price chart
    var fee: Double
    var feeType: String

    /// Coins per day per unit/s: Kryptex's own PPS+ estimate when it publishes one, otherwise our share of
    /// the network's daily emission after the pool fee (PROP pools).
    var coinsPerDayPerUnit: Double {
        if let poolEstimate { return poolEstimate }
        return networkHashrate > 0 ? dailyEmission / networkHashrate * (1 - fee) : 0
    }
    var usdPerDayPerUnit: Double { coinsPerDayPerUnit * price }
    var basis: String { poolEstimate == nil ? "share of daily emission" : "Kryptex PPS+ estimate" }
}

struct RankRow: Codable {
    var coin: String
    var pool: String
    var algorithm: String
    var unit: String
    /// Benchmarked rate after rebuild overhead.
    var rate: Double
    var networkShare: Double
    var usdPerDay: Double
    var watts: Double?
    var powerUsdPerDay: Double?
    var netUsdPerDay: Double?
    var economics: CoinEconomics
    /// Kryptex can pay this pool's earnings to a Kryptex account (its index's `directMining`); nil when not listed.
    var accountPayouts: Bool?
    var score: Double { netUsdPerDay ?? usdPerDay }
}

struct RankFile: Codable {
    var date: String
    var device: String
    var benchFile: String
    var kwhPrice: Double?
    var rows: [RankRow]
}

enum Earnings {
    /// Kryptex's algorithm name for each of our algorithm ids.
    static let kryptexAlgorithm: [String: String] = [
        "etchash": "Etchash", "ethash": "Ethash", "ethash-octa": "Ethash", "kawpow": "KawPow",
        "autolykos2": "Autolykos", "octopus": "Octopus", "pearlhash": "PearlHash", "xelishash": "Xelishash",
        "nexapow": "NexaPow", "cuckaroo29": "Cuckaroo29", "poseidon2": "Poseidon2",
    ]

    /// Ephemeral: nothing is cached on disk.
    static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        return URLSession(configuration: configuration)
    }()

    static func getJSON(_ path: String) throws -> Any {
        let url = URL(string: "https://pool.kryptex.com" + path)!
        var result: Result<Data, Error> = .failure(MinerError("no response from \(path)"))
        let done = DispatchSemaphore(value: 0)
        session.dataTask(with: url) { data, response, error in
            if let error {
                result = .failure(error)
            } else if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                result = .failure(MinerError("HTTP \(http.statusCode) for \(path)"))
            } else {
                result = .success(data ?? Data())
            }
            done.signal()
        }.resume()
        done.wait()
        return try JSONSerialization.jsonObject(with: try result.get())
    }

    /// Kryptex pool slugs mining `coins` with the Kryptex algorithm that matches our id.
    static func pools(algorithm id: String, coins: [String], index: [String: Any]) -> [String] {
        guard let algo = kryptexAlgorithm[id] else { return [] }
        let tickers = Set(coins.map { $0.lowercased() })
        return index.compactMap { slug, value in
            guard let pool = value as? [String: Any], let ticker = pool["ticker"] as? String,
                  pool["algo"] as? String == algo, tickers.contains(ticker) else { return nil }
            return slug
        }.sorted()
    }

    static func economics(pool: String) throws -> CoinEconomics {
        guard let info = try getJSON("/\(pool)/api/v1/pool/info") as? [String: Any] else { throw MinerError("bad pool info for \(pool)") }
        // Coin info and the price chart are keyed by pool slug ("quai-kawpow", "xtm-c29"), not ticker.
        let coin = try getJSON("/api/v1/coin/\(pool)/info") as? [String: Any] ?? [:]
        let chart = try getJSON("/api/v1/coin/\(pool)/price/chart") as? [[String: Any]] ?? []
        guard let price = (chart.last?["price"] as? NSNumber)?.doubleValue else { throw MinerError("no price for \(pool)") }
        func number(_ dictionary: [String: Any], _ key: String) -> Double? { (dictionary[key] as? NSNumber)?.doubleValue }
        let blockSeconds = number(info, "block_time") ?? 0
        let fallbackEmission = blockSeconds > 0 ? 86_400 / blockSeconds * (number(info, "block_reward") ?? 0) : 0
        return CoinEconomics(pool: pool, ticker: (info["ticker"] as? String ?? pool).uppercased(),
                             name: info["name"] as? String ?? pool, algorithm: info["algo"] as? String ?? "",
                             networkHashrate: number(info, "net_hashrate") ?? 0,
                             dailyEmission: number(coin, "daily_emission") ?? fallbackEmission,
                             poolEstimate: number(info, "estimated_profit_day"), price: price,
                             fee: number(info, "fee") ?? 0, feeType: info["fee_type"] as? String ?? "")
    }

    /// The newest results/bench-*.json.
    static func latestBench(root: URL) throws -> URL {
        let dir = root.appendingPathComponent("results")
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        guard let name = files.filter({ $0.hasPrefix("bench-") && $0.hasSuffix(".json") }).sorted().last else {
            throw MinerError("no results/bench-*.json yet; run a benchmark first")
        }
        return dir.appendingPathComponent(name)
    }

    /// Every (algorithm, coin) pair in a benchmark, valued with live Kryptex data, best first. With an electricity
    /// price the measured extra power is subtracted and the order follows net earnings: algorithms draw different
    /// power, so a close race can flip. Without one, electricity counts as free.
    static func rows(bench: BenchFile, kwh: Double?, note: (String) -> Void = { print("   (\($0))") }) throws -> [RankRow] {
        guard let index = try getJSON("/api/v1/index") as? [String: Any] else { throw MinerError("bad pool index") }
        var rows: [RankRow] = []
        for result in bench.results where result.error == nil && result.rate > 0 && !result.quick {
            let slugs = pools(algorithm: result.algorithm, coins: result.coins, index: index)
            if slugs.isEmpty { note("no Kryptex pool found for \(result.algorithm)") }
            for slug in slugs {
                do {
                    let e = try economics(pool: slug)
                    let effective = result.rate * (1 - (result.overhead ?? 0))   // after periodic rebuilds
                    let gross = effective * e.usdPerDayPerUnit
                    let watts = result.watts.map { w in max(0, w - (result.idleWatts ?? 0)) }
                    let power = kwh.flatMap { price in watts.map { $0 * 24 / 1000 * price } }
                    rows.append(RankRow(coin: e.ticker, pool: slug, algorithm: result.algorithm, unit: result.unit, rate: effective,
                                        networkShare: e.networkHashrate > 0 ? effective / e.networkHashrate : 0,
                                        usdPerDay: gross, watts: watts, powerUsdPerDay: power, netUsdPerDay: power.map { gross - $0 },
                                        economics: e,
                                        accountPayouts: (index[slug] as? [String: Any])?["directMining"] as? Bool))
                } catch {
                    note("skipped \(slug): \(error)")
                }
            }
        }
        return rows.sorted { $0.score > $1.score }
    }

    /// Prints the ranking for a benchmark file and saves results/rank-<time>.json.
    static func rank(benchFile: URL, kwh: Double?, root: URL, profitOnly: Bool = false) throws -> URL {
        let bench = try JSONDecoder().decode(BenchFile.self, from: Data(contentsOf: benchFile))
        let rows = try rows(bench: bench, kwh: kwh)

        func pad(_ s: String, _ n: Int) -> String { s.padding(toLength: max(n, s.count), withPad: " ", startingAt: 0) }
        func usd(_ x: Double) -> String { MinerFormat.usd(x) }
        print("\n" + pad("coin", 7) + pad("algorithm", 14) + pad("rate", 16) + pad("price", 12) + pad("$/day", 11)
              + pad("$/year", 11) + pad("watts", 8) + (kwh == nil ? "" : pad("power/day", 11) + "net $/day"))
        for r in rows {
            var line = pad(r.coin, 7) + pad(r.algorithm, 14) + pad(formatRate(r.rate, r.unit), 16) + pad(usd(r.economics.price), 12)
                + pad(usd(r.usdPerDay), 11) + pad(usd(r.usdPerDay * 365), 11) + pad(r.watts.map { String(format: "%.0f", $0) } ?? "-", 8)
            if let power = r.powerUsdPerDay, let net = r.netUsdPerDay {
                line += pad(usd(power), 11) + pad(usd(net), 10)
                if net < 0 { line += profitOnly ? "  loses money: would idle" : "  loses money" }
            }
            print(line)
        }
        if kwh == nil {
            print("(electricity free: gross earnings after pool fees. Save a price with `metalminer settings --kwh 0.12`.)")
        } else if profitOnly {
            if let best = rows.first, let net = best.netUsdPerDay, net > 0 {
                print("profit-only: would mine \(best.coin) (\(best.algorithm)), \(usd(net)) a day after power")
            } else {
                print("profit-only: nothing beats the power cost, so the miner would idle")
            }
        }

        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        let file = root.appendingPathComponent("results/rank-\(stamp.string(from: Date())).json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(RankFile(date: ISO8601DateFormatter().string(from: Date()), device: bench.device,
                                    benchFile: benchFile.lastPathComponent, kwhPrice: kwh, rows: rows)).write(to: file)
        return file
    }
}

