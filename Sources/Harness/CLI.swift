import Foundation

/// The `metalminer` command line, exposed so the thin executable in Sources/CLI only needs MinerCore's public API.
public func runCommandLine(_ args: [String]) -> Int32 {
    do {
        return try CLI.run(args)
    } catch {
        FileHandle.standardError.write(Data("error: \(error)\n".utf8))
        return 1
    }
}

enum CLI {
    static let usage = """
    metalminer: Metal proof-of-work benchmarks for Apple GPUs

      metalminer info                           GPUs, memory limits, current system power
      metalminer list                           algorithms built into this binary
      metalminer power [SECONDS]                chip power by channel (CPU, GPU, DRAM) from its energy counters
      metalminer pooltest [pool ...|all]        each pool miner against a local test pool: jobs in, shares out
      metalminer handshake [pool ...|all]       connect to the real Kryptex pools without logging in
      metalminer mine <pool> [--seconds N] [--shares N] [--quiet yes|no] [--region R] [--tcp] [--trace]   real mining with the saved payout login
      metalminer test  <id ...|all> [--quick]   known-answer vectors, then GPU vs CPU cross-check
      metalminer bench <id ...|all> [--seconds N] [--cooldown N] [--quick] [--set key=value ...] [--merge] [--no-save]
      metalminer rank  [--kwh PRICE] [--bench results/bench-....json]
      metalminer settings [--kwh PRICE] [--profit-only yes|no] [--quiet yes|no] [--payout kryptex|wallets]
                          [--kryptex-user NAME] [--wallet COIN=ADDRESS ...] [--worker NAME]

      --quick         small test-sized parameters: fast setup, rates not comparable to mainnet
      --seconds N     timed run per algorithm (default 20)
      --cooldown N    idle seconds before each algorithm after the first, so heat doesn't carry over
      --set k=v       algorithm option, e.g. --set epoch=433 (see the algorithm's docs/specs note)
      --merge         save these results together with the newest bench file's other algorithms
      --no-save       don't write results/bench-*.json
      --kwh PRICE     electricity price per kWh (USD). 0 = free, the default. With `settings` it's saved;
                      with `rank` it applies to that ranking only.
      --profit-only   mine only while earnings beat the power cost
      --quiet yes|no  quiet mode: mine more slowly so the fans stay near their slowest speed (settings saves it;
                      mine follows the saved choice unless given)
      --payout        kryptex: one Kryptex username for every coin, paid out in BTC or USDT
                      wallets: your own wallet per coin, paid in that coin (coins without one are skipped)
      --kryptex-user  your Kryptex username
      --wallet C=A    your wallet address A for coin C (e.g. --wallet RVN=R...); C= removes it
      --worker NAME   worker name shown on the pool (default metalminer)
      --bench FILE    benchmark file to rank (default: the newest results/bench-*.json)
      --trace         print every line sent to and received from the pool (mine, handshake, pooltest)
      --shares N      (mine) stop after N accepted shares, or after --seconds, whichever comes first
    """

    static func run(_ args: [String]) throws -> Int32 {
        guard let command = args.first else {
            print(usage)
            return 0
        }
        var rest = Array(args.dropFirst())
        var config = AlgoConfig()
        var seconds = 20.0
        var cooldown = 0.0
        var save = true
        var merge = false
        var kwh: Double?
        var profitOnly: Bool?
        var quiet: Bool?
        var payout: PayoutMode?
        var kryptexUser: String?
        var worker: String?
        var walletChanges: [(String, String)] = []
        var benchPath: String?
        var region: String?
        var useTCP = false
        var shareLimit = 0
        var targets: [String] = []
        func value(_ flag: String) throws -> String {
            guard let v = rest.first else { throw MinerError("\(flag) needs a value") }
            rest.removeFirst()
            return v
        }
        while !rest.isEmpty {
            let arg = rest.removeFirst()
            switch arg {
            case "--quick":
                config.quick = true
            case "--seconds":
                guard let v = Double(try value(arg)) else { throw MinerError("--seconds needs a number") }
                seconds = v
            case "--cooldown":
                guard let v = Double(try value(arg)) else { throw MinerError("--cooldown needs a number") }
                cooldown = v
            case "--kwh":
                guard let v = Double(try value(arg)), v >= 0 else { throw MinerError("--kwh needs a price of 0 or more") }
                kwh = v
            case "--profit-only":
                switch try value(arg).lowercased() {
                case "yes", "on", "true": profitOnly = true
                case "no", "off", "false": profitOnly = false
                default: throw MinerError("--profit-only takes yes or no")
                }
            case "--quiet":
                switch try value(arg).lowercased() {
                case "yes", "on", "true": quiet = true
                case "no", "off", "false": quiet = false
                default: throw MinerError("--quiet takes yes or no")
                }
            case "--payout":
                switch try value(arg).lowercased() {
                case "kryptex", "account", "kryptexaccount": payout = .kryptexAccount
                case "wallets", "wallet", "ownwallets": payout = .ownWallets
                default: throw MinerError("--payout takes kryptex or wallets")
                }
            case "--kryptex-user":
                kryptexUser = try value(arg)
            case "--worker":
                worker = try value(arg)
            case "--wallet":
                let pair = try value(arg)
                guard let eq = pair.firstIndex(of: "=") else { throw MinerError("--wallet needs COIN=ADDRESS") }
                walletChanges.append((String(pair[..<eq]).uppercased(), String(pair[pair.index(after: eq)...])))
            case "--region":
                region = try value(arg)
            case "--tcp":
                useTCP = true
            case "--shares":
                let text = try value(arg)
                guard let n = Int(text), n > 0 else { throw MinerError("--shares needs a positive number, not \(text)") }
                shareLimit = n
            case "--trace":
                StratumConnection.printTraffic = true
            case "--bench":
                benchPath = try value(arg)
            case "--set":
                let pair = try value(arg)
                guard let eq = pair.firstIndex(of: "=") else { throw MinerError("--set needs key=value") }
                config.options[String(pair[..<eq])] = String(pair[pair.index(after: eq)...])
            case "--merge":
                merge = true
            case "--no-save":
                save = false
            default:
                targets.append(arg)
            }
        }

        switch command {
        case "info":
            print(try GPU().info)
            let devices = GPU.allDevices()
            print("GPUs macOS exposes (\(devices.count)):")
            for device in devices { print("  \(device)") }
            if let reading = EnergyMeter.shared?.measure(seconds: 1) { print(String(format: "GPU power now: %.1f W", reading.gpuWatts)) }
            return 0
        case "stratumtest":
            // The Stratum layer against a local test pool: a call and its reply, an error reply, the ways pools say "no
            // error", a reply that echoes its method, a pool request that reuses a pending call's id, pushed notifications.
            let mock = try MockPool { message, pool in
                let id = message["id"] ?? NSNull()
                switch message["method"] as? String {
                case "ping"?:
                    pool.push(["id": NSNull(), "method": "mining.notify", "params": ["job-1"]])
                    return [["id": id, "result": "pong", "error": NSNull()]]
                case "blank"?:
                    return [["id": id, "result": true, "error": ""]]
                case "falsy"?:
                    return [["id": id, "result": true, "error": false]]
                case "echo"?:
                    return [["id": id, "method": "echo", "result": true, "error": NSNull()]]
                case "ask"?:
                    // A request from the pool that reuses the pending call's id, then the real reply.
                    return [["id": id, "method": "client.get_version", "params": [] as [Any]], ["id": id, "result": "answer", "error": NSNull()]]
                default:
                    return [["id": id, "result": NSNull(), "error": [21, "unknown method", NSNull()]]]
                }
            }
            let connection = try StratumConnection(host: "127.0.0.1", port: mock.port, tls: false)
            let pong = try connection.call("ping", params: [])
            guard pong["result"] as? String == "pong", stratumError(pong) == nil else { throw MinerError("bad reply \(pong)") }
            let refused = try connection.call("nope", params: [])
            guard stratumError(refused) == "21 unknown method <null>" else { throw MinerError("bad error reply \(refused)") }
            for method in ["blank", "falsy", "echo"] {
                let reply = try connection.call(method, params: [], timeout: 5)
                guard reply["result"] as? Bool == true, stratumError(reply) == nil else { throw MinerError("\(method): bad reply \(reply)") }
            }
            let answer = try connection.call("ask", params: [], timeout: 5)
            guard answer["result"] as? String == "answer" else { throw MinerError("ask: bad reply \(answer)") }
            var pushed: [String] = []
            while let message = try connection.nextNotification(timeout: 1) { pushed.append(message["method"] as? String ?? "?") }
            guard pushed.sorted() == ["client.get_version", "mining.notify"] else { throw MinerError("notifications \(pushed)") }
            connection.close()
            mock.close()
            print("stratum layer ok: call/reply, error reply, \"\" and false as no error, a reply echoing its method,"
                + " a pool request reusing a call's id, pushed notifications")
            return 0
        case "pooltest":
            let gpu = try GPU()
            let miners = poolMiners(targets)
            if miners.isEmpty { print("(no pool miners built in yet)") }
            var failures = 0
            for type in miners {
                print("== \(type.pools.joined(separator: ", "))  (\(type.algorithm))")
                do {
                    for line in try type.selfTest(gpu: gpu) { print("   \(line)") }
                    print("   PASS")
                } catch {
                    print("   FAIL    \(error)")
                    failures += 1
                }
            }
            return failures == 0 ? 0 : 1
        case "handshake":
            for type in poolMiners(targets) {
                for pool in type.pools {
                    do {
                        let endpoint = try PoolEndpoint.kryptex(pool: pool, region: region ?? "Global", tls: !useTCP)
                        print("== \(pool) at \(endpoint): \(try type.handshake(endpoint: endpoint))")
                    } catch {
                        print("== \(pool): FAIL \(error)")
                    }
                }
            }
            return 0
        case "mine":
            guard let pool = targets.first, let type = Registry.poolMiner(for: pool) else {
                throw MinerError("mine needs a pool that has a pool miner: \(Registry.poolMiners.flatMap { $0.pools }.joined(separator: ", "))")
            }
            let coin = String(pool.split(separator: "-").first ?? Substring(pool)).uppercased()
            let saved = try MinerSettings.load(root: try MinerPaths.data())
            guard let login = saved.login(coin: coin) else {
                throw MinerError("no payout set for \(coin): metalminer settings --payout kryptex --kryptex-user NAME, or --payout wallets --wallet \(coin)=ADDRESS")
            }
            let endpoint = try PoolEndpoint.kryptex(pool: pool, region: region ?? "Global", tls: !useTCP)
            let unit = Registry.all.first { $0.id == type.algorithm }?.unit ?? "H/s"
            let counts = NSLock()
            var accepted = 0, rejected = 0
            let events = PoolEvents(
                share: { ok, _, note in
                    counts.lock()
                    if ok { accepted += 1 } else { rejected += 1 }
                    counts.unlock()
                    print("   share \(ok ? "accepted" : "REJECTED")" + (note.map { ": \($0)" } ?? ""))
                },
                hashrate: { print("   rate \(formatRate($0, unit))") },
                log: { print("   \($0)") })
            print("mining \(pool) at \(endpoint) as \(login) for \(Int(seconds)) s")
            let miner = try type.init(gpu: try GPU(), endpoint: endpoint, login: login, events: events)
            let end = now() + seconds
            let quietMonitor = (quiet ?? saved.quietMode) ? QuietMonitor.start(log: { print("   \($0)") }) : nil
            defer { quietMonitor?.stop() }
            try miner.run(shouldStop: {
                counts.lock()
                defer { counts.unlock() }
                return now() > end || (shareLimit > 0 && accepted >= shareLimit)
            })
            print("accepted \(accepted), rejected \(rejected)")
            return rejected == 0 ? 0 : 1
        case "power":
            guard let meter = EnergyMeter.shared else {
                print("the chip's energy counters (IOReport) aren't available on this Mac")
                return 1
            }
            guard let reading = meter.measure(seconds: Double(targets.first ?? "") ?? 3) else { throw MinerError("no energy reading") }
            for (name, joules) in reading.joules.sorted(by: { $0.value > $1.value }) {
                print("  " + name.padding(toLength: 26, withPad: " ", startingAt: 0) + String(format: "%7.2f W", joules / reading.seconds))
            }
            print(String(format: "chip %.2f W (GPU %.2f W) over %.1f s", reading.totalWatts, reading.gpuWatts, reading.seconds))
            if !reading.skipped.isEmpty { print("channels in other units: " + reading.skipped.sorted { $0.key < $1.key }.map { "\($0.key) [\($0.value)]" }.joined(separator: ", ")) }
            return 0
        case "list":
            if Registry.all.isEmpty { print("(no algorithms built in; see ./build.sh)") }
            for type in Registry.all {
                print(type.id.padding(toLength: 18, withPad: " ", startingAt: 0) + type.coins.joined(separator: ", ") + "  [\(type.unit)]")
            }
            return 0
        case "test":
            let gpu = try GPU()
            var failures = 0
            for type in try select(targets) {
                if !Bench.test(type, gpu: gpu, config: config) { failures += 1 }
            }
            return failures == 0 ? 0 : 1
        case "bench":
            let gpu = try GPU()
            print(gpu.info)
            // Let earlier GPU work wind down, then read the GPU's idle draw from its energy counter.
            Thread.sleep(forTimeInterval: 5)
            let idle = EnergyMeter.shared?.measure(seconds: 3)?.gpuWatts
            if let idle { print(String(format: "idle GPU power: %.1f W", idle)) }
            var results: [BenchResult] = []
            for (i, type) in try select(targets).enumerated() {
                if i > 0, cooldown > 0 {
                    print("   (cooling down \(Int(cooldown)) s)")
                    Thread.sleep(forTimeInterval: cooldown)
                }
                results.append(Bench.bench(type, gpu: gpu, config: config, seconds: seconds, idleWatts: idle))
            }
            Bench.printTable(results)
            if save {
                var combined = results
                if merge, let latest = try? Earnings.latestBench(root: gpu.dataDirectory),
                   let previous = try? JSONDecoder().decode(BenchFile.self, from: Data(contentsOf: latest)) {
                    let fresh = Set(results.map(\.algorithm))
                    combined = previous.results.filter { !fresh.contains($0.algorithm) } + results
                    print("merged with \(latest.lastPathComponent)")
                }
                print("saved \(try Bench.save(combined, gpu: gpu).path)")
            }
            return results.contains { $0.error != nil } ? 1 : 0
        case "rank":
            let root = try MinerPaths.data()
            let settings = try MinerSettings.load(root: root)
            let price = kwh ?? settings.electricityPricePerKWh
            let file = try benchPath.map { URL(fileURLWithPath: $0) } ?? Earnings.latestBench(root: root)
            print("ranking \(file.lastPathComponent) with live Kryptex pool data · electricity "
                  + (price > 0 ? String(format: "$%.4g per kWh", price) : "free"))
            let saved = try Earnings.rank(benchFile: file, kwh: price > 0 ? price : nil, root: root,
                                          profitOnly: settings.mineOnlyWhenProfitable)
            print("saved \(saved.path)")
            return 0
        case "settings":
            let root = try MinerPaths.data()
            var settings = try MinerSettings.load(root: root)
            let before = settings
            if let kwh { settings.electricityPricePerKWh = kwh }
            if let profitOnly { settings.mineOnlyWhenProfitable = profitOnly }
            if let quiet { settings.quietMode = quiet }
            if let payout { settings.payoutMode = payout }
            if let kryptexUser { settings.kryptexUsername = kryptexUser }
            if let worker { settings.workerName = worker }
            for (coin, address) in walletChanges { settings.wallets[coin] = address.isEmpty ? nil : address }
            if settings != before { try settings.save(root: root) }
            print("\(settings.summary)\n(\(MinerSettings.url(root: root).path))")
            return 0
        default:
            print(usage)
            return 2
        }
    }

    /// Pool miners matching pool slugs or algorithm ids (all of them for none or "all").
    static func poolMiners(_ targets: [String]) -> [PoolMiner.Type] {
        if targets.isEmpty || targets == ["all"] { return Registry.poolMiners }
        return Registry.poolMiners.filter { type in targets.contains { type.pools.contains($0) || type.algorithm == $0 } }
    }

    static func select(_ targets: [String]) throws -> [MiningAlgorithm.Type] {
        if targets.isEmpty || targets == ["all"] { return Registry.all }
        return try targets.map { id in
            guard let type = Registry.all.first(where: { $0.id == id.lowercased() }) else {
                throw MinerError("unknown algorithm \(id); built in: \(Registry.all.map { $0.id }.joined(separator: ", "))")
            }
            return type
        }
    }
}
