import Foundation
import Metal

// The whole interface front-ends (the Mac app, a future web view) see. Nothing here names an algorithm,
// a coin or a GPU model: those come from the plug-in folders, the device list and Kryptex at runtime.

/// A compute device the engine can mine on.
public struct DeviceSummary: Identifiable, Hashable, Sendable {
    public let id: UInt64
    public let name: String
    public let detail: String
}

/// One coin the engine could mine now: the benchmarked rate valued with live pool data.
public struct CoinOption: Identifiable, Hashable, Sendable {
    public var id: String { pool }
    public let coin: String
    public let pool: String
    public let algorithm: String
    public let unit: String
    /// Benchmarked rate, after periodic rebuild overhead.
    public let rate: Double
    /// Gross USD per day after the pool fee.
    public let usdPerDay: Double
    /// Extra GPU watts while mining it, when measured.
    public let watts: Double?
    /// USD per day after electricity, when a price is set and watts were measured.
    public let netUsdPerDay: Double?
    public let price: Double
    /// The settings say where to pay this coin: a wallet for it, or a Kryptex account if Kryptex pays it to accounts.
    public let payoutReady: Bool
    /// Kryptex can pay this coin to a Kryptex account; when false, it needs the user's own wallet.
    public let accountPayouts: Bool
    /// This build has a pool connection for it (a pool miner for its pool).
    public let hasPoolConnection: Bool
    /// The pool's reason, when it refused this coin's login; the engine won't mine the coin until the payout settings
    /// change.
    public let loginRefused: String?
    /// What the engine compares: net when electricity has a price, otherwise gross.
    public var score: Double { netUsdPerDay ?? usdPerDay }
    /// The engine can mine it: a pool connection, somewhere to pay it, and a login the pool hasn't refused.
    public var canMine: Bool { hasPoolConnection && payoutReady && loginRefused == nil }
}

public enum EngineState: Equatable, Sendable {
    case idle
    case benchmarking(String)
    case preparing(String)
    case mining
    case waiting(String)
    case failed(String)

    public var label: String {
        switch self {
        case .idle: return "Stopped"
        case .benchmarking(let what): return "Benchmarking \(what)"
        case .preparing(let what): return "Preparing \(what)"
        case .mining: return "Mining"
        case .waiting(let why): return "Waiting: \(why)"
        case .failed(let why): return "Stopped: \(why)"
        }
    }

    public var isBusy: Bool {
        switch self {
        case .idle, .failed: return false
        default: return true
        }
    }
}

public struct WorkerStatus: Identifiable, Sendable {
    public var id: UInt64 { device.id }
    public let device: DeviceSummary
    public var option: CoinOption?
    /// Live rate, smoothed over a few seconds.
    public var hashrate: Double
    /// Shares the pool accepted and rejected since this coin started (real mining only).
    public var accepted = 0
    public var rejected = 0
}

public struct EarningsRow: Codable, Identifiable, Hashable, Sendable {
    public var id: String { "\(algorithm)/\(coin)" }
    public let algorithm: String
    public let coin: String
    public var seconds: Double
    public var estimatedUSD: Double
    public var acceptedShares: Int
}

public struct EngineSnapshot: Sendable {
    public var state: EngineState = .idle
    public var workers: [WorkerStatus] = []
    /// Best first.
    public var options: [CoinOption] = []
    /// Earnings: accepted shares, valued at the prices of the time.
    public var earnings: [EarningsRow] = []
    public var benchmarkDate: Date?
    public var lastPriceCheck: Date?
    /// GPU power now, from its energy counter (while mining).
    public var gpuWatts: Double?
    /// Fan speeds in RPM, when the Mac reports them (while mining).
    public var fanRPM: [Double] = []
    /// While quiet mode holds the GPU back: the power it's held near, in watts.
    public var quietWatts: Double?
    public var message: String?

    public init() {}
}

/// Formatting shared by front-ends.
public enum MinerFormat {
    public static func rate(_ value: Double, _ unit: String) -> String { formatRate(value, unit) }
    public static func usd(_ value: Double) -> String {
        if value != 0, value.magnitude < 0.0001 { return String(format: "$%.2g", value) }   // e.g. NEXA at $0.000003
        return String(format: value.magnitude < 0.01 && value != 0 ? "$%.4f" : "$%.2f", value)
    }
}

/// Runs the miner: benchmarks, prices, picking and switching coins, pool mining, and the earnings ledger. Thread-safe;
/// blocking calls (`refreshPrices`, `runBenchmarks`) belong off the main thread, and `onChange` fires on the engine's
/// own threads.
public final class MinerEngine: @unchecked Sendable {
    public var onChange: (@Sendable (EngineSnapshot) -> Void)?
    /// How often prices are re-checked while mining.
    public var checkInterval: TimeInterval = 600
    /// How much better (as a fraction) another coin must score before switching to it.
    public var switchMargin = 0.10

    let root: URL
    private let lock = NSLock()
    private var snap = EngineSnapshot()
    private var currentSettings: MinerSettings
    private var rows: [RankRow] = []
    private var running = false
    private var stopFlag = false
    private var switchFlag = false
    private var active: CoinOption?
    /// Pool slug -> the pool's reason, for logins refused since the settings last changed.
    private var refusedLogins: [String: String] = [:]
    /// Quiet mode's controller; the monitor thread ticks it while mining.
    private let quiet = QuietController()
    private var ledger: [String: EarningsRow] = [:]

    public init() throws {
        root = try MinerPaths.data()
        currentSettings = try MinerSettings.load(root: root)
        ledger = Self.loadLedger(at: root.appendingPathComponent("results/ledger.json"))
        snap.earnings = Self.sorted(ledger)
        snap.workers = Self.deviceSummaries().map { WorkerStatus(device: $0, option: nil, hashrate: 0) }
        snap.benchmarkDate = (try? Earnings.latestBench(root: root)).flatMap(Self.benchDate)
    }

    // MARK: State

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    public var snapshot: EngineSnapshot { locked { snap } }
    public var settings: MinerSettings { locked { currentSettings } }

    private func publish(_ change: (inout EngineSnapshot) -> Void) {
        let copy: EngineSnapshot = locked {
            change(&snap)
            return snap
        }
        onChange?(copy)
    }

    private func setWorker(_ option: CoinOption?) {
        publish { s in
            s.workers = s.workers.enumerated().map { i, w in
                var w = w
                w.option = i == 0 ? option : nil   // one GPU on Apple silicon; more devices get workers later
                w.hashrate = 0
                w.accepted = 0
                w.rejected = 0
                return w
            }
        }
    }

    /// Every Metal GPU macOS exposes (one built-in GPU on Apple silicon).
    public static func deviceSummaries() -> [DeviceSummary] {
        MTLCopyAllDevices().map { device in
            DeviceSummary(id: device.registryID, name: device.name,
                          detail: (device.hasUnifiedMemory ? "built-in, unified memory · " : "")
                              + "\(formatBytes(Int(device.recommendedMaxWorkingSetSize))) usable by the GPU")
        }
    }

    // MARK: Settings and prices

    /// Saves the settings and re-scores the coins; while mining, the choice is re-made with the new settings.
    public func update(settings: MinerSettings) throws {
        try settings.save(root: root)
        let rows = locked {
            currentSettings = settings
            refusedLogins = [:]   // the payout may be fixed now
            if running { switchFlag = true }
            return self.rows
        }
        publish { $0.options = Self.options(rows, settings, refused: [:]) }
    }

    /// Re-reads the newest benchmark and values it with live Kryptex data. Blocking (network).
    public func refreshPrices() throws {
        let file = try Earnings.latestBench(root: root)
        let bench = try JSONDecoder().decode(BenchFile.self, from: Data(contentsOf: file))
        let rows = try Earnings.rows(bench: bench, kwh: nil, note: { _ in })
        let (settings, refused) = locked {
            self.rows = rows
            return (currentSettings, refusedLogins)
        }
        publish {
            $0.options = Self.options(rows, settings, refused: refused)
            $0.lastPriceCheck = Date()
            $0.benchmarkDate = Self.benchDate(file)
        }
    }

    static func options(_ rows: [RankRow], _ settings: MinerSettings, refused: [String: String]) -> [CoinOption] {
        let price = settings.electricityPricePerKWh
        return rows.map { r in
            let net: Double? = price > 0 ? r.watts.map { r.usdPerDay - $0 * 24 / 1000 * price } : nil
            let accountPayouts = r.accountPayouts ?? true
            return CoinOption(coin: r.coin, pool: r.pool, algorithm: r.algorithm, unit: r.unit, rate: r.rate,
                              usdPerDay: r.usdPerDay, watts: r.watts, netUsdPerDay: net, price: r.economics.price,
                              payoutReady: settings.login(coin: r.coin) != nil
                                  && (settings.payoutMode != .kryptexAccount || accountPayouts),
                              accountPayouts: accountPayouts,
                              hasPoolConnection: Registry.poolMiner(for: r.pool) != nil, loginRefused: refused[r.pool])
        }.sorted { $0.score > $1.score }
    }

    static func benchDate(_ file: URL) -> Date? {
        let name = file.deletingPathExtension().lastPathComponent.replacingOccurrences(of: "bench-", with: "")
        let parser = DateFormatter()
        parser.dateFormat = "yyyyMMdd-HHmmss"
        return parser.date(from: name)
    }

    // MARK: Benchmarks

    /// Benchmarks every built-in algorithm on the default GPU, saves the results and re-prices. Takes minutes.
    public func runBenchmarks(seconds: Double = 20, cooldown: Double = 10) throws {
        try locked {
            guard !running else { throw MinerError("stop mining before benchmarking") }
            running = true
            stopFlag = false
        }
        defer { locked { running = false } }
        GPUThrottle.shared.duty = 1   // benchmarks measure full speed, quiet mode or not
        let gpu = try GPU()
        publish { $0.state = .benchmarking("(measuring idle GPU power)") }
        Thread.sleep(forTimeInterval: 5)   // let earlier GPU work wind down
        let idle = EnergyMeter.shared?.measure(seconds: 3)?.gpuWatts
        var results: [BenchResult] = []
        let all = Registry.all
        for (i, type) in all.enumerated() {
            if locked({ stopFlag }) { break }
            if i > 0 {
                publish { $0.state = .benchmarking("(cooling down before \(type.id))") }
                Thread.sleep(forTimeInterval: cooldown)
            }
            publish { $0.state = .benchmarking("\(type.id), \(i + 1) of \(all.count)") }
            results.append(Bench.bench(type, gpu: gpu, config: AlgoConfig(), seconds: seconds, idleWatts: idle))
        }
        if !results.isEmpty { _ = try Bench.save(results, gpu: gpu) }
        publish { $0.state = .idle }
        try refreshPrices()
    }

    // MARK: Choosing

    private func chooseUnlocked() -> (option: CoinOption?, reason: String?) {
        Self.choose(snap.options, mineOnlyWhenProfitable: currentSettings.mineOnlyWhenProfitable)
    }

    /// The coin to mine from `options` (best first): the best one the engine can mine (`CoinOption.canMine`). nil,
    /// with a reason, when there are no prices yet, nothing can be mined, or (under "mine only when profitable") the
    /// pick doesn't pay for its electricity.
    static func choose(_ options: [CoinOption], mineOnlyWhenProfitable: Bool) -> (option: CoinOption?, reason: String?) {
        guard !options.isEmpty else { return (nil, "no benchmark results yet") }
        guard let pick = options.first(where: \.canMine) else {
            if !options.contains(where: \.hasPoolConnection) { return (nil, "this build has no pool connections") }
            if !options.contains(where: { $0.hasPoolConnection && $0.payoutReady }) {
                return (nil, "no payout set; choose where earnings go in Settings")
            }
            return (nil, "the pool refused the login; check the payout in Settings")
        }
        if mineOnlyWhenProfitable, pick.score <= 0 {
            return (nil, "nothing earns more than its electricity")
        }
        return (pick, nil)
    }

    // MARK: Mining

    public func start() {
        let begin: Bool = locked {
            guard !running else { return false }
            running = true
            stopFlag = false
            switchFlag = false
            return true
        }
        guard begin else { return }
        let miner = Thread { [weak self] in self?.mineLoop() }
        miner.name = "MinerEngine"
        miner.qualityOfService = .userInitiated
        miner.start()
        let monitor = Thread { [weak self] in self?.monitorLoop() }
        monitor.name = "MinerEngine monitor"
        monitor.start()
    }

    public func stop() { locked { stopFlag = true } }

    private var shouldStop: Bool { locked { stopFlag } }
    /// The miner should hand back control: stopping, or the coin choice needs re-making.
    private var shouldYield: Bool { locked { stopFlag || switchFlag } }

    private func sleep(until deadline: Date) {
        while Date() < deadline, !shouldYield { Thread.sleep(forTimeInterval: 0.5) }
    }

    /// While mining: reads GPU power every 2 s, counts time mined, re-prices every `checkInterval`, and flags a switch
    /// when another coin beats the current one by `switchMargin`, the current one can't be mined any more, or nothing
    /// qualifies.
    private func monitorLoop() {
        var nextCheck = Date().addingTimeInterval(checkInterval)
        var lastEnergy = EnergyMeter.shared?.sample()
        var lastTick = now()
        while locked({ running && !stopFlag }) {
            Thread.sleep(forTimeInterval: 2)
            var watts: Double?
            if let meter = EnergyMeter.shared, let previous = lastEnergy, let current = meter.sample() {
                watts = meter.reading(from: previous, to: current)?.gpuWatts
                lastEnergy = current
            }
            let quietMode = locked { currentSettings.quietMode }
            if quietMode { quiet.tick(gpuWatts: watts) } else { GPUThrottle.shared.duty = 1 }
            let fans = FanSensor.shared?.read().map(\.rpm) ?? []
            let quietWatts = quietMode ? quiet.targetWatts : nil
            let elapsed = now() - lastTick
            lastTick = now()
            let earnings: [EarningsRow]? = locked {
                guard let option = active, case .mining = snap.state else { return nil }
                var row = ledger[Self.ledgerKey(option)] ?? EarningsRow(algorithm: option.algorithm, coin: option.coin, seconds: 0,
                                                          estimatedUSD: 0, acceptedShares: 0)
                row.seconds += elapsed
                ledger[Self.ledgerKey(option)] = row
                return Self.sorted(ledger)
            }
            publish { s in
                s.gpuWatts = watts
                s.fanRPM = fans
                s.quietWatts = quietWatts
                if let earnings { s.earnings = earnings }
            }

            guard Date() >= nextCheck else { continue }
            nextCheck = Date().addingTimeInterval(checkInterval)
            do {
                try refreshPrices()
            } catch {
                publish { $0.message = "Price check failed: \(error)" }
                continue
            }
            locked {
                let choice = chooseUnlocked()
                guard let pick = choice.option else {
                    if active != nil { switchFlag = true }
                    return
                }
                guard let current = active else {
                    switchFlag = true   // was waiting; something qualifies now
                    return
                }
                guard pick.pool != current.pool else { return }
                guard let refreshed = snap.options.first(where: { $0.pool == current.pool }), refreshed.canMine,
                      pick.score <= refreshed.score * (1 + switchMargin) else {
                    switchFlag = true
                    return
                }
            }
        }
    }

    private func mineLoop() {
        defer {
            saveLedger()
            locked {
                running = false
                active = nil
            }
            quiet.stop()
            setWorker(nil)
            publish { s in
                if case .failed = s.state {} else { s.state = .idle }
                s.gpuWatts = nil
                s.fanRPM = []
                s.quietWatts = nil
            }
        }
        do {
            let gpu = try GPU()
            publish { $0.message = "Checking prices" }
            try refreshPrices()
            while !shouldStop {
                let choice = locked { () -> (option: CoinOption?, reason: String?) in
                    switchFlag = false
                    let choice = chooseUnlocked()
                    active = choice.option
                    return choice
                }
                guard let option = choice.option, let type = Registry.poolMiner(for: option.pool),
                      let login = settings.login(coin: option.coin) else {
                    setWorker(nil)
                    publish {
                        $0.state = .waiting(choice.reason ?? "nothing to mine")
                        $0.message = nil
                    }
                    sleep(until: .distantFuture)
                    continue
                }
                setWorker(option)
                mine(option, type: type, login: login, gpu: gpu)
            }
        } catch {
            publish { $0.state = .failed("\(error)") }
        }
    }

    /// Mines `option` on its Kryptex pool until told to yield, reconnecting with growing back-off when the pool drops.
    /// Returns early when the pool refuses the login, after marking the coin so the next choice skips it.
    private func mine(_ option: CoinOption, type: PoolMiner.Type, login: String, gpu: GPU) {
        var failures = 0
        while !shouldYield {
            do {
                publish {
                    $0.state = .preparing("\(option.coin) on Kryptex")
                    $0.message = "Connecting to the \(option.coin) pool"
                }
                let endpoint = try PoolEndpoint.kryptex(pool: option.pool)
                let events = PoolEvents(
                    share: { [weak self] accepted, work, note in self?.recordShare(option, accepted: accepted, work: work, note: note) },
                    hashrate: { [weak self] rate in
                        self?.publish { s in
                            s.state = .mining
                            if !s.workers.isEmpty { s.workers[0].hashrate = rate }
                        }
                    },
                    log: { [weak self] line in self?.publish { $0.message = line } })
                let miner = try type.init(gpu: gpu, endpoint: endpoint, login: login, events: events)
                publish {
                    $0.state = .mining
                    $0.message = "Mining \(option.coin) at \(endpoint)"
                }
                try miner.run(shouldStop: { [weak self] in self?.shouldYield ?? true })
                failures = 0
            } catch let refused as PoolLoginRefused {
                let (rows, settings, all) = locked { () -> ([RankRow], MinerSettings, [String: String]) in
                    refusedLogins[option.pool] = refused.reason
                    return (self.rows, currentSettings, refusedLogins)
                }
                publish {
                    $0.options = Self.options(rows, settings, refused: all)
                    $0.message = "The \(option.coin) pool refused the login \(refused.login): \(refused.reason)"
                }
                return
            } catch {
                failures += 1
                let wait = min(60.0, 5.0 * Double(failures))
                publish { $0.message = "Pool: \(error). Retrying in \(Int(wait)) s." }
                sleep(until: Date().addingTimeInterval(wait))
            }
        }
    }

    /// A share's value is its expected work at the coin's current payout per unit of work.
    private func recordShare(_ option: CoinOption, accepted: Bool, work: Double, note: String?) {
        let value = accepted && option.rate > 0 ? work * option.usdPerDay / option.rate / 86_400 : 0
        let rows: [EarningsRow] = locked {
            var row = ledger[Self.ledgerKey(option)] ?? EarningsRow(algorithm: option.algorithm, coin: option.coin, seconds: 0,
                                                      estimatedUSD: 0, acceptedShares: 0)
            if accepted {
                row.acceptedShares += 1
                row.estimatedUSD += value
            }
            ledger[Self.ledgerKey(option)] = row
            return Self.sorted(ledger)
        }
        publish { s in
            s.earnings = rows
            if !s.workers.isEmpty {
                if accepted { s.workers[0].accepted += 1 } else { s.workers[0].rejected += 1 }
            }
            if !accepted { s.message = "Share rejected" + (note.map { ": \($0)" } ?? "") }
        }
        saveLedger()
    }

    // MARK: Ledgers

    /// A saved ledger, one row per coin. Rows saved twice for one coin (by earlier builds) are added together.
    static func loadLedger(at url: URL) -> [String: EarningsRow] {
        guard let data = try? Data(contentsOf: url), let rows = try? JSONDecoder().decode([EarningsRow].self, from: data) else { return [:] }
        return Dictionary(rows.map { ($0.id, $0) }, uniquingKeysWith: { a, b in
            EarningsRow(algorithm: a.algorithm, coin: a.coin, seconds: a.seconds + b.seconds,
                        estimatedUSD: a.estimatedUSD + b.estimatedUSD, acceptedShares: a.acceptedShares + b.acceptedShares)
        })
    }

    /// A coin's key in the ledger: its earnings row's id, so a saved ledger reads back under the same keys.
    static func ledgerKey(_ option: CoinOption) -> String { "\(option.algorithm)/\(option.coin)" }

    private static func sorted(_ ledger: [String: EarningsRow]) -> [EarningsRow] {
        ledger.values.sorted { $0.estimatedUSD > $1.estimatedUSD }
    }

    /// Earnings in results/ledger.json.
    private func saveLedger() {
        let rows = locked { Self.sorted(ledger) }
        guard !rows.isEmpty else { return }
        let results = root.appendingPathComponent("results")
        try? FileManager.default.createDirectory(at: results, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try? encoder.encode(rows).write(to: results.appendingPathComponent("ledger.json"))
    }
}
