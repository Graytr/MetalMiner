import Foundation

struct BenchResult: Codable {
    var algorithm: String
    var coins: [String]
    var unit: String
    /// Work per second, in `unit`.
    var rate = 0.0
    var seconds = 0.0
    var batches = 0
    var batchSize = 0
    var setup = ""
    var setupSeconds = 0.0
    var crossCheck = ""
    var quick = false
    var thermalStart = ""
    var thermalEnd = ""
    /// GPU power during the timed run and with nothing running, from the GPU's energy counter (IOReport).
    /// It leaves out DRAM and CPU power, which macOS doesn't report to normal apps, so wall power is higher.
    var watts: Double?
    var idleWatts: Double?
    /// Share of mining time lost to periodic rebuilds (see MiningAlgorithm.overheadFraction).
    var overhead: Double?
    var error: String?
}

struct BenchFile: Codable {
    var date: String
    var device: String
    var results: [BenchResult]
}

enum Bench {
    /// Known-answer vectors, then the GPU-vs-CPU cross-check. Returns true on pass.
    static func test(_ type: MiningAlgorithm.Type, gpu: GPU, config: AlgoConfig) -> Bool {
        print("== \(type.id)  \(type.coins.joined(separator: ", "))")
        do {
            let start = now()
            let algorithm = try type.init(gpu: gpu, config: config)
            print("   setup   \(algorithm.setupSummary)  (\(fmt(now() - start, 1)) s)")
            for line in try algorithm.knownAnswerTests() { print("   vector  \(line)") }
            print("   gpu     \(try algorithm.crossCheck(samples: 32))")
            print("   PASS")
            return true
        } catch {
            print("   FAIL    \(error)")
            return false
        }
    }

    /// Setup, a short cross-check at the benchmark parameters, batch sizing, then a timed run. `idleWatts` is the
    /// system power measured before any GPU work (power telemetry lags, so it can't be read between runs).
    static func bench(_ type: MiningAlgorithm.Type, gpu: GPU, config: AlgoConfig, seconds: Double, idleWatts: Double?) -> BenchResult {
        var result = BenchResult(algorithm: type.id, coins: type.coins, unit: type.unit)
        result.quick = config.quick
        print("== \(type.id)  \(type.coins.joined(separator: ", "))")
        do {
            let start = now()
            let algorithm = try type.init(gpu: gpu, config: config)
            result.setupSeconds = now() - start
            result.setup = algorithm.setupSummary
            print("   setup   \(result.setup)  (\(fmt(result.setupSeconds, 1)) s)")
            result.crossCheck = try algorithm.crossCheck(samples: 8)
            print("   gpu     \(result.crossCheck)")
            result.idleWatts = idleWatts
            if algorithm.overheadFraction > 0 { result.overhead = algorithm.overheadFraction }

            // Size batches to about 150 ms: long enough to keep the GPU busy, short enough for the watchdog.
            var count = max(1, algorithm.defaultBatch)
            var nonce = UInt64.random(in: 0 ..< (1 << 62))
            for _ in 0 ..< 4 {
                let t = now()
                _ = try algorithm.runBatch(startNonce: nonce, count: count)
                let elapsed = max(now() - t, 1e-4)
                nonce &+= UInt64(count)
                count = max(1, Int(Double(count) * min(8, max(0.125, 0.15 / elapsed))))
            }
            result.batchSize = count
            result.thermalStart = gpu.thermalState

            var work = 0.0
            let energyStart = EnergyMeter.shared?.sample()
            let t0 = now()
            var lastReport = t0
            while now() - t0 < seconds {
                work += try algorithm.runBatch(startNonce: nonce, count: count)
                nonce &+= UInt64(count)
                result.batches += 1
                if now() - lastReport >= 5 {
                    lastReport = now()
                    print("   ...     \(formatRate(work / (lastReport - t0), type.unit))")
                }
            }
            result.seconds = now() - t0
            result.rate = work / result.seconds
            result.thermalEnd = gpu.thermalState
            if let meter = EnergyMeter.shared, let start = energyStart, let end = meter.sample(),
               let reading = meter.reading(from: start, to: end) {
                result.watts = reading.gpuWatts
            }
            let overheadNote = result.overhead.map { String(format: ", %.1f%% rebuild overhead", $0 * 100) } ?? ""
            let powerNote = result.watts.map { w in String(format: ", %.0f W GPU (%.1f W idle)", w, result.idleWatts ?? 0) } ?? ""
            print("   rate    \(formatRate(result.rate, type.unit))  (\(result.batches) batches of \(count), thermal \(result.thermalStart) → \(result.thermalEnd)\(powerNote)\(overheadNote))")
        } catch {
            result.error = "\(error)"
            print("   FAIL    \(error)")
        }
        return result
    }

    static func printTable(_ results: [BenchResult]) {
        guard !results.isEmpty else { return }
        func pad(_ s: String, _ n: Int) -> String { s.padding(toLength: max(n, s.count), withPad: " ", startingAt: 0) }
        print("\n" + pad("algorithm", 16) + pad("coins", 14) + pad("rate", 18) + pad("watts", 12) + "setup")
        for r in results {
            let rate = r.error == nil ? formatRate(r.rate, r.unit) : "failed"
            let watts = r.watts.map { w in String(format: "%.0f (+%.0f)", w, w - (r.idleWatts ?? w)) } ?? "-"
            print(pad(r.algorithm, 16) + pad(r.coins.joined(separator: ","), 14) + pad(rate, 18) + pad(watts, 12) + r.setup + (r.quick ? "  (quick)" : ""))
        }
    }

    /// Writes results/bench-<timestamp>.json and returns its URL.
    static func save(_ results: [BenchResult], gpu: GPU) throws -> URL {
        let dir = gpu.dataDirectory.appendingPathComponent("results")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        let file = dir.appendingPathComponent("bench-\(stamp.string(from: Date())).json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let payload = BenchFile(date: ISO8601DateFormatter().string(from: Date()), device: gpu.info, results: results)
        try encoder.encode(payload).write(to: file)
        return file
    }
}
