import Foundation

/// Quiet mode's brake: the GPU works only `duty` of the time, resting after each piece of GPU work. One per process,
/// shared by every algorithm; 1, the default, means no rests.
final class GPUThrottle {
    static let shared = GPUThrottle()
    private let lock = NSLock()
    private var value = 1.0

    /// The share of time the GPU may work, 0.02 to 1.
    var duty: Double {
        get {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
        set {
            lock.lock()
            value = min(1, max(0.02, newValue))
            lock.unlock()
        }
    }

    /// Called after waiting for GPU work that took `gpuSeconds`: rests so the GPU averages `duty` busy (2 s at most).
    func rest(after gpuSeconds: Double) {
        let duty = self.duty
        guard duty < 1, gpuSeconds > 0 else { return }
        Thread.sleep(forTimeInterval: min(2, gpuSeconds * (1 / duty - 1)))
    }
}

/// Quiet mode: holds the GPU to a power target through GPUThrottle, and moves the target so the fans stay near their
/// slowest speed. On Macs whose fans can't be read, it backs off under thermal pressure instead. Call `tick` every
/// couple of seconds while mining, and `stop` after.
final class QuietController {
    /// The GPU power held, in watts: starts at 10 W and settles where the fans stay quiet (3 W to 60 W).
    private(set) var targetWatts = 10.0
    /// The fans' speeds at the last check (RPM), when readable.
    private(set) var fanRPM: [Double] = []
    private var lastCheck = 0.0
    /// The fans' level at the last check; nil before the first, which only notes where they are.
    private var lastLevel: Double?
    private var quietSince: Double?

    /// `gpuWatts` is the GPU's average power since the last tick.
    func tick(gpuWatts: Double?, at time: Double = now()) {
        if let watts = gpuWatts, watts > 0.2 {   // hold the target: the duty follows target / measured, damped
            let throttle = GPUThrottle.shared
            throttle.duty *= min(2, max(0.5, targetWatts / watts)).squareRoot()
        }
        guard time - lastCheck >= 20 else { return }   // fans and heat change slowly: re-aim every 20 s
        lastCheck = time
        guard let sensor = FanSensor.shared else {
            if ProcessInfo.processInfo.thermalState != .nominal { targetWatts = max(3, targetWatts * 0.85) }
            return
        }
        let fans = sensor.read()
        fanRPM = fans.map(\.rpm)
        let level = FanSensor.level(fans)
        defer { lastLevel = level }
        guard let previous = lastLevel else { return }   // the fans may still be loud from earlier work: just note them
        if level > 0.15 {
            quietSince = nil
            if level >= previous - 0.02 { targetWatts = max(3, targetWatts * 0.85) }   // loud and not easing: back off
        } else if level < 0.05 {
            if let since = quietSince {
                if time - since >= 120 { targetWatts = min(60, targetWatts * 1.03) }   // quiet for 2 minutes: creep up
            } else {
                quietSince = time
            }
        } else {
            quietSince = nil
        }
    }

    /// Back to full speed.
    func stop() { GPUThrottle.shared.duty = 1 }

    func describe(gpuWatts: Double?) -> String {
        let fans = fanRPM.isEmpty ? "" : ", fans " + fanRPM.map { String(format: "%.0f", $0) }.joined(separator: " / ") + " RPM"
        return String(format: "quiet mode: GPU %.1f W (holding %.1f W), working %.0f%% of the time", gpuWatts ?? 0, targetWatts,
                      GPUThrottle.shared.duty * 100) + fans
    }
}

/// Runs a QuietController on its own thread, reading GPU power every 2 s, for callers without the engine (the CLI's
/// `mine`). `log` gets a status line every 30 s.
final class QuietMonitor {
    private let controller = QuietController()
    private let lock = NSLock()
    private var running = true

    static func start(log: @escaping (String) -> Void) -> QuietMonitor {
        let monitor = QuietMonitor()
        log("quiet mode: holding the GPU near \(Int(monitor.controller.targetWatts)) W to start, then adjusting to keep the fans slow")
        let thread = Thread { monitor.loop(log: log) }
        thread.name = "quiet mode"
        thread.start()
        return monitor
    }

    func stop() {
        lock.lock()
        running = false
        lock.unlock()
        controller.stop()
    }

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func loop(log: (String) -> Void) {
        var last = EnergyMeter.shared?.sample()
        var lastLog = now()
        while isRunning {
            Thread.sleep(forTimeInterval: 2)
            var watts: Double?
            if let meter = EnergyMeter.shared, let previous = last, let current = meter.sample() {
                watts = meter.reading(from: previous, to: current)?.gpuWatts
                last = current
            }
            guard isRunning else { break }
            controller.tick(gpuWatts: watts)
            if now() - lastLog >= 30 {
                lastLog = now()
                log(controller.describe(gpuWatts: watts))
            }
        }
        controller.stop()
    }
}
