import Foundation
import MinerCore
import SwiftUI

/// The app's view of the engine. Views read `snapshot` and `settings` and call the actions; nothing here knows
/// which algorithms, coins or GPUs exist.
@MainActor
final class EngineModel: ObservableObject {
    @Published private(set) var snapshot = EngineSnapshot()
    @Published private(set) var settings = MinerSettings()
    @Published var error: String?
    private let engine: MinerEngine?

    init() {
        do {
            let engine = try MinerEngine()
            self.engine = engine
            snapshot = engine.snapshot
            settings = engine.settings
            engine.onChange = { [weak self] snapshot in
                Task { @MainActor in self?.snapshot = snapshot }
            }
        } catch {
            engine = nil
            self.error = "\(error)"
        }
        refreshPrices()
    }

    var isBenchmarking: Bool {
        if case .benchmarking = snapshot.state { return true }
        return false
    }

    var isMining: Bool { snapshot.state.isBusy && !isBenchmarking }

    func start() {
        error = nil
        engine?.start()
    }

    func stop() { engine?.stop() }

    func refreshPrices() {
        guard let engine else { return }
        background { try engine.refreshPrices() }
    }

    func benchmark() {
        guard let engine else { return }
        error = nil
        background { try engine.runBenchmarks() }
    }

    func save(_ settings: MinerSettings) {
        do {
            try engine?.update(settings: settings)
            self.settings = settings
        } catch {
            self.error = "\(error)"
        }
    }

    private func background(_ work: @escaping @Sendable () throws -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try work()
            } catch {
                let message = "\(error)"
                Task { @MainActor in self?.error = message }
            }
        }
    }
}
