import AppKit
import MinerCore
import SwiftUI

/// One main window, opened fresh on every launch. Restoring the last session could bring the app back with no
/// window at all, and the window is the app: closing it quits (and stops mining).
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct MetalMinerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = EngineModel()

    init() {
        // Has to happen before AppKit starts restoring windows, so here rather than in the delegate.
        UserDefaults.standard.set(true, forKey: "ApplePersistenceIgnoreState")
        UserDefaults.standard.set(false, forKey: "NSQuitAlwaysKeepsWindows")
    }

    var body: some Scene {
        Window("Metal Miner", id: "main") {
            ContentView()
                .environmentObject(model)
                .onAppear { LaunchOptions.apply(to: model) }
        }
        .windowResizability(.contentMinSize)
    }
}

/// Environment variables for checking the app from a script. (Not command-line arguments: AppKit reads
/// `-key value` pairs from argv and treats any leftover argument as a file to open, and an app launched
/// to open a file doesn't show its default window.)
///   METALMINER_AUTOSTART=1            start mining right away
///   METALMINER_SNAPSHOT=PATH.png      after METALMINER_SNAPSHOT_DELAY seconds (default 6), save the window
///                                    as a PNG and quit
enum LaunchOptions {
    @MainActor static func apply(to model: EngineModel) {
        let environment = ProcessInfo.processInfo.environment
        if environment["METALMINER_AUTOSTART"] == "1" { model.start() }
        guard let path = environment["METALMINER_SNAPSHOT"], !path.isEmpty else { return }
        let delay = environment["METALMINER_SNAPSHOT_DELAY"].flatMap(Double.init) ?? 6
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(delay))
            if let window = NSApp.windows.first(where: { $0.isVisible }), let view = window.contentView,
               let image = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                view.cacheDisplay(in: view.bounds, to: image)
                try? image.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
            }
            model.stop()
            try? await Task.sleep(for: .seconds(1))
            NSApp.terminate(nil)
        }
    }
}
