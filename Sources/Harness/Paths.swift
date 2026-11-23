import Foundation

/// Where Metal Miner finds its kernels and keeps its data.
public enum MinerPaths {
    /// The source checkout this binary was built in, if any: the first folder above the executable holding both
    /// Kernels/common.metal and build.sh. METALMINER_ROOT overrides it.
    static let checkout: URL? = {
        if let path = ProcessInfo.processInfo.environment["METALMINER_ROOT"] { return URL(fileURLWithPath: path) }
        var dir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0 ..< 8 {
            let fm = FileManager.default
            if fm.fileExists(atPath: dir.appendingPathComponent("Kernels/common.metal").path),
               fm.fileExists(atPath: dir.appendingPathComponent("build.sh").path) { return dir }
            dir.deleteLastPathComponent()
        }
        return nil
    }()

    /// Metal kernel sources: the app bundle's Resources/Kernels when it has them, otherwise the checkout's Kernels/.
    static func kernels() throws -> URL {
        if let bundled = Bundle.main.resourceURL?.appendingPathComponent("Kernels"),
           FileManager.default.fileExists(atPath: bundled.appendingPathComponent("common.metal").path) { return bundled }
        if let checkout { return checkout.appendingPathComponent("Kernels") }
        throw MinerError("can't find the Metal kernels (Kernels/common.metal); set METALMINER_ROOT")
    }

    /// Settings, benchmarks, rankings and the earnings ledger. Run from a source checkout they stay in its folder, so
    /// development never writes to ~/Library; an installed app uses ~/Library/Application Support/Metal Miner.
    /// METALMINER_DATA overrides both.
    public static func data() throws -> URL {
        if let path = ProcessInfo.processInfo.environment["METALMINER_DATA"] { return URL(fileURLWithPath: path) }
        if let checkout { return checkout }
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let folder = support.appendingPathComponent("Metal Miner", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }
}
