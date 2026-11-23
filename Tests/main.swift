import Foundation

// Metal Miner's unit tests: offline, no GPU. `./test.sh [NAME]` builds and runs them.

// Tests never touch real settings or results: the data folder is a fresh folder next to this binary.
let dataFolder = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().appendingPathComponent("test-data", isDirectory: true)
try? FileManager.default.removeItem(at: dataFolder)
try! FileManager.default.createDirectory(at: dataFolder, withIntermediateDirectories: true)
setenv("METALMINER_DATA", dataFolder.path, 1)
guard (try? MinerPaths.data())?.standardizedFileURL.path == dataFolder.standardizedFileURL.path else {
    print("can't point the data folder at \(dataFolder.path), so no tests ran")
    exit(2)
}

let suites = [
    StratumTests.suite,
    SettingsTests.suite,
    EngineTests.suite,
    QuietTests.suite,
    FormatTests.suite,
    CLITests.suite,
]
exit(TestRunner.run(suites, filter: CommandLine.arguments.dropFirst().first))
