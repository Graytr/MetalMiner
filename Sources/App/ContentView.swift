import MinerCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: EngineModel
    @State private var settingsSheet: SettingsSheet?

    /// Settings opened from the Settings button, or from Start Mining while no payout is set.
    enum SettingsSheet: Identifiable {
        case edit, payoutFirst
        var id: Self { self }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if !model.settings.hasPayout {
                    Banner(symbol: "arrow.down.to.line.circle", tint: .orange,
                           text: "Before mining, choose where your earnings go: your Kryptex account, or your own wallet for each coin.")
                }
                if !refused.isEmpty {
                    Banner(symbol: "person.crop.circle.badge.exclamationmark", tint: .red,
                           text: "The pool refused the login for \(refused.map(\.coin).joined(separator: ", ")) (\(refused[0].loginRefused ?? "")). "
                               + "Those coins are skipped until you change the payout in Settings.")
                }
                if let error = model.error {
                    Banner(symbol: "exclamationmark.triangle.fill", tint: .red, text: error)
                }
                HStack(alignment: .top, spacing: 16) {
                    DevicesCard(workers: model.snapshot.workers, watts: model.snapshot.gpuWatts, fans: model.snapshot.fanRPM,
                                quietWatts: model.snapshot.quietWatts)
                    EarningsCard(rows: model.snapshot.earnings)
                }
                OptionsCard(options: model.snapshot.options, mining: model.snapshot.workers.compactMap(\.option).map(\.pool),
                            priced: model.settings.electricityPricePerKWh > 0,
                            kryptexAccount: model.settings.payoutMode == .kryptexAccount)
                footer
            }
            .padding(20)
        }
        .frame(minWidth: 940, minHeight: 700)
        .sheet(item: $settingsSheet) { sheet in
            SettingsView(original: model.settings, startsMining: sheet == .payoutFirst).environmentObject(model)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "cube.transparent")
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text("Metal Miner").font(.title.bold())
                Text(statusLine).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Button { settingsSheet = .edit } label: { Label("Settings", systemImage: "gearshape") }
            Button { model.benchmark() } label: { Label("Run Benchmarks", systemImage: "speedometer") }
                .disabled(model.snapshot.state.isBusy)
            if model.isMining {
                Button(role: .destructive) { model.stop() } label: { Label("Stop", systemImage: "stop.fill") }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            } else {
                Button {
                    if model.settings.hasPayout { model.start() } else { settingsSheet = .payoutFirst }
                } label: { Label("Start Mining", systemImage: "play.fill") }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(model.isBenchmarking || model.snapshot.options.isEmpty)
            }
        }
    }

    /// Coins whose pool refused the login.
    private var refused: [CoinOption] { model.snapshot.options.filter { $0.loginRefused != nil } }

    private var statusLine: String {
        var line = model.snapshot.state.label
        if let message = model.snapshot.message { line += " · \(message)" }
        return line
    }

    private var footer: some View {
        HStack(spacing: 16) {
            if let checked = model.snapshot.lastPriceCheck {
                Text("Prices from Kryptex, checked \(checked.formatted(date: .omitted, time: .shortened))")
            } else {
                Text("Prices from Kryptex: not checked yet")
            }
            if let date = model.snapshot.benchmarkDate {
                Text("Benchmarked \(date.formatted(date: .abbreviated, time: .shortened))")
            }
            Spacer()
            Button("Refresh Prices") { model.refreshPrices() }
                .buttonStyle(.link)
                .disabled(model.snapshot.state.isBusy)
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
    }
}

struct Banner: View {
    let symbol: String
    let tint: Color
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(tint)
            Text(text).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct Card<Content: View>: View {
    let title: String
    let symbol: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: symbol).font(.headline)
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(nsColor: .separatorColor)))
    }
}

struct DevicesCard: View {
    let workers: [WorkerStatus]
    let watts: Double?
    let fans: [Double]
    let quietWatts: Double?

    var body: some View {
        Card(title: "GPUs", symbol: "cpu") {
            if workers.isEmpty { Text("No Metal GPU found").foregroundStyle(.secondary) }
            ForEach(workers) { worker in
                VStack(alignment: .leading, spacing: 3) {
                    Text(worker.device.name).fontWeight(.semibold)
                    Text(worker.device.detail).font(.caption).foregroundStyle(.secondary)
                    if let option = worker.option {
                        HStack {
                            Image(systemName: "bolt.fill").foregroundStyle(.green)
                            Text("Mining \(option.coin)").fontWeight(.medium)
                            Text(option.algorithm).foregroundStyle(.secondary)
                            Spacer()
                            Text(worker.hashrate > 0 ? MinerFormat.rate(worker.hashrate, option.unit) : "starting")
                                .monospacedDigit()
                        }
                        if worker.accepted + worker.rejected > 0 {
                            Text("Shares: \(worker.accepted) accepted, \(worker.rejected) rejected").font(.caption).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("Idle").foregroundStyle(.secondary)
                    }
                }
            }
            if let watts {
                Text(String(format: "GPU drawing %.0f W", watts)).font(.caption).foregroundStyle(.secondary)
            }
            if !fans.isEmpty {
                Text("Fans " + fans.map { String(format: "%.0f", $0) }.joined(separator: " · ") + " RPM")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let quietWatts {
                Label(String(format: "Quiet mode: GPU held near %.0f W", quietWatts), systemImage: "speaker.wave.1")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct EarningsCard: View {
    let rows: [EarningsRow]

    private var total: Double { rows.reduce(0) { $0 + $1.estimatedUSD } }

    var body: some View {
        Card(title: "Earnings by algorithm", symbol: "dollarsign.circle") {
            if rows.isEmpty {
                Text("Nothing mined yet").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                    GridRow {
                        Text("Algorithm")
                        Text("Coin")
                        Text("Time")
                        Text("Earned")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    ForEach(rows) { row in
                        GridRow {
                            Text(row.algorithm)
                            Text(row.coin)
                            Text(Self.duration(row.seconds)).monospacedDigit()
                            Text(MinerFormat.usd(row.estimatedUSD)).monospacedDigit()
                        }
                    }
                    Divider().gridCellUnsizedAxes(.horizontal)
                    GridRow {
                        Text("Total").fontWeight(.semibold)
                        Text("")
                        Text(Self.duration(rows.reduce(0) { $0 + $1.seconds })).monospacedDigit()
                        Text(MinerFormat.usd(total)).fontWeight(.semibold).monospacedDigit()
                    }
                }
            }
        }
    }

    static func duration(_ seconds: Double) -> String {
        let minutes = Int(seconds / 60)
        return minutes >= 60 ? "\(minutes / 60)h \(minutes % 60)m" : "\(minutes)m \(Int(seconds) % 60)s"
    }
}

struct OptionsCard: View {
    let options: [CoinOption]
    let mining: [String]
    let priced: Bool
    let kryptexAccount: Bool

    var body: some View {
        Card(title: "Best coins right now", symbol: "chart.bar.xaxis") {
            if options.isEmpty {
                Text("No ranking yet. Run benchmarks, then refresh prices.").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 5) {
                    GridRow {
                        Text("#")
                        Text("Coin")
                        Text("Algorithm")
                        Text("Your rate")
                        Text("Per day")
                        if priced { Text("After power") }
                        Text("Extra power")
                        Text("")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    ForEach(Array(options.enumerated()), id: \.element.id) { index, option in
                        GridRow {
                            Text("\(index + 1)").foregroundStyle(.secondary).monospacedDigit()
                            Text(option.coin).fontWeight(.semibold)
                            Text(option.algorithm).foregroundStyle(.secondary)
                            Text(MinerFormat.rate(option.rate, option.unit)).monospacedDigit()
                            Text(MinerFormat.usd(option.usdPerDay)).monospacedDigit()
                            if priced {
                                Text(option.netUsdPerDay.map { MinerFormat.usd($0) } ?? "–")
                                    .monospacedDigit()
                                    .foregroundStyle((option.netUsdPerDay ?? 0) < 0 ? Color.red : Color.primary)
                            }
                            Text(option.watts.map { String(format: "%.0f W", $0) } ?? "–").monospacedDigit()
                            status(option)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private func status(_ option: CoinOption) -> some View {
        if mining.contains(option.pool) {
            Label("Mining", systemImage: "bolt.fill").foregroundStyle(.green)
        } else if !option.hasPoolConnection {
            Text("No pool connection").foregroundStyle(.secondary)
        } else if option.loginRefused != nil {
            Text("Login refused").foregroundStyle(.red)
        } else if !option.payoutReady, kryptexAccount, !option.accountPayouts {
            Text("Needs a wallet").foregroundStyle(.orange)
        } else if !option.payoutReady {
            Text("No payout set").foregroundStyle(.orange)
        } else {
            Text("")
        }
    }
}
