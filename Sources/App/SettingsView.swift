import MinerCore
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: EngineModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft: MinerSettings
    @State private var priceText: String
    @State private var priceError = false
    /// Opened from Start Mining while no payout is set: says why, and starts mining once one is saved.
    private let startsMining: Bool

    init(original: MinerSettings, startsMining: Bool = false) {
        self.startsMining = startsMining
        _draft = State(initialValue: original)
        _priceText = State(initialValue: original.electricityPricePerKWh > 0 ? String(original.electricityPricePerKWh) : "")
    }

    /// Coins Kryptex pays only to the coin's own wallets, not to Kryptex accounts.
    private var walletOnlyCoins: [String] {
        model.snapshot.options.filter { !$0.accountPayouts }.map(\.coin).sorted()
    }

    /// Coins the user might need a wallet for: everything ranked, plus any wallet already saved.
    private var coins: [String] {
        Array(Set(model.snapshot.options.map(\.coin)).union(draft.wallets.keys)).sorted()
    }

    var body: some View {
        VStack(spacing: 0) {
            if startsMining {
                Label("Choose where your earnings go before mining starts.", systemImage: "arrow.down.to.line.circle")
                    .font(.headline)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding([.horizontal, .top])
            }
            Form {
                Section("Electricity") {
                    TextField("Price per kWh (USD)", text: $priceText, prompt: Text("Blank or 0 means free"))
                    if priceError { Text("Enter a number such as 0.12").foregroundStyle(.red).font(.caption) }
                    Toggle("Only mine when it earns more than the electricity costs", isOn: $draft.mineOnlyWhenProfitable)
                }
                Section("Noise") {
                    Toggle("Quiet mode", isOn: $draft.quietMode)
                    Text("Mines more slowly so the fans stay at their lowest speed. Earnings drop with the speed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Payout") {
                    Picker("Pay to", selection: $draft.payoutMode) {
                        Text("Kryptex account").tag(PayoutMode.kryptexAccount)
                        Text("My own wallets").tag(PayoutMode.ownWallets)
                    }
                    .pickerStyle(.segmented)
                    if draft.payoutMode == .kryptexAccount {
                        TextField("Kryptex email or username", text: $draft.kryptexUsername)
                        Text("Your Kryptex account's email (or username), for every coin. Earnings collect in your Kryptex account and pay out in BTC or USDT.")
                            .font(.caption).foregroundStyle(.secondary)
                        if !walletOnlyCoins.isEmpty {
                            Text("Kryptex doesn't pay \(walletOnlyCoins.joined(separator: ", ")) to accounts yet, so those coins are skipped. Use your own wallets to mine them.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    } else {
                        if coins.isEmpty { Text("Run benchmarks first to see which coins you can mine.").foregroundStyle(.secondary) }
                        ForEach(coins, id: \.self) { coin in
                            TextField(coin, text: wallet(coin), prompt: Text("\(coin) wallet address"))
                        }
                        Text("Each coin is paid to your own wallet for it. Coins without an address are skipped.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    TextField("Worker name", text: $draft.workerName)
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(startsMining ? "Save and Start Mining" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(startsMining && !draft.hasPayout)
            }
            .padding()
        }
        .frame(width: 540, height: 680)
    }

    private func wallet(_ coin: String) -> Binding<String> {
        Binding(get: { draft.wallets[coin] ?? "" },
                set: { draft.wallets[coin] = $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 })
    }

    private func save() {
        let text = priceText.trimmingCharacters(in: .whitespaces)
        guard text.isEmpty || (Double(text).map { $0 >= 0 } ?? false) else {
            priceError = true
            return
        }
        var settings = draft
        settings.electricityPricePerKWh = Double(text) ?? 0
        model.save(settings)
        if startsMining, settings.hasPayout { model.start() }
        dismiss()
    }
}
