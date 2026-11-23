import Foundation

@inline(__always) func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1e9 }

func fmt(_ value: Double, _ digits: Int = 2) -> String { String(format: "%.\(digits)f", value) }

func formatBytes(_ count: Int) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"]
    var value = Double(count)
    var i = 0
    while value >= 1024 && i < units.count - 1 {
        value /= 1024
        i += 1
    }
    return i == 0 ? "\(count) B" : String(format: "%.2f %@", value, units[i])
}

/// "23.41 MH/s" style, with SI prefixes up to E.
func formatRate(_ rate: Double, _ unit: String) -> String {
    let prefixes = ["", "k", "M", "G", "T", "P", "E"]
    var value = rate
    var i = 0
    while value >= 1000 && i < prefixes.count - 1 {
        value /= 1000
        i += 1
    }
    return String(format: "%.2f %@%@", value, prefixes[i], unit)
}

func randomBytes(_ count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0 ..< count).map { _ in UInt8.random(in: 0 ... 255, using: &generator) }
}

extension Array where Element == UInt8 {
    /// Parses hex with or without a 0x prefix; nil on malformed input.
    init?(hex: String) {
        var digits = Substring(hex)
        if digits.hasPrefix("0x") { digits = digits.dropFirst(2) }
        guard digits.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        var i = digits.startIndex
        while i < digits.endIndex {
            let j = digits.index(i, offsetBy: 2)
            guard let byte = UInt8(digits[i ..< j], radix: 16) else { return nil }
            bytes.append(byte)
            i = j
        }
        self = bytes
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }

    func le32(at offset: Int) -> UInt32 {
        (0 ..< 4).reduce(UInt32(0)) { $0 | UInt32(self[offset + $1]) << (8 * $1) }
    }

    func le64(at offset: Int) -> UInt64 {
        (0 ..< 8).reduce(UInt64(0)) { $0 | UInt64(self[offset + $1]) << (8 * $1) }
    }

    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
}
