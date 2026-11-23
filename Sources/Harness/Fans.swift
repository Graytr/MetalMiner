import Foundation
import IOKit

/// The Mac's fan speeds, read from its System Management Controller (read-only; no admin rights needed). nil on Macs
/// without fans, or when the SMC can't be opened.
final class FanSensor {
    struct Fan {
        let rpm: Double
        let minimum: Double
        let maximum: Double
    }

    static let shared: FanSensor? = FanSensor()

    private let connection: io_connect_t
    private let count: Int
    private let lock = NSLock()

    private init?() {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSMC"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        var connection: io_connect_t = 0
        guard IOServiceOpen(service, mach_task_self_, 0, &connection) == KERN_SUCCESS else { return nil }
        guard let fans = Self.value(connection, "FNum"), fans >= 1 else {
            IOServiceClose(connection)
            return nil
        }
        self.connection = connection
        count = Int(fans)
    }

    deinit { IOServiceClose(connection) }

    /// Every fan's current, minimum and maximum speed in RPM. A fan that's off reads 0.
    func read() -> [Fan] {
        lock.lock()
        defer { lock.unlock() }
        return (0 ..< count).compactMap { i in
            guard let rpm = Self.value(connection, "F\(i)Ac"), let minimum = Self.value(connection, "F\(i)Mn"),
                  let maximum = Self.value(connection, "F\(i)Mx") else { return nil }
            return Fan(rpm: rpm, minimum: minimum, maximum: maximum)
        }
    }

    /// How hard the busiest fan works: 0 at or below its minimum speed (or off), 1 at its maximum.
    static func level(_ fans: [Fan]) -> Double {
        fans.map { fan in fan.maximum > fan.minimum ? (fan.rpm - fan.minimum) / (fan.maximum - fan.minimum) : 0 }
            .map { min(1, max(0, $0)) }
            .max() ?? 0
    }

    // The SMC's 80-byte key-data struct, filled by offset: key (0), keyInfo.dataSize (28), keyInfo.dataType (32),
    // result (40), command (42), value bytes (48 on).
    private static func value(_ connection: io_connect_t, _ key: String) -> Double? {
        let code = key.utf8.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        var request = [UInt8](repeating: 0, count: 80)
        put(&request, 0, code)
        request[42] = 9   // get key info
        guard let info = call(connection, request) else { return nil }
        let size = get(info, 28), type = get(info, 32)
        guard size > 0, size <= 32 else { return nil }
        request = [UInt8](repeating: 0, count: 80)
        put(&request, 0, code)
        put(&request, 28, size)
        request[42] = 5   // read key
        guard let reply = call(connection, request) else { return nil }
        let bytes = Array(reply[48 ..< 48 + Int(size)])
        switch type {
        case 0x666C_7420:   // "flt " (Apple silicon)
            guard bytes.count >= 4 else { return nil }
            return Double(bytes.withUnsafeBytes { $0.loadUnaligned(as: Float.self) })
        case 0x7569_3820:   // "ui8 "
            return Double(bytes[0])
        case 0x6670_6532:   // "fpe2" (Intel)
            guard bytes.count >= 2 else { return nil }
            return Double(UInt16(bytes[0]) << 8 | UInt16(bytes[1])) / 4
        default:
            return nil
        }
    }

    private static func call(_ connection: io_connect_t, _ input: [UInt8]) -> [UInt8]? {
        var output = [UInt8](repeating: 0, count: 80)
        var size = 80
        let result = input.withUnsafeBytes { inp in
            output.withUnsafeMutableBytes { out in
                IOConnectCallStructMethod(connection, 2, inp.baseAddress, 80, out.baseAddress, &size)
            }
        }
        return result == KERN_SUCCESS && output[40] == 0 ? output : nil
    }

    private static func put(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
        withUnsafeBytes(of: value) { for i in 0 ..< 4 { bytes[offset + i] = $0[i] } }
    }

    private static func get(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        bytes[offset ..< offset + 4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
    }
}
