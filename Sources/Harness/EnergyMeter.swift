import Foundation

/// The chip's energy counters (IOReport "Energy Model" group), the source Apple's powermetrics reads. IOReport is a
/// private but read-only API: it's loaded at runtime, needs no admin rights, and on a Mac where it's missing the
/// meter is simply nil. Readings are per channel (CPU clusters, GPU, DRAM, ...), in joules between two samples.
final class EnergyMeter {
    struct Reading {
        let seconds: Double
        /// Joules per channel name over the interval.
        let joules: [String: Double]
        /// Channels whose unit wasn't an energy unit we know, with that unit (for diagnosis).
        var skipped: [String: String] = [:]
        var totalWatts: Double { seconds > 0 ? joules.values.reduce(0, +) / seconds : 0 }
        var gpuWatts: Double { seconds > 0 ? joules.filter { $0.key.uppercased().contains("GPU") }.values.reduce(0, +) / seconds : 0 }
    }

    private typealias CopyChannelsInGroup = @convention(c) (CFString?, CFString?, UInt64, UInt64, UInt64) -> Unmanaged<CFDictionary>?
    private typealias CreateSubscription = @convention(c) (UnsafeMutableRawPointer?, CFMutableDictionary,
                                                           UnsafeMutablePointer<Unmanaged<CFMutableDictionary>?>, UInt64,
                                                           CFTypeRef?) -> Unmanaged<AnyObject>?
    private typealias CreateSamples = @convention(c) (AnyObject, CFMutableDictionary, CFTypeRef?) -> Unmanaged<CFDictionary>?
    private typealias CreateSamplesDelta = @convention(c) (CFDictionary, CFDictionary, CFTypeRef?) -> Unmanaged<CFDictionary>?
    private typealias ChannelString = @convention(c) (CFDictionary) -> Unmanaged<CFString>?
    private typealias SimpleIntegerValue = @convention(c) (CFDictionary, Int32) -> Int64

    private let createSamples: CreateSamples
    private let createSamplesDelta: CreateSamplesDelta
    private let channelName: ChannelString
    private let unitLabel: ChannelString
    private let integerValue: SimpleIntegerValue
    private let subscription: AnyObject
    private let channels: CFMutableDictionary
    private let lock = NSLock()

    /// Shared meter, or nil when IOReport or its energy channels aren't available.
    static let shared: EnergyMeter? = EnergyMeter()

    private init?() {
        guard let library = dlopen("/usr/lib/libIOReport.dylib", RTLD_NOW) else { return nil }
        func symbol<T>(_ name: String, _ type: T.Type) -> T? {
            dlsym(library, name).map { unsafeBitCast($0, to: type) }
        }
        guard let copyChannels = symbol("IOReportCopyChannelsInGroup", CopyChannelsInGroup.self),
              let subscribe = symbol("IOReportCreateSubscription", CreateSubscription.self),
              let samples = symbol("IOReportCreateSamples", CreateSamples.self),
              let delta = symbol("IOReportCreateSamplesDelta", CreateSamplesDelta.self),
              let name = symbol("IOReportChannelGetChannelName", ChannelString.self),
              let unit = symbol("IOReportChannelGetUnitLabel", ChannelString.self),
              let value = symbol("IOReportSimpleGetIntegerValue", SimpleIntegerValue.self),
              let group = copyChannels("Energy Model" as CFString, nil, 0, 0, 0)?.takeRetainedValue(),
              let desired = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, group) else { return nil }
        var subscribed: Unmanaged<CFMutableDictionary>?
        guard let sub = subscribe(nil, desired, &subscribed, 0, nil)?.takeRetainedValue(),
              let subscribedChannels = subscribed?.takeRetainedValue() else { return nil }
        createSamples = samples
        createSamplesDelta = delta
        channelName = name
        unitLabel = unit
        integerValue = value
        subscription = sub
        channels = subscribedChannels
    }

    /// An opaque snapshot of the counters plus when it was taken.
    struct Sample {
        fileprivate let counters: CFDictionary
        fileprivate let time: Double
    }

    func sample() -> Sample? {
        lock.lock()
        defer { lock.unlock() }
        guard let counters = createSamples(subscription, channels, nil)?.takeRetainedValue() else { return nil }
        return Sample(counters: counters, time: now())
    }

    /// Joules per channel between two samples.
    func reading(from start: Sample, to end: Sample) -> Reading? {
        guard let delta = createSamplesDelta(start.counters, end.counters, nil)?.takeRetainedValue(),
              let items = (delta as NSDictionary)["IOReportChannels"] as? [NSDictionary] else { return nil }
        var joules: [String: Double] = [:]
        var skipped: [String: String] = [:]
        for item in items {
            let channel = item as CFDictionary
            guard let name = channelName(channel)?.takeUnretainedValue() as String? else { continue }
            let scale: Double
            switch unitLabel(channel)?.takeUnretainedValue() as String? {
            case "mJ": scale = 1e-3
            case "uJ", "µJ": scale = 1e-6
            case "nJ": scale = 1e-9
            default:
                skipped[name] = (unitLabel(channel)?.takeUnretainedValue() as String?) ?? "(none)"
                continue
            }
            joules[name, default: 0] += Double(integerValue(channel, 0)) * scale
        }
        return Reading(seconds: end.time - start.time, joules: joules, skipped: skipped)
    }

    /// Average power over `seconds` from now (blocks).
    func measure(seconds: Double) -> Reading? {
        guard let start = sample() else { return nil }
        Thread.sleep(forTimeInterval: seconds)
        guard let end = sample() else { return nil }
        return reading(from: start, to: end)
    }
}
