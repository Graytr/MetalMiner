import Foundation
import IOKit
import Metal

/// The Metal device plus what every algorithm needs: runtime kernel compilation, buffers, dispatch.
final class GPU {
    let device: MTLDevice
    let queue: MTLCommandQueue
    /// Where the Metal kernel sources are, and where results go (see MinerPaths).
    let kernelsDirectory: URL
    let dataDirectory: URL
    private var libraries: [String: MTLLibrary] = [:]

    init() throws {
        guard let device = MTLCreateSystemDefaultDevice() else { throw MinerError("no Metal device") }
        guard let queue = device.makeCommandQueue() else { throw MinerError("can't create a Metal command queue") }
        self.device = device
        self.queue = queue
        kernelsDirectory = try MinerPaths.kernels()
        dataDirectory = try MinerPaths.data()
    }

    var info: String {
        let cores = GPU.coreCount.map { "\($0)-core GPU, " } ?? ""
        let memory = formatBytes(Int(ProcessInfo.processInfo.physicalMemory))
        return "\(device.name) (\(cores)\(memory)) · working set \(formatBytes(Int(device.recommendedMaxWorkingSetSize)))"
            + " · max buffer \(formatBytes(device.maxBufferLength)) · thermal \(thermalState)"
    }

    var thermalState: String {
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "unknown"
        }
    }

    /// Every Metal GPU macOS exposes. Apple silicon Macs have exactly one, built in: macOS has no eGPU support on
    /// Apple silicon, and the macOS 27 SDK deprecates GPU location and removability as not applicable to it.
    static func allDevices() -> [String] {
        MTLCopyAllDevices().map { device in
            device.name + (device.hasUnifiedMemory ? " · built-in, unified memory" : "")
                + " · GPU working set \(formatBytes(Int(device.recommendedMaxWorkingSetSize)))"
        }
    }

    /// GPU core count from the IORegistry (read-only).
    static var coreCount: Int? {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AGXAccelerator"), &iterator) == KERN_SUCCESS else {
            return nil
        }
        defer { IOObjectRelease(iterator) }
        var service = IOIteratorNext(iterator)
        while service != 0 {
            let value = IORegistryEntryCreateCFProperty(service, "gpu-core-count" as CFString, kCFAllocatorDefault, 0)?
                .takeRetainedValue()
            IOObjectRelease(service)
            if let cores = value as? Int { return cores }
            service = IOIteratorNext(iterator)
        }
        return nil
    }

    /// Text of a file in Kernels/.
    func kernelSource(_ file: String) throws -> String {
        try String(contentsOf: kernelsDirectory.appendingPathComponent(file), encoding: .utf8)
    }

    /// Compiles Kernels/common.metal followed by the named files (from Kernels/) as one library.
    /// Runtime-compiled Metal source can't #include our own files, so they're concatenated in order.
    func library(_ files: [String], macros: [String: String] = [:]) throws -> MTLLibrary {
        var source = ""
        for file in files {
            source += "\n// ---- \(file) ----\n"
            source += try kernelSource(file)
        }
        let key = (files + macros.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }).joined(separator: "|")
        return try library(source: source, key: key, macros: macros)
    }

    /// Compiles Kernels/common.metal followed by `source` (for example a generated per-period program),
    /// cached under `key`.
    func library(source: String, key: String, macros: [String: String] = [:]) throws -> MTLLibrary {
        if let library = libraries[key] { return library }
        let full = try kernelSource("common.metal") + "\n" + source
        let options = MTLCompileOptions()
        if !macros.isEmpty { options.preprocessorMacros = macros.mapValues { $0 as NSString } }
        do {
            let library = try device.makeLibrary(source: full, options: options)
            libraries[key] = library
            return library
        } catch {
            throw MinerError("Metal compile failed for \(key):\n\(error)")
        }
    }

    func pipeline(_ library: MTLLibrary, _ function: String) throws -> MTLComputePipelineState {
        guard let fn = library.makeFunction(name: function) else { throw MinerError("kernel \(function) not found") }
        return try device.makeComputePipelineState(function: fn)
    }

    /// CPU-visible buffer of `length` bytes (zero-filled).
    func buffer(_ length: Int, label: String) throws -> MTLBuffer {
        guard let buffer = device.makeBuffer(length: max(length, 16), options: .storageModeShared) else {
            throw MinerError("can't allocate \(formatBytes(length)) for \(label)")
        }
        buffer.label = label
        return buffer
    }

    /// CPU-visible buffer holding a copy of `array`.
    func buffer<T>(_ array: [T], label: String) throws -> MTLBuffer {
        let length = array.count * MemoryLayout<T>.stride
        guard length > 0 else { return try buffer(16, label: label) }
        let made = array.withUnsafeBytes { device.makeBuffer(bytes: $0.baseAddress!, length: length, options: .storageModeShared) }
        guard let buffer = made else { throw MinerError("can't allocate \(formatBytes(length)) for \(label)") }
        buffer.label = label
        return buffer
    }

    /// GPU-only buffer, for big tables such as DAGs that the CPU never reads.
    func privateBuffer(_ length: Int, label: String) throws -> MTLBuffer {
        guard let buffer = device.makeBuffer(length: max(length, 16), options: .storageModePrivate) else {
            throw MinerError("can't allocate \(formatBytes(length)) for \(label)")
        }
        buffer.label = label
        return buffer
    }

    /// Encodes a 1-D dispatch of `threads` threads.
    func dispatch(_ encoder: MTLComputeCommandEncoder, _ pipeline: MTLComputePipelineState, threads: Int, group: Int = 256) {
        let width = min(group, pipeline.maxTotalThreadsPerThreadgroup)
        encoder.setComputePipelineState(pipeline)
        encoder.dispatchThreads(MTLSize(width: threads, height: 1, depth: 1),
                                threadsPerThreadgroup: MTLSize(width: width, height: 1, depth: 1))
    }

    /// Runs one command buffer and waits for it, then rests if quiet mode is holding the GPU back (GPUThrottle).
    /// Returns GPU seconds; throws on GPU errors such as watchdog timeouts.
    @discardableResult
    func run(_ label: String, _ encode: (MTLCommandBuffer) throws -> Void) throws -> Double {
        guard let commands = queue.makeCommandBuffer() else { throw MinerError("can't create a command buffer") }
        commands.label = label
        try encode(commands)
        commands.commit()
        commands.waitUntilCompleted()
        if let error = commands.error { throw MinerError("GPU error in \(label): \(error.localizedDescription)") }
        let seconds = commands.gpuEndTime - commands.gpuStartTime
        GPUThrottle.shared.rest(after: seconds)
        return seconds
    }

    /// Runs one compute encoder in its own command buffer and waits for it. Returns GPU seconds.
    @discardableResult
    func compute(_ label: String, _ body: (MTLComputeCommandEncoder) throws -> Void) throws -> Double {
        try run(label) { commands in
            guard let encoder = commands.makeComputeCommandEncoder() else { throw MinerError("can't create a compute encoder") }
            try body(encoder)
            encoder.endEncoding()
        }
    }
}
