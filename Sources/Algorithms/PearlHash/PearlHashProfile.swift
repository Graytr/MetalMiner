import Foundation
import Metal

/// Development timing: `test pearlhash --set profile=N` times each kernel over N instances, and
/// `--set lab=1` runs the micro-benchmarks in pearlhash_lab.metal.
extension PearlHashAlgorithm {
    func profile(instances count: Int) throws -> String {
        try reserveInstances(count)
        for i in 0 ..< count { writeInstance(i, nonce: UInt64(i)) }
        let p = params(bound: [UInt32](repeating: 0, count: 8), writeHashes: false)
        func time(_ label: String, _ body: (MTLComputeCommandEncoder, Int) -> Void) throws -> Double {
            try gpu.compute(label) { encoder in
                p.withUnsafeBytes { encoder.setBytes($0.baseAddress!, length: $0.count, index: 0) }
                for i in 0 ..< count { body(encoder, i) }
            } / Double(count)
        }
        let noise = try time("noise") { encoder, i in
            encoder.setBuffer(instances, offset: i * Self.instanceStride, index: 1)
            encoder.setBuffer(ealBuffer, offset: 0, index: 2)
            encoder.setBuffer(ebrBuffer, offset: 0, index: 3)
            encoder.setBuffer(permABuffer, offset: 0, index: 4)
            encoder.setBuffer(permBBuffer, offset: 0, index: 5)
            gpu.dispatch(encoder, noisePipeline, threads: Int(p[4] + p[5] + 2 * p[6]), group: 64)
        }
        let apply = try time("apply") { encoder, i in
            encoder.setBuffer(instances, offset: i * Self.instanceStride, index: 1)
            encoder.setBuffer(aBuffer, offset: 0, index: 2)
            encoder.setBuffer(btBuffer, offset: 0, index: 3)
            encoder.setBuffer(ealBuffer, offset: 0, index: 4)
            encoder.setBuffer(ebrBuffer, offset: 0, index: 5)
            encoder.setBuffer(permABuffer, offset: 0, index: 6)
            encoder.setBuffer(permBBuffer, offset: 0, index: 7)
            encoder.setBuffer(anBuffer, offset: 0, index: 8)
            encoder.setBuffer(bnBuffer, offset: 0, index: 9)
            gpu.dispatch(encoder, applyPipeline, threads: (m + n) * config.k / 16, group: 256)
        }
        let mine = try time("mine") { encoder, i in
            encoder.setComputePipelineState(minePipeline)
            encoder.setBuffer(instances, offset: i * Self.instanceStride, index: 1)
            encoder.setBuffer(anBuffer, offset: 0, index: 2)
            encoder.setBuffer(bnBuffer, offset: 0, index: 3)
            encoder.setBuffer(hitsBuffer, offset: 0, index: 4)
            encoder.setBuffer(hitsBuffer, offset: 0, index: 5)
            encoder.dispatchThreadgroups(MTLSize(width: n / 64, height: m / 128, depth: 1),
                                         threadsPerThreadgroup: MTLSize(width: 256, height: 1, depth: 1))
        }
        let macs = Double(m) * Double(n) * Double(config.k)
        return "per instance: noise \(fmt(noise * 1e3, 3)) ms, apply \(fmt(apply * 1e3, 3)) ms, mine \(fmt(mine * 1e3, 3)) ms"
            + " (\(formatRate(macs / mine, "MAC/s")) in the search kernel); mine pipeline: max \(minePipeline.maxTotalThreadsPerThreadgroup) threads,"
            + " \(minePipeline.staticThreadgroupMemoryLength) B threadgroup memory"
    }

    /// Every pearlhash_lab_* kernel except _fma: 640 groups of 128 threads, each SIMD group 16 x iters MMAs.
    func lab() throws -> String {
        let library = try gpu.library(["pearlhash_lab.metal"])
        let groups = 640
        let out = try gpu.buffer(groups * 4 * 16 * 64 * 4, label: "lab out")
        var lines: [String] = []
        for name in library.functionNames.sorted() where name.hasPrefix("pearlhash_lab_") && name != "pearlhash_lab_fma" {
            let pipeline = try gpu.pipeline(library, name)
            var iters = UInt32(2048)
            let seconds = try gpu.compute(name) { encoder in
                encoder.setComputePipelineState(pipeline)
                encoder.setBuffer(out, offset: 0, index: 0)
                encoder.setBytes(&iters, length: 4, index: 1)
                encoder.dispatchThreadgroups(MTLSize(width: groups, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 128, height: 1, depth: 1))
            }
            let macs = Double(groups * 4) * Double(iters) * 16 * 512
            lines.append("\(name): \(formatRate(macs / seconds, "MAC/s")) (max threads \(pipeline.maxTotalThreadsPerThreadgroup))")
        }
        let fma = try gpu.pipeline(library, "pearlhash_lab_fma")
        var iters = UInt32(4096)
        let threads = 40 * 1024 * 4
        let seconds = try gpu.compute("fma") { encoder in
            encoder.setBuffer(out, offset: 0, index: 0)
            encoder.setBytes(&iters, length: 4, index: 1)
            gpu.dispatch(encoder, fma, threads: threads, group: 256)
        }
        lines.append("pearlhash_lab_fma: \(formatRate(Double(threads) * Double(iters) * 64 / seconds, "FMA/s"))")
        return lines.joined(separator: " | ")
    }
}
