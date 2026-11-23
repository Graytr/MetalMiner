import Foundation
import Metal

/// GPU-against-CPU checks for XelisHashV3.
extension XelisHashV3 {
    func crossCheck(samples: Int) throws -> String {
        let primitiveCount = try checkPrimitives()

        // 1. Random MinerWork and nonces: every full hash, and the hit list against a 1-in-4 target.
        let n = max(1, min(max(samples, checkSamples), slots))
        let randomWork = randomBytes(112)
        let start = UInt64.random(in: 0 ... UInt64.max - UInt64(n))
        var target = [UInt8](repeating: 0xFF, count: 32)
        target[0] = 0x3F
        let gpu1 = try search(work: randomWork, target: target, start: start, count: n)
        let nonces = (0 ..< n).map { start &+ UInt64($0) }
        let cpuStart = now()
        let cpu = XelisHashReference.V3.hashes(work: randomWork, nonces: nonces)
        let cpuRate = Double(n) / max(now() - cpuStart, 1e-6)
        for k in 0 ..< n where gpu1.hashes[k] != cpu[k] {
            throw MinerError("nonce \(String(nonces[k], radix: 16)): GPU \(gpu1.hashes[k].hex) vs CPU \(cpu[k].hex)")
        }
        let expected = Set((0 ..< n).filter { XelisHashReference.meets(cpu[$0], target) }.map { nonces[$0] })
        let reported = Set(gpu1.hits)
        guard gpu1.hits.count == min(expected.count, 62), reported.isSubset(of: expected),
              expected.count > 62 || reported == expected else {
            throw MinerError("hit list differs: GPU \(gpu1.hits.count) hits, CPU expects \(expected.count)")
        }

        // 2. A real mainnet block: the kernel must find its nonce under its network target.
        let block = XelisHashReference.mainnetBlocks[0]
        let blockWork = try block.minerWork()
        let blockTarget = XelisHashReference.target(difficulty: block.difficulty)
        let gpu2 = try search(work: blockWork, target: blockTarget, start: block.nonce &- 8, count: 16)
        guard gpu2.hits.contains(block.nonce) else {
            throw MinerError("block \(block.height): GPU did not report nonce \(block.nonce) (hits \(gpu2.hits))")
        }
        guard gpu2.hashes[8] == XelisHashReference.V3.hash(blockWork) else {
            throw MinerError("block \(block.height): GPU PoW hash \(gpu2.hashes[8].hex) differs from the CPU")
        }
        return "\(n) random nonces: full hashes match the CPU, \(expected.count) hits at a 1/4 target match"
            + " · block \(block.height) nonce found under its network target"
            + " · \(primitiveCount) primitive cases (isqrt, u128 div, AES, modpow, map_index) match"
            + " · (Swift CPU reference ran at \(fmt(cpuRate, 0)) H/s on \(ProcessInfo.processInfo.activeProcessorCount) cores)"
    }

    private struct PrimitiveCase {
        var op: UInt32
        var x: UInt64, y: UInt64, z: UInt64, w: UInt64
    }

    /// GPU arithmetic against the CPU on the rare paths random hashes almost never reach.
    private func checkPrimitives() throws -> Int {
        typealias R = XelisHashReference
        func rnd() -> UInt64 { UInt64.random(in: 0 ... UInt64.max) }
        func rndBits() -> UInt64 { rnd() >> UInt64.random(in: 0 ... 63) }
        var cases: [PrimitiveCase] = []

        // isqrt: the f64 reference's wrap-around region near 2^64, squares +-1 at many magnitudes, random
        var roots: [UInt64] = [0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 24, 25, 26, .max, .max - 1, .max - 1022, .max - 1023,
                               .max - 1024, .max - 2047, 0xFFFF_FFFE_0000_0000, 0xFFFF_FFFE_0000_0001,
                               0xFFFF_FFFE_0000_0002, 0xFFFF_FFFE_FFFF_FFFF, 1 << 63, (1 << 63) - 1, (1 << 53) + 1, (1 << 54) + 3]
        for k: UInt64 in [3, 1 << 12, 1 << 16, 1 << 24, (1 << 26) + 1, 1 << 31, (1 << 31) + 12345,
                          0xFFFF_FFF0, 0xFFFF_FFFD, 0xFFFF_FFFE, 0xFFFF_FFFF] {
            roots += [k &* k &- 1, k &* k, k &* k &+ 1]
        }
        for _ in 0 ..< 48 {
            let k = rnd() >> UInt64.random(in: 32 ... 40)
            roots += [k &* k &- 1, k &* k, rndBits()]
        }
        cases += roots.map { PrimitiveCase(op: 0, x: $0, y: 0, z: 0, w: 0) }

        // u128 division: 64-bit divisors (with high word above and below the divisor), 128-bit divisors,
        // and numerators built as q * D + rem next to the correction steps
        var divs: [(UInt64, UInt64, UInt64, UInt64)] = [
            (0, 0, 0, 1), (rnd(), rnd(), 0, 1), (rnd(), rnd(), 0, 2), (rnd(), rnd(), 0, .max), (rnd(), rnd(), 0, 1 << 63),
            (.max, .max, 0, 3), (0, rnd(), 0, rnd() | 1), (5, rnd(), 0, 7), (1, 0, 1, 0), (1, 5, 1, 4), (1, 3, 1, 4),
            (.max, .max, .max, .max), (.max, .max, .max, .max - 1), (.max, .max - 1, .max, .max), (.max, .max, 1, 0),
            (.max, .max, 1, .max), (rnd(), rnd(), 1, rnd()), (rnd(), rnd(), 1 << 63, rnd()), (0, 0, 1, 0),
        ]
        for _ in 0 ..< 64 {
            divs.append((rnd(), rnd(), rndBits(), rnd()))
            divs.append((rnd(), rnd(), 0, rndBits() | 1))
            divs.append((rndBits(), rnd(), rndBits(), rnd()))
            let d = R.combine(rndBits(), rnd() | 1)
            let q = UInt128(rndBits())
            let (product, overflow) = d.multipliedReportingOverflow(by: q)
            if !overflow {
                for delta in [UInt128(0), 1, d - 1] {
                    let (num, o2) = product.addingReportingOverflow(delta)
                    if !o2 {
                        divs.append((UInt64(truncatingIfNeeded: num >> 64), UInt64(truncatingIfNeeded: num),
                                     UInt64(truncatingIfNeeded: d >> 64), UInt64(truncatingIfNeeded: d)))
                    }
                }
            }
        }
        cases += divs.filter { $0.2 != 0 || $0.3 != 0 }.map { PrimitiveCase(op: 1, x: $0.0, y: $0.1, z: $0.2, w: $0.3) }

        // AES round: every S-box input appears once, plus random blocks
        for k in 0 ..< 16 {
            var block: [UInt8] = []
            for i in 0 ..< 16 { block.append(UInt8(16 * k + i)) }
            cases.append(PrimitiveCase(op: 2, x: block.le64(at: 0), y: block.le64(at: 8), z: 0, w: 0))
        }
        for _ in 0 ..< 16 { cases.append(PrimitiveCase(op: 2, x: rnd(), y: rnd(), z: 0, w: 0)) }

        // modular power, as used between the two stage-3 passes (exponent < 2^32) and beyond
        let pows: [(UInt64, UInt64, UInt64)] = [(rnd(), rnd() >> 32, rnd()), (rnd(), 0, rnd()), (rnd(), rnd() >> 32, 1),
                                                (0, 5, 7), (rnd(), 0xFFFF_FFFF, .max), (rnd(), rnd() >> 32, 1 << 63),
                                                (rnd(), 12345, 3), (rnd(), rnd(), rnd()), (.max, .max, .max - 58)]
        cases += pows.map { PrimitiveCase(op: 3, x: $0.0, y: $0.1, z: $0.2, w: 0) }
        for _ in 0 ..< 16 { cases.append(PrimitiveCase(op: 3, x: rnd(), y: rnd() >> 32, z: rndBits() | 1, w: 0)) }

        // map_index / murmurhash3, mulhi / pick_half
        for v in [0, 1, UInt64.max, 1 << 63] + (0 ..< 16).map({ _ in rnd() }) {
            cases.append(PrimitiveCase(op: 4, x: v, y: 0, z: 0, w: 0))
            cases.append(PrimitiveCase(op: 5, x: v, y: rnd(), z: 0, w: 0))
        }
        cases.append(PrimitiveCase(op: 5, x: .max, y: .max, z: 0, w: 0))

        var raw: [UInt64] = []
        for c in cases { raw += [c.x, c.y, c.z, c.w, UInt64(c.op)] }   // XhPrimCase: x, y, z, w, op, pad
        let input = try gpu.buffer(raw, label: "xelishash primitive cases")
        let results = try gpu.buffer(cases.count * 16, label: "xelishash primitive results")
        var count = UInt32(cases.count)
        try gpu.compute("xelishash primitives") { encoder in
            encoder.setBuffer(input, offset: 0, index: 0)
            encoder.setBuffer(results, offset: 0, index: 1)
            encoder.setBytes(&count, length: 4, index: 2)
            gpu.dispatch(encoder, primitivePipeline, threads: cases.count, group: 64)
        }
        let out = results.contents().bindMemory(to: UInt64.self, capacity: cases.count * 2)
        for (k, c) in cases.enumerated() {
            let expected: (UInt64, UInt64)
            switch c.op {
            case 0: expected = (R.V3.isqrt(c.x), 0)
            case 1:
                let num = R.combine(c.x, c.y), den = R.combine(c.z, c.w)
                expected = (UInt64(truncatingIfNeeded: num / den), UInt64(truncatingIfNeeded: num % den))
            case 2: expected = R.AES.round(lo: c.x, hi: c.y, key: R.V3.key)
            case 3: expected = (R.V3.modularPower(c.x, c.y, c.z), 0)
            case 4: expected = (UInt64(R.V3.mapIndex(c.x)), R.murmurhash3(c.x))
            default: expected = (c.x.multipliedFullWidth(by: c.y).high, R.V3.pickHalf(c.x) ? 1 : 0)
            }
            guard out[2 * k] == expected.0, out[2 * k + 1] == expected.1 else {
                let args = [c.x, c.y, c.z, c.w].map { String($0, radix: 16) }.joined(separator: ", ")
                throw MinerError("primitive op \(c.op) (\(args)): GPU (\(String(out[2 * k], radix: 16)), "
                    + "\(String(out[2 * k + 1], radix: 16))) vs CPU (\(String(expected.0, radix: 16)), \(String(expected.1, radix: 16)))")
            }
        }
        return cases.count
    }
}
