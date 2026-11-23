import Foundation

/// 256-bit arithmetic and secp256k1 for the CPU reference (see NexaPowReference.swift).
extension NexaPowReference {
    /// 256-bit value, lane 0 = least significant 64 bits.
    typealias U256 = SIMD4<UInt64>

    static let zero = U256(0, 0, 0, 0)
    static let one = U256(1, 0, 0, 0)

    /// 32 big-endian bytes to a value.
    static func value(be bytes: [UInt8]) -> U256 {
        precondition(bytes.count == 32)
        var v = zero
        for (i, byte) in bytes.enumerated() {
            let bit = (31 - i) * 8
            v[bit / 64] |= UInt64(byte) << UInt64(bit % 64)
        }
        return v
    }

    static func bytesBE(_ v: U256) -> [UInt8] {
        (0 ..< 32).map { i in
            let bit = (31 - i) * 8
            return UInt8(truncatingIfNeeded: v[bit / 64] >> UInt64(bit % 64))
        }
    }

    static func value(hex: String) -> U256 { value(be: [UInt8](hex: hex)!) }

    /// Little-endian 32-bit limbs (what the GPU uses).
    static func limbs32(_ v: U256) -> [UInt32] {
        (0 ..< 8).map { UInt32(truncatingIfNeeded: v[$0 / 2] >> UInt64(32 * ($0 % 2))) }
    }

    static func value(limbs32 l: [UInt32]) -> U256 {
        U256((0 ..< 4).map { UInt64(l[2 * $0]) | UInt64(l[2 * $0 + 1]) << 32 })
    }

    static func compare(_ a: U256, _ b: U256) -> Int {
        for i in (0 ..< 4).reversed() where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        return 0
    }

    static func add(_ a: U256, _ b: U256) -> (U256, Bool) {
        var r = zero
        var carry: UInt64 = 0
        for i in 0 ..< 4 {
            let (s1, o1) = a[i].addingReportingOverflow(b[i])
            let (s2, o2) = s1.addingReportingOverflow(carry)
            r[i] = s2
            carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return (r, carry != 0)
    }

    static func sub(_ a: U256, _ b: U256) -> (U256, Bool) {
        var r = zero
        var borrow: UInt64 = 0
        for i in 0 ..< 4 {
            let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            r[i] = d2
            borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return (r, borrow != 0)
    }

    static func shiftRight1(_ v: U256) -> U256 {
        U256(v[0] >> 1 | v[1] << 63, v[1] >> 1 | v[2] << 63, v[2] >> 1 | v[3] << 63, v[3] >> 1)
    }

    static func bit(_ v: U256, _ i: Int) -> Bool { (v[i / 64] >> UInt64(i % 64)) & 1 == 1 }

    /// Schoolbook product of little-endian 64-bit limb arrays.
    static func multiply(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var r = [UInt64](repeating: 0, count: a.count + b.count)
        for i in 0 ..< a.count {
            var carry: UInt64 = 0
            for j in 0 ..< b.count {
                let (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                let (s1, o1) = lo.addingReportingOverflow(r[i + j])
                let (s2, o2) = s1.addingReportingOverflow(carry)
                r[i + j] = s2
                carry = hi &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
            }
            r[i + b.count] = carry
        }
        return r
    }

    static func addLimbs(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var r = [UInt64](repeating: 0, count: max(a.count, b.count) + 1)
        var carry: UInt64 = 0
        for i in 0 ..< r.count - 1 {
            let (s1, o1) = (i < a.count ? a[i] : 0).addingReportingOverflow(i < b.count ? b[i] : 0)
            let (s2, o2) = s1.addingReportingOverflow(carry)
            r[i] = s2
            carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        r[r.count - 1] = carry
        return r
    }

    /// A prime modulus m > 2^255 with c = 2^256 - m, so 2^256 = c (mod m).
    struct Modulus {
        let m: U256
        let c: U256
        init(_ hex: String) {
            m = NexaPowReference.value(hex: hex)
            c = NexaPowReference.sub(NexaPowReference.zero, m).0
        }
    }

    /// secp256k1 field prime and group order.
    static let p = Modulus("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    static let n = Modulus("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

    /// Reduces any little-endian limb array modulo m by folding the part above 2^256 with c.
    static func reduce(_ wide: [UInt64], _ mod: Modulus) -> U256 {
        var t = wide
        while t.count < 4 { t.append(0) }
        while t.count > 4 {
            if t[4...].allSatisfy({ $0 == 0 }) {
                t.removeLast(t.count - 4)
                break
            }
            t = addLimbs(Array(t[0 ..< 4]), multiply(Array(t[4...]), [mod.c[0], mod.c[1], mod.c[2], mod.c[3]]))
            while t.count > 4 && t.last == 0 { t.removeLast() }
        }
        var r = U256(t[0], t[1], t[2], t[3])
        while compare(r, mod.m) >= 0 { r = sub(r, mod.m).0 }
        return r
    }

    static func modAdd(_ a: U256, _ b: U256, _ mod: Modulus) -> U256 {
        let (s, carry) = add(a, b)
        return carry || compare(s, mod.m) >= 0 ? sub(s, mod.m).0 : s
    }

    static func modSub(_ a: U256, _ b: U256, _ mod: Modulus) -> U256 {
        let (d, borrow) = sub(a, b)
        return borrow ? add(d, mod.m).0 : d
    }

    static func modMul(_ a: U256, _ b: U256, _ mod: Modulus) -> U256 {
        reduce(multiply([a[0], a[1], a[2], a[3]], [b[0], b[1], b[2], b[3]]), mod)
    }

    static func modPow(_ a: U256, _ e: U256, _ mod: Modulus) -> U256 {
        var r = one
        for i in (0 ..< 256).reversed() {
            r = modMul(r, r, mod)
            if bit(e, i) { r = modMul(r, a, mod) }
        }
        return r
    }

    /// Fermat inverse (both moduli are prime).
    static func modInverse(_ a: U256, _ mod: Modulus) -> U256 { modPow(a, sub(mod.m, U256(2, 0, 0, 0)).0, mod) }

    /// Euler's criterion: true when a is a nonzero square mod p (what secp256k1_fe_is_quad_var decides).
    static func isQuadraticResidue(_ a: U256) -> Bool { modPow(a, shiftRight1(sub(p.m, one).0), p) == one }

    // MARK: secp256k1 points

    struct Affine: Equatable {
        var x: U256
        var y: U256
    }

    struct Jacobian {
        var x: U256
        var y: U256
        var z: U256
        var infinity: Bool
        static let infinityPoint = Jacobian(x: zero, y: one, z: zero, infinity: true)
        init(x: U256, y: U256, z: U256, infinity: Bool = false) {
            self.x = x
            self.y = y
            self.z = z
            self.infinity = infinity
        }
        init(_ a: Affine) { self.init(x: a.x, y: a.y, z: one) }
    }

    static let G = Affine(x: value(hex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                          y: value(hex: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))

    static func fmul(_ a: U256, _ b: U256) -> U256 { modMul(a, b, p) }
    static func fsqr(_ a: U256) -> U256 { modMul(a, a, p) }
    static func fadd(_ a: U256, _ b: U256) -> U256 { modAdd(a, b, p) }
    static func fsub(_ a: U256, _ b: U256) -> U256 { modSub(a, b, p) }

    static func isOnCurve(_ a: Affine) -> Bool { fsqr(a.y) == fadd(fmul(fsqr(a.x), a.x), U256(7, 0, 0, 0)) }

    /// dbl-2009-l (a = 0).
    static func double(_ a: Jacobian) -> Jacobian {
        if a.infinity || a.y == zero { return .infinityPoint }
        let A = fsqr(a.x), B = fsqr(a.y), C = fsqr(B)
        let D2 = fsub(fsqr(fadd(a.x, B)), fadd(A, C))
        let D = fadd(D2, D2)
        let E = fadd(fadd(A, A), A)
        let x3 = fsub(fsqr(E), fadd(D, D))
        let C2 = fadd(C, C), C4 = fadd(C2, C2), C8 = fadd(C4, C4)
        let y3 = fsub(fmul(E, fsub(D, x3)), C8)
        let z3 = fmul(fadd(a.y, a.y), a.z)
        return Jacobian(x: x3, y: y3, z: z3)
    }

    /// add-2007-bl, with the doubling and inverse special cases.
    static func add(_ a: Jacobian, _ b: Jacobian) -> Jacobian {
        if a.infinity { return b }
        if b.infinity { return a }
        let z1z1 = fsqr(a.z), z2z2 = fsqr(b.z)
        let u1 = fmul(a.x, z2z2), u2 = fmul(b.x, z1z1)
        let s1 = fmul(fmul(a.y, b.z), z2z2), s2 = fmul(fmul(b.y, a.z), z1z1)
        if u1 == u2 { return s1 == s2 ? double(a) : .infinityPoint }
        let h = fsub(u2, u1)
        let i = fsqr(fadd(h, h))
        let j = fmul(h, i)
        let r = fadd(fsub(s2, s1), fsub(s2, s1))
        let v = fmul(u1, i)
        let x3 = fsub(fsub(fsqr(r), j), fadd(v, v))
        let s1j = fmul(s1, j)
        let y3 = fsub(fmul(r, fsub(v, x3)), fadd(s1j, s1j))
        let z3 = fmul(fsub(fsqr(fadd(a.z, b.z)), fadd(z1z1, z2z2)), h)
        return Jacobian(x: x3, y: y3, z: z3)
    }

    static func affine(_ a: Jacobian) -> Affine? {
        guard !a.infinity else { return nil }
        let zi = modInverse(a.z, p)
        let zi2 = fsqr(zi)
        return Affine(x: fmul(a.x, zi2), y: fmul(a.y, fmul(zi2, zi)))
    }

    /// k * point by plain double-and-add from the top bit.
    static func multiply(_ k: U256, _ point: Affine) -> Jacobian {
        var r = Jacobian.infinityPoint
        let base = Jacobian(point)
        for i in (0 ..< 256).reversed() {
            r = double(r)
            if bit(k, i) { r = add(r, base) }
        }
        return r
    }

    static func compressed(_ a: Affine) -> [UInt8] { [a.y[0] & 1 == 1 ? 0x03 : 0x02] + bytesBE(a.x) }
}
