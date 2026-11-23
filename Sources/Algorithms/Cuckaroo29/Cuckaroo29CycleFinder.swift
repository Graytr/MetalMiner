import Foundation

/// Cycle finding on the CPU over the edges left after trimming, by Tromp's cuckoo-hash path following (cuckoo.c,
/// cuckaroo/mean.hpp): the graph is kept as a forest of directed links in a hash table. Each new edge either joins two
/// trees (the shorter path to a root is reversed so the edge can hang off its start) or, when both ends already share
/// a root, closes a cycle of nu + nv + 1 edges and is not added. U nodes are stored as 2u and V nodes as 2v + 1, so
/// the two node sets never mix.
struct Cuckaroo29CycleFinder {
    static let maxPathLength = 8192
    private static let empty = UInt32.max
    private var keys: [UInt32]
    private var values: [UInt32]
    private let mask: Int

    init(edgeCount: Int) {
        var size = 1 << 10
        while size < 4 * max(edgeCount, 1) { size <<= 1 }
        keys = [UInt32](repeating: Self.empty, count: size)
        values = [UInt32](repeating: 0, count: size)
        mask = size - 1
    }

    @inline(__always) private func slot(_ node: UInt32) -> Int {
        Int(truncatingIfNeeded: (UInt64(node) &* 0x9E37_79B9_7F4A_7C15) >> 32) & mask
    }

    private func next(_ node: UInt32) -> UInt32? {
        var i = slot(node)
        while true {
            let key = keys[i]
            if key == node { return values[i] }
            if key == Self.empty { return nil }
            i = (i + 1) & mask
        }
    }

    private mutating func link(_ node: UInt32, to target: UInt32) {
        var i = slot(node)
        while keys[i] != Self.empty && keys[i] != node { i = (i + 1) & mask }
        keys[i] = node
        values[i] = target
    }

    /// `node`, then each node it links to, ending at its tree's root. False if longer than maxPathLength.
    private func path(from node: UInt32, into path: inout [UInt32]) -> Bool {
        path.removeAll(keepingCapacity: true)
        var n = node
        path.append(n)
        while let m = next(n) {
            n = m
            path.append(n)
            if path.count > Self.maxPathLength { return false }
        }
        return true
    }

    struct Result {
        /// Each cycle of the requested length as its edges' (u, v) pairs.
        var cycles: [[SIMD2<UInt32>]] = []
        /// How many cycles of any length were closed.
        var allCycles = 0
        /// Edges skipped because a path was too long (the graph wasn't trimmed enough).
        var pathOverflows = 0
    }

    /// Cycles of `length` edges among `edges`, given as (u, v) pairs.
    static func find(_ edges: [SIMD2<UInt32>], length: Int) -> Result {
        var finder = Cuckaroo29CycleFinder(edgeCount: edges.count)
        var result = Result()
        var us: [UInt32] = [], vs: [UInt32] = []
        us.reserveCapacity(64)
        vs.reserveCapacity(64)
        for e in edges {
            let u0 = e.x << 1, v0 = e.y << 1 | 1
            guard finder.path(from: u0, into: &us), finder.path(from: v0, into: &vs) else {
                result.pathOverflows += 1
                continue
            }
            var nu = us.count - 1, nv = vs.count - 1
            if us[nu] == vs[nv] {
                let common = min(nu, nv)
                nu -= common
                nv -= common
                while us[nu] != vs[nv] {
                    nu += 1
                    nv += 1
                }
                result.allCycles += 1
                if nu + nv + 1 == length {
                    var cycle: [SIMD2<UInt32>] = [e]
                    for i in 0 ..< nu { cycle.append(Self.edge(us[i], us[i + 1])) }
                    for i in 0 ..< nv { cycle.append(Self.edge(vs[i], vs[i + 1])) }
                    result.cycles.append(cycle)
                }
                continue
            }
            if nu < nv {
                while nu > 0 {
                    finder.link(us[nu], to: us[nu - 1])
                    nu -= 1
                }
                finder.link(u0, to: v0)
            } else {
                while nv > 0 {
                    finder.link(vs[nv], to: vs[nv - 1])
                    nv -= 1
                }
                finder.link(v0, to: u0)
            }
        }
        return result
    }

    /// The (u, v) pair of the edge between stored nodes a and b.
    private static func edge(_ a: UInt32, _ b: UInt32) -> SIMD2<UInt32> {
        a & 1 == 0 ? SIMD2(a >> 1, b >> 1) : SIMD2(b >> 1, a >> 1)
    }
}
