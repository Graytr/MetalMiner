import Foundation

enum QuietTests {
    /// Fans that idle at 2,000 RPM and top out at 7,000.
    static func fans(_ rpm: Double...) -> [FanSensor.Fan] { rpm.map { FanSensor.Fan(rpm: $0, minimum: 2000, maximum: 7000) } }

    static let suite = TestSuite(name: "Quiet", tests: [
        ("fan level: 0 at the minimum or off, 1 at the maximum, the busiest fan counts", { expect in
            expect.near(FanSensor.level(fans(2000, 2000)), 0, within: 1e-12)
            expect.near(FanSensor.level(fans(0, 0)), 0, within: 1e-12)
            expect.near(FanSensor.level(fans(2500, 4500)), 0.5, within: 1e-12)
            expect.near(FanSensor.level(fans(9000)), 1, within: 1e-12)
            expect.near(FanSensor.level([]), 0, within: 1e-12)
        }),
        ("the throttle's duty is clamped, and it rests in proportion", { expect in
            let throttle = GPUThrottle.shared
            defer { throttle.duty = 1 }
            throttle.duty = 5
            expect.equal(throttle.duty, 1)
            throttle.duty = 0
            expect.equal(throttle.duty, 0.02)
            throttle.duty = 1
            var start = now()
            throttle.rest(after: 0.05)
            expect.that(now() - start < 0.01, "rested \(fmt(now() - start, 3)) s at full duty")
            throttle.duty = 0.5   // 20 ms of work at 50%: rest 20 ms
            start = now()
            throttle.rest(after: 0.02)
            let rested = now() - start
            expect.that(rested >= 0.019 && rested < 0.1, "rested \(fmt(rested, 3)) s, expected about 0.02 s")
        }),
        ("the duty settles where the GPU draws the power target", { expect in
            GPUThrottle.shared.duty = 1
            defer { GPUThrottle.shared.duty = 1 }
            let quiet = QuietController(readFans: { nil })
            // A GPU drawing 0.5 W idle plus 30 W at full duty, ticked every 2 s (before the first fan check at 20 s).
            for i in 0 ..< 10 { quiet.tick(gpuWatts: 0.5 + 30 * GPUThrottle.shared.duty, at: Double(i) * 2) }
            expect.near(0.5 + 30 * GPUThrottle.shared.duty, quiet.targetWatts, within: 0.3)
        }),
        ("loud fans that aren't easing lower the target; easing ones don't", { expect in
            var reading = fans(6000, 6000)   // level 0.8
            let quiet = QuietController(readFans: { reading })
            quiet.tick(gpuWatts: nil, at: 20)   // the first look only notes the fans
            expect.equal(quiet.targetWatts, 10)
            quiet.tick(gpuWatts: nil, at: 40)
            expect.near(quiet.targetWatts, 8.5, within: 1e-9)
            reading = fans(4500, 4500)   // level 0.5: easing
            quiet.tick(gpuWatts: nil, at: 60)
            expect.near(quiet.targetWatts, 8.5, within: 1e-9)
            quiet.tick(gpuWatts: nil, at: 80)   // still 0.5: not easing any more
            expect.near(quiet.targetWatts, 7.225, within: 1e-9)
        }),
        ("fans quiet for two minutes raise the target slowly", { expect in
            let quiet = QuietController(readFans: { fans(2000, 2050) })
            for t in stride(from: 20.0, through: 140, by: 20) { quiet.tick(gpuWatts: nil, at: t) }
            expect.equal(quiet.targetWatts, 10)   // quiet since 40 s: not two minutes yet
            quiet.tick(gpuWatts: nil, at: 160)
            expect.near(quiet.targetWatts, 10.3, within: 1e-9)
        }),
        ("the target stays between 3 W and 60 W", { expect in
            let loud = QuietController(readFans: { fans(7000) })
            for t in stride(from: 20.0, through: 2000, by: 20) { loud.tick(gpuWatts: nil, at: t) }
            expect.equal(loud.targetWatts, 3)
            let calm = QuietController(readFans: { fans(0, 0) })
            for t in stride(from: 20.0, through: 8000, by: 20) { calm.tick(gpuWatts: nil, at: t) }
            expect.equal(calm.targetWatts, 60)
        }),
        ("stop returns the GPU to full speed", { expect in
            GPUThrottle.shared.duty = 0.3
            QuietController(readFans: { nil }).stop()
            expect.equal(GPUThrottle.shared.duty, 1)
        }),
    ])
}
