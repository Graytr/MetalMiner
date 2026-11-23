// Draws the app icon into an .iconset folder (build.sh then runs iconutil on it).
//   make-icon <output.iconset>
// A scout's magnifying glass with the GPU's cube inside the lens, on a blue-violet tile.
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset")
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

func render(pixels: Int) -> Data? {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                                        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                        bytesPerRow: 0, bitsPerPixel: 0) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    let s = CGFloat(pixels) / 1024   // drawn on a 1024-point canvas
    // macOS icon grid: an 824 pt rounded square centred on the canvas.
    let tile = NSRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let shape = NSBezierPath(roundedRect: tile, xRadius: 185 * s, yRadius: 185 * s)
    NSGradient(colors: [NSColor(srgbRed: 0.10, green: 0.42, blue: 0.95, alpha: 1),
                        NSColor(srgbRed: 0.45, green: 0.20, blue: 0.85, alpha: 1)])?.draw(in: shape, angle: -60)

    // The lens: most of the tile, up and to the left to leave room for the handle.
    let center = NSPoint(x: 470 * s, y: 554 * s), radius = 272 * s
    let lens = NSBezierPath(ovalIn: NSRect(x: center.x - radius, y: center.y - radius, width: 2 * radius, height: 2 * radius))
    NSColor(white: 1, alpha: 0.14).setFill()   // the glass
    lens.fill()
    let shine = NSBezierPath()   // a highlight on the glass, upper left
    shine.appendArc(withCenter: center, radius: radius * 0.8, startAngle: 115, endAngle: 165)
    shine.lineWidth = 20 * s
    shine.lineCapStyle = .round
    NSColor(white: 1, alpha: 0.45).setStroke()
    shine.stroke()

    // The cube, inside the lens.
    if let cube = NSImage(systemSymbolName: "cube.transparent", accessibilityDescription: nil)?
        .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 330 * s, weight: .semibold)
            .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))) {
        let size = cube.size
        cube.draw(in: NSRect(x: center.x - size.width / 2, y: center.y - size.height / 2, width: size.width, height: size.height))
    }

    // The rim and the handle, to the lower right.
    NSColor.white.setStroke()
    lens.lineWidth = 46 * s
    lens.stroke()
    let handle = NSBezierPath()
    handle.move(to: NSPoint(x: center.x + radius * 0.75, y: center.y - radius * 0.75))
    handle.line(to: NSPoint(x: 822 * s, y: 202 * s))
    handle.lineWidth = 88 * s
    handle.lineCapStyle = .round
    handle.stroke()

    NSGraphicsContext.restoreGraphicsState()
    return bitmap.representation(using: .png, properties: [:])
}

for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"
        guard let png = render(pixels: points * scale) else { fatalError("can't draw \(name)") }
        try png.write(to: output.appendingPathComponent(name))
    }
}
