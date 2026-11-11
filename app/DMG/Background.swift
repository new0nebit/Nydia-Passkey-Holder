import AppKit
import CoreText
import ImageIO
import UniformTypeIdentifiers

enum Background {
    static func image(scale: Int) throws -> CGImage {
        guard [1, 2].contains(scale),
              let space = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(data: nil, width: Layout.width * scale, height: Layout.height * scale,
                  bitsPerComponent: 8, bytesPerRow: 0, space: space,
                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw DMGError("Cannot allocate the background at the requested scale")
        }
        context.translateBy(x: 0, y: CGFloat(Layout.height * scale))
        context.scaleBy(x: CGFloat(scale), y: -CGFloat(scale))
        let colors = [color(0xfff7ed), color(0xffedd5), color(0xffe4e6)] as CFArray
        guard let gradient = CGGradient(colorsSpace: space, colors: colors, locations: [0, 0.48, 1]) else {
            throw DMGError("Cannot create the background gradient")
        }
        let inset = CGFloat(Layout.width - Layout.height) / 4
        context.drawLinearGradient(gradient, start: CGPoint(x: inset, y: -inset),
            end: CGPoint(x: CGFloat(Layout.width) - inset, y: CGFloat(Layout.height) + inset),
            options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
        drawLeaves(context)
        drawCaption(context)
        guard let image = context.makeImage() else { throw DMGError("Cannot read the rendered background") }
        return image
    }

    static func write(to url: URL) throws {
        guard let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.tiff.identifier as CFString, 2, nil) else {
            throw DMGError("Cannot create the Retina TIFF")
        }
        for scale in [1, 2] {
            let properties: [CFString: Any] = [
                kCGImagePropertyDPIWidth: 72 * scale,
                kCGImagePropertyDPIHeight: 72 * scale,
                kCGImagePropertyTIFFDictionary: [kCGImagePropertyTIFFCompression: 5]
            ]
            CGImageDestinationAddImage(destination, try image(scale: scale), properties as CFDictionary)
        }
        guard CGImageDestinationFinalize(destination) else { throw DMGError("Cannot write the Retina TIFF") }
    }

    private static func color(_ rgb: UInt32, alpha: CGFloat = 1) -> CGColor {
        CGColor(srgbRed: CGFloat((rgb >> 16) & 255) / 255,
            green: CGFloat((rgb >> 8) & 255) / 255, blue: CGFloat(rgb & 255) / 255, alpha: alpha)
    }

    private static func drawCaption(_ context: CGContext) {
        let font = NSFont.systemFont(ofSize: CGFloat(Layout.textSize))
        let text = NSAttributedString(string: "Drag \(Layout.appName) to Applications", attributes: [
            .font: font, .foregroundColor: NSColor(cgColor: color(0x9a6b4f))!, .kern: 0.13
        ])
        let line = CTLineCreateWithAttributedString(text)
        var ascent: CGFloat = 0
        let width = CGFloat(CTLineGetTypographicBounds(line, &ascent, nil, nil))
        context.saveGState()
        context.translateBy(x: (CGFloat(Layout.width) - width) / 2, y: CGFloat(Layout.appPosition.1 + 122) + ascent)
        context.scaleBy(x: 1, y: -1)
        context.textPosition = .zero
        CTLineDraw(line, context)
        context.restoreGState()
    }

    private static func drawLeaves(_ context: CGContext) {
        let app = Layout.appPosition, applications = Layout.applicationsPosition
        let p0 = CGPoint(x: app.0 + 96, y: app.1 + 12)
        let p1 = CGPoint(x: app.0 + 128, y: app.1 - 30)
        let p2 = CGPoint(x: applications.0 - 134, y: applications.1 - 32)
        let p3 = CGPoint(x: applications.0 - 100, y: applications.1 - 2)
        func point(_ t: CGFloat) -> CGPoint {
            let u = 1 - t
            return CGPoint(x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
                           y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y)
        }
        func angle(_ t: CGFloat) -> CGFloat {
            let u = 1 - t
            let dx = 3 * u * u * (p1.x - p0.x) + 6 * u * t * (p2.x - p1.x) + 3 * t * t * (p3.x - p2.x)
            let dy = 3 * u * u * (p1.y - p0.y) + 6 * u * t * (p2.y - p1.y) + 3 * t * t * (p3.y - p2.y)
            return atan2(dy, dx)
        }
        // Space the leaves by arc length.
        let steps = 256
        var lengths: [CGFloat] = [0]
        var previous = point(0)
        for step in 1...steps {
            let next = point(CGFloat(step) / CGFloat(steps))
            lengths.append(lengths.last! + hypot(next.x - previous.x, next.y - previous.y))
            previous = next
        }
        for index in 0..<7 {
            let fraction = (CGFloat(index) + 0.5) / 7
            let distance = fraction * lengths.last!
            let upper = lengths.firstIndex(where: { $0 >= distance })!
            let lower = upper - 1
            let t = (CGFloat(lower) + (distance - lengths[lower]) / (lengths[upper] - lengths[lower])) / CGFloat(steps)
            let position = point(t)
            context.saveGState()
            context.translateBy(x: position.x, y: position.y)
            context.rotate(by: angle(t) - 25 * .pi / 180)
            let scale = 0.75 + 0.45 * fraction
            context.scaleBy(x: scale, y: scale)
            context.setFillColor(color(0x2e7d32, alpha: ((0.25 + 0.75 * fraction) * 100).rounded() / 100))
            context.move(to: CGPoint(x: -7, y: 0))
            context.addCurve(to: CGPoint(x: 7, y: 0), control1: CGPoint(x: -3, y: -4.5), control2: CGPoint(x: 3, y: -4.5))
            context.addCurve(to: CGPoint(x: -7, y: 0), control1: CGPoint(x: 3, y: 4.5), control2: CGPoint(x: -3, y: 4.5))
            context.closePath()
            context.fillPath()
            context.restoreGState()
        }
        let direction = angle(1)
        context.saveGState()
        context.translateBy(x: p3.x + 12 * cos(direction), y: p3.y + 12 * sin(direction))
        context.rotate(by: direction)
        context.setStrokeColor(color(0x2e7d32))
        context.setLineWidth(3)
        context.setLineCap(.round)
        context.setLineJoin(.round)
        context.move(to: CGPoint(x: -8, y: -6.5))
        context.addLine(to: CGPoint(x: 1, y: 0))
        context.addLine(to: CGPoint(x: -8, y: 6.5))
        context.strokePath()
        context.restoreGState()
    }
}
