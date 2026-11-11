import Foundation
import Darwin
import ImageIO
import UniformTypeIdentifiers

@main
struct Tests {
    static func u32(_ value: UInt32) -> Data {
        Data([UInt8((value >> 24) & 255), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)])
    }

    static func record(_ name: String, _ code: String, _ type: String, _ value: Data) -> Data {
        let text = name.data(using: .utf16BigEndian)!
        return u32(UInt32(text.count / 2)) + text + Data(code.utf8) + Data(type.utf8) + value
    }

    static func store(_ records: [Data], count: Int? = nil, cycle: Bool = false) -> Data {
        var data = Data(repeating: 0, count: 12292)
        func put(_ offset: Int, _ bytes: Data) { data.replaceSubrange(offset..<(offset + bytes.count), with: bytes) }
        put(0, Data([0, 0, 0, 1, 66, 117, 100, 49]) + u32(2048) + u32(2048) + u32(2048))
        put(2052, u32(3) + u32(0) + u32(2048 | 11) + u32(4096 | 5) + u32(8192 | 12))
        put(2052 + 1032, u32(1) + Data([4]) + Data("DSDB".utf8) + u32(1))
        put(4100, u32(2) + u32(0) + u32(UInt32(count ?? records.count)) + u32(1) + u32(4096))
        put(8196, u32(cycle ? 2 : 0) + u32(UInt32(records.count)) + records.reduce(Data(), +))
        return data
    }

    static func main() throws {
        var passed = 0
        func rejects(_ name: String, _ body: () throws -> Void) throws {
            do { try body() } catch {
                passed += 1
                print("PASS \(name)")
                return
            }
            throw DMGError("Expected rejection: \(name)")
        }
        let validRecord = record(".", "vSrn", "long", u32(1))
        let valid = store([validRecord])
        guard try DSStore(data: valid).records.count == 1 else { throw DMGError("Valid leaf rejected") }
        passed += 1
        var internalTree = valid + Data(repeating: 0, count: 8192)
        func put(_ offset: Int, _ value: Data) {
            internalTree.replaceSubrange(offset..<(offset + value.count), with: value)
        }
        put(2052, u32(5) + u32(0) + u32(2048 | 11) + u32(4096 | 5)
            + u32(8192 | 12) + u32(12288 | 12) + u32(16384 | 12))
        put(4100, u32(2) + u32(1) + u32(3) + u32(3) + u32(4096))
        put(8196, u32(4) + u32(1) + u32(3) + record(".", "bbbb", "long", u32(2)))
        put(12292, u32(0) + u32(1) + record(".", "aaaa", "long", u32(1)))
        put(16388, u32(0) + u32(1) + record(".", "cccc", "long", u32(3)))
        guard try DSStore(data: internalTree).records.count == 3 else { throw DMGError("Valid internal tree rejected") }
        passed += 1
        try rejects("invalid header") { _ = try DSStore(data: Data(repeating: 0, count: 32)) }
        try rejects("truncated allocator") { _ = try DSStore(data: valid.prefix(3000)) }
        try rejects("cyclic tree") { _ = try DSStore(data: store([], cycle: true)) }
        try rejects("duplicate record") { _ = try DSStore(data: store([validRecord, validRecord])) }
        try rejects("record count mismatch") { _ = try DSStore(data: store([validRecord], count: 2)) }
        try rejects("oversized record") {
            _ = try DSStore(data: store([record(".", "icvp", "blob", u32(16 * 1024 * 1024))]))
        }
        var badAddress = valid
        badAddress.replaceSubrange((2052 + 16)..<(2052 + 20), with: u32(1048576 | 12))
        try rejects("out-of-file block") { _ = try DSStore(data: badAddress) }
        try rejects("invalid background alias") { _ = try resolveAlias(Data()) }

        let runtime = Runtime()
        let work = try runtime.temporaryDirectory("dmg-tests-")
        defer { try? runtime.files.removeItem(at: work) }
        let root = work.appendingPathComponent("image", isDirectory: true)
        try runtime.files.createDirectory(at: root, withIntermediateDirectories: false)
        try runtime.files.createDirectory(at: root.appendingPathComponent(Layout.app), withIntermediateDirectories: false)
        let background = root.appendingPathComponent(".background")
        try runtime.files.createDirectory(at: background, withIntermediateDirectories: false)
        try Data().write(to: root.appendingPathComponent(".DS_Store"))
        let volumeIcon = root.appendingPathComponent(".VolumeIcon.icns")
        try Data("icon fixture".utf8).write(to: volumeIcon)
        try Data().write(to: background.appendingPathComponent("background.tiff"))
        let applications = root.appendingPathComponent("Applications")
        try runtime.files.createSymbolicLink(atPath: applications.path, withDestinationPath: "/Applications")
        try checkContents(root)
        passed += 1
        try runtime.files.removeItem(at: volumeIcon)
        try rejects("missing volume icon") { try checkContents(root) }
        try runtime.files.createSymbolicLink(atPath: volumeIcon.path, withDestinationPath: applications.path)
        try rejects("volume icon symlink") { try checkContents(root) }
        try runtime.files.removeItem(at: volumeIcon)
        try Data("icon fixture".utf8).write(to: volumeIcon)
        let expectedIcon = work.appendingPathComponent("VolumeIcon.icns")
        try runtime.files.copyItem(at: volumeIcon, to: expectedIcon)
        try rejects("missing volume icon flag") { try checkVolumeIcon(root, expected: expectedIcon) }
        try setVolumeIcon(root)
        try checkVolumeIcon(root, expected: expectedIcon)
        passed += 1
        try Data("static app icon".utf8).write(to: volumeIcon)
        try rejects("volume icon replaced by static app icon") {
            try checkVolumeIcon(root, expected: expectedIcon)
        }
        try runtime.files.removeItem(at: volumeIcon)
        try runtime.files.copyItem(at: expectedIcon, to: volumeIcon)
        let extra = root.appendingPathComponent("unexpected\nentry")
        try Data().write(to: extra)
        try rejects("extra filename containing newline") { try checkContents(root) }
        try runtime.files.removeItem(at: extra)
        try runtime.files.removeItem(at: applications)
        try runtime.files.createSymbolicLink(atPath: applications.path, withDestinationPath: "/tmp")
        try rejects("wrong Applications link") { try checkContents(root) }
        try runtime.files.removeItem(at: applications)
        try runtime.files.createSymbolicLink(atPath: applications.path, withDestinationPath: "/Applications")
        try runtime.files.removeItem(at: background)
        try runtime.files.createSymbolicLink(atPath: background.path, withDestinationPath: work.path)
        try rejects("background directory symlink") { try checkContents(root) }
        try runtime.files.removeItem(at: background)
        try runtime.files.createDirectory(at: background, withIntermediateDirectories: false)
        try Data().write(to: background.appendingPathComponent("background.tiff"))
        try runtime.files.removeItem(at: root.appendingPathComponent(Layout.app))
        try runtime.files.createSymbolicLink(atPath: root.appendingPathComponent(Layout.app).path, withDestinationPath: work.path)
        try rejects("application directory symlink") { try checkContents(root) }

        let text = "space ' quote \" dollar $() ; newline\n"
        let echoed = try runtime.checked("/usr/bin/printf", ["%s", text])
        guard echoed.text == text else { throw DMGError("Arguments were changed") }
        passed += 1
        try rejects("nonzero child status") { try runtime.checked("/usr/bin/false", []) }
        let start = ProcessInfo.processInfo.systemUptime
        try rejects("child timeout") { try runtime.checked("/bin/sleep", ["10"], timeout: 0.1) }
        guard ProcessInfo.processInfo.systemUptime - start < 3 else { throw DMGError("Timeout did not terminate the child") }

        let tiff = work.appendingPathComponent("background.tiff")
        try Background.write(to: tiff)
        try checkTIFF(tiff)
        passed += 1
        let source = CGImageSourceCreateWithURL(tiff as CFURL, nil)!
        for (index, scale) in [1, 2].enumerated() {
            guard let image = CGImageSourceCreateImageAtIndex(source, index, nil),
                  image.width == Layout.width * scale, image.height == Layout.height * scale else {
                throw DMGError("The generated TIFF cannot be decoded at both scales")
            }
        }
        passed += 1
        try rejects("unsupported background scale") { _ = try Background.image(scale: 0) }
        let single = work.appendingPathComponent("single.png")
        func writeImages(_ url: URL, images: [CGImage], type: CFString) throws {
            guard let destination = CGImageDestinationCreateWithURL(url as CFURL, type, images.count, nil) else {
                throw DMGError("Cannot create the negative TIFF fixture")
            }
            for image in images {
                CGImageDestinationAddImage(destination, image,
                    [kCGImagePropertyDPIWidth: 72, kCGImagePropertyDPIHeight: 72] as CFDictionary)
            }
            guard CGImageDestinationFinalize(destination) else { throw DMGError("Cannot write the negative TIFF fixture") }
        }
        let lowResolution = try Background.image(scale: 1)
        try writeImages(single, images: [lowResolution], type: UTType.png.identifier as CFString)
        try rejects("single-representation background") { try checkTIFF(single) }
        let wrong = work.appendingPathComponent("wrong.tiff")
        try writeImages(wrong, images: [lowResolution, lowResolution], type: UTType.tiff.identifier as CFString)
        try rejects("two images with wrong Retina dimensions") { try checkTIFF(wrong) }
        print("\(passed) checks passed; Finder and signing keys were not used.")
    }
}
