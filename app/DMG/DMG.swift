import Foundation
import CoreFoundation
import ImageIO
import Darwin

enum Layout {
    static let appName = "Nydia for Safari"
    static let volume = appName
    static let app = appName + ".app"
    static let background = ".background/background.tiff"
    static let width = 640, height = 400
    static let windowX = 200, windowY = 120
    static let iconSize = 128, textSize = 13
    static let appPosition = (160, 160), applicationsPosition = (480, 160)
    static let positions = [app: appPosition, "Applications": applicationsPosition]
}

func fileKind(_ url: URL) throws -> mode_t {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw DMGError("Cannot inspect \(url.path): \(String(cString: strerror(errno)))") }
    return info.st_mode & mode_t(S_IFMT)
}

func checkContents(_ mount: URL) throws {
    let files = FileManager.default
    let expected: [String: mode_t] = [
        ".DS_Store": mode_t(S_IFREG), ".VolumeIcon.icns": mode_t(S_IFREG), ".background": mode_t(S_IFDIR),
        Layout.app: mode_t(S_IFDIR), "Applications": mode_t(S_IFLNK)
    ]
    let names = Set(try files.contentsOfDirectory(atPath: mount.path))
    guard names == Set(expected.keys) else {
        throw DMGError("Unexpected image contents: \(names.sorted()); expected \(expected.keys.sorted())")
    }
    for (name, kind) in expected {
        guard try fileKind(mount.appendingPathComponent(name)) == kind else {
            throw DMGError("Wrong file type for \(name)")
        }
    }
    guard try files.destinationOfSymbolicLink(atPath: mount.appendingPathComponent("Applications").path) == "/Applications" else {
        throw DMGError("Applications must link to /Applications")
    }
    let background = mount.appendingPathComponent(".background", isDirectory: true)
    guard try files.contentsOfDirectory(atPath: background.path) == ["background.tiff"],
          try fileKind(background.appendingPathComponent("background.tiff")) == mode_t(S_IFREG) else {
        throw DMGError(".background must contain only a regular background.tiff")
    }
}

func finderInfo(_ volume: URL) throws -> Data {
    var data = Data(repeating: 0, count: 32)
    let count = data.withUnsafeMutableBytes { getxattr(volume.path, "com.apple.FinderInfo", $0.baseAddress, 32, 0, 0) }
    guard count == 32 || (count == -1 && errno == ENOATTR) else { throw DMGError("Cannot read volume FinderInfo") }
    return data
}

func setVolumeIcon(_ volume: URL) throws {
    var data = try finderInfo(volume)
    data[8] |= 0x04 // kHasCustomIcon
    let result = data.withUnsafeBytes { setxattr(volume.path, "com.apple.FinderInfo", $0.baseAddress, 32, 0, 0) }
    guard result == 0 else { throw DMGError("Cannot set the volume icon flag") }
}

func checkVolumeIcon(_ volume: URL, expected: URL) throws {
    guard FileManager.default.contentsEqual(atPath: expected.path, andPath: volume.appendingPathComponent(".VolumeIcon.icns").path),
          try finderInfo(volume)[8] & 0x04 != 0 else { throw DMGError("The volume icon or its Finder flag is incorrect") }
}

func resolveAlias(_ data: Data) throws -> URL {
    guard let reference = CFURLCreateBookmarkDataFromAliasRecord(nil, data as CFData) else {
        throw DMGError("Cannot decode the background alias")
    }
    let bookmark = reference.takeRetainedValue()
    var stale = DarwinBoolean(false)
    let options = CFURLBookmarkResolutionOptions(rawValue: (1 << 8) | (1 << 9))
    guard let target = CFURLCreateByResolvingBookmarkData(nil, bookmark, options, nil, nil, &stale, nil) else {
        throw DMGError("Cannot resolve the background alias without UI or mounting")
    }
    return target.takeRetainedValue() as URL
}

func checkTIFF(_ url: URL) throws {
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
          CGImageSourceGetCount(source) == 2 else {
        throw DMGError("The background must contain exactly two images")
    }
    for (index, expected) in [(Layout.width, Layout.height, 72.0), (Layout.width * 2, Layout.height * 2, 144.0)].enumerated() {
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [CFString: Any],
              let width = props[kCGImagePropertyPixelWidth] as? NSNumber,
              let height = props[kCGImagePropertyPixelHeight] as? NSNumber,
              let dpiX = props[kCGImagePropertyDPIWidth] as? NSNumber,
              let dpiY = props[kCGImagePropertyDPIHeight] as? NSNumber,
              width.intValue == expected.0, height.intValue == expected.1,
              abs(dpiX.doubleValue - expected.2) < 0.01,
              abs(dpiY.doubleValue - expected.2) < 0.01 else {
            throw DMGError("Wrong background dimensions or DPI in TIFF image \(index)")
        }
    }
}

func checkLayout(_ mount: URL) throws {
    let file = mount.appendingPathComponent(".DS_Store")
    let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
    guard size <= 8 * 1024 * 1024 else { throw DMGError(".DS_Store is too large") }
    let store = try DSStore(data: Data(contentsOf: file))
    let window = try store.plist("bwsp")
    let pattern = #"^\{\{-?\d+, -?\d+\}, \{"# + "\(Layout.width), \(Layout.height)" + #"\}\}$"#
    guard let bounds = window["WindowBounds"] as? String,
          bounds.range(of: pattern, options: .regularExpression) != nil else {
        throw DMGError("The image window must be \(Layout.width)×\(Layout.height)")
    }
    for key in ["ShowToolbar", "ShowSidebar"] {
        guard window[key] as? Bool == false else { throw DMGError("\(key) must be false") }
    }
    let view = try store.plist("icvp")
    guard (view["backgroundType"] as? NSNumber)?.doubleValue == 2,
          (view["iconSize"] as? NSNumber)?.doubleValue == Double(Layout.iconSize),
          (view["textSize"] as? NSNumber)?.doubleValue == Double(Layout.textSize),
          view["arrangeBy"] as? String == "none" else {
        throw DMGError("Wrong image background, icon size, text size or arrangement")
    }
    guard let alias = view["backgroundImageAlias"] as? Data else { throw DMGError("Missing background alias") }
    let target = try resolveAlias(alias).resolvingSymlinksInPath().standardizedFileURL
    let expected = mount.appendingPathComponent(Layout.background).resolvingSymlinksInPath().standardizedFileURL
    guard target == expected else { throw DMGError("The background alias resolves outside this image's TIFF") }
    for (name, expected) in Layout.positions {
        var record = DSStore.Reader(data: try store.blob(name, "Iloc"))
        let x = try record.uint32(), y = try record.uint32()
        guard x == UInt32(expected.0), y == UInt32(expected.1) else {
            throw DMGError("Wrong icon position for \(name)")
        }
    }
    try checkTIFF(expected)
}

func checkDeveloperID(_ app: URL, team: String, runtime: Runtime) throws {
    guard team.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) else {
        throw DMGError("Expected a ten-character Apple Team ID")
    }
    let requirement = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(team)\" and identifier \"me.Nydia.Safari\""
    try runtime.checked("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", "-R=" + requirement, app.path])
}

func build(app: URL, output: URL, volumeIcon: URL, volumeName: String = Layout.volume, runtime: Runtime) throws {
    guard app.lastPathComponent == Layout.app, try fileKind(app) == mode_t(S_IFDIR) else {
        throw DMGError("Expected a directory named \(Layout.app)")
    }
    guard output.pathExtension == "dmg", !runtime.files.fileExists(atPath: output.path) else {
        throw DMGError("The .dmg output path must not already exist")
    }
    guard try fileKind(volumeIcon) == mode_t(S_IFREG) else {
        throw DMGError("Expected a regular volume ICNS file")
    }
    let source = app.resolvingSymlinksInPath().standardizedFileURL.path + "/"
    guard !output.resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(source) else {
        throw DMGError("The output must be outside the source application")
    }
    guard let volumes = runtime.files.mountedVolumeURLs(includingResourceValuesForKeys: [.volumeNameKey], options: []) else {
        throw DMGError("Cannot list mounted volumes")
    }
    for volume in volumes {
        if try volume.resourceValues(forKeys: [.volumeNameKey]).volumeName == volumeName {
            throw DMGError("Eject the existing \(volumeName) volume at \(volume.path) before building")
        }
    }
    let work = try runtime.temporaryDirectory("nydia-dmg-")
    let mount = work.appendingPathComponent("mount", isDirectory: true)
    defer { runtime.cleanup(work, mount: mount) }
    let stage = work.appendingPathComponent("stage", isDirectory: true)
    let writable = work.appendingPathComponent("writable.dmg")
    let compressed = work.appendingPathComponent("finished.dmg")
    try runtime.files.createDirectory(at: stage.appendingPathComponent(".background"), withIntermediateDirectories: true)
    try runtime.files.createDirectory(at: stage.appendingPathComponent(".fseventsd"), withIntermediateDirectories: false)
    try Data().write(to: stage.appendingPathComponent(".fseventsd/no_log"))
    try runtime.checked("/usr/bin/ditto", [app.path, stage.appendingPathComponent(Layout.app).path])
    try runtime.files.copyItem(at: volumeIcon, to: stage.appendingPathComponent(".VolumeIcon.icns"))
    try runtime.files.createSymbolicLink(atPath: stage.appendingPathComponent("Applications").path, withDestinationPath: "/Applications")
    try Background.write(to: stage.appendingPathComponent(Layout.background))
    try checkTIFF(stage.appendingPathComponent(Layout.background))
    try runtime.hdiutil(["create", "-quiet", "-volname", volumeName, "-srcfolder", stage.path,
        "-fs", "HFS+", "-format", "UDRW", writable.path])
    try runtime.files.createDirectory(at: mount, withIntermediateDirectories: false)
    try runtime.hdiutil(["attach", "-quiet", "-readwrite", "-noautoopen", "-nobrowse", "-mountpoint", mount.path, writable.path])
    try setVolumeIcon(mount)
    try FinderScripts.run(mount, arrange: true, runtime: runtime)
    for name in [".fseventsd", ".Trashes", ".Spotlight-V100", ".TemporaryItems"] {
        let url = mount.appendingPathComponent(name)
        if runtime.files.fileExists(atPath: url.path) { try runtime.files.removeItem(at: url) }
    }
    try runtime.hdiutil(["detach", "-quiet", mount.path])
    try runtime.hdiutil(["convert", "-quiet", writable.path, "-format", "UDZO", "-imagekey", "zlib-level=9", "-o", compressed.path])
    try runtime.files.moveItem(at: compressed, to: output)
    print(output.path)
}

func check(image: URL, volumeIcon: URL, finder: Bool, runtime: Runtime,
           verifyApp: (URL) throws -> Void) throws {
    guard try fileKind(image) == mode_t(S_IFREG) else { throw DMGError("Expected a regular DMG file") }
    let work = try runtime.temporaryDirectory("nydia-check-")
    let mount = work.appendingPathComponent("mount", isDirectory: true)
    defer { runtime.cleanup(work, mount: mount) }
    try runtime.files.createDirectory(at: mount, withIntermediateDirectories: false)
    try runtime.hdiutil(["attach", "-quiet", "-readonly", "-noautoopen", "-nobrowse", "-mountpoint", mount.path, image.path])
    try checkContents(mount)
    try checkVolumeIcon(mount, expected: volumeIcon)
    try checkLayout(mount)
    let app = mount.appendingPathComponent(Layout.app)
    try runtime.checked("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", app.path])
    try verifyApp(app)
    if finder { try FinderScripts.run(mount, arrange: false, runtime: runtime) }
    try runtime.hdiutil(["detach", "-quiet", mount.path])
    print("Checked image contents, stored layout, Retina TIFF and app signature\(finder ? ", and Finder window" : "").")
}

#if !DMG_TESTS
@main
struct DMGCommand {
    static func main() {
        let runtime = Runtime()
        do {
            let args = Array(CommandLine.arguments.dropFirst())
            if args.count == 4, args[0] == "build" {
                try build(app: URL(fileURLWithPath: args[1]), output: URL(fileURLWithPath: args[2]),
                          volumeIcon: URL(fileURLWithPath: args[3]), runtime: runtime)
            } else if (args.count == 5 || args.count == 6), args[0] == "check", args[3] == "--team-id",
                      args.count == 5 || args[5] == "--skip-finder" {
                try check(image: URL(fileURLWithPath: args[1]), volumeIcon: URL(fileURLWithPath: args[2]),
                          finder: args.count == 5, runtime: runtime) { app in
                    try checkDeveloperID(app, team: args[4], runtime: runtime)
                }
            } else {
                throw DMGError("Usage:\n  nydia-dmg build <app> <new.dmg> <volume.icns>\n  nydia-dmg check <image.dmg> <volume.icns> --team-id <TEAMID> [--skip-finder]")
            }
        } catch {
            writeError("DMG: \(error)\n")
            let requested = runtime.cancellation.requestedSignal
            exit(requested == 0 ? 1 : 128 + requested)
        }
    }
}
#endif
