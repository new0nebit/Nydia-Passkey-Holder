import Foundation
import Dispatch
import Darwin

func writeError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

final class Cancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var signalNumber: Int32 = 0
    private var sources: [DispatchSourceSignal] = []

    init() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { [weak self] in
                guard let self else { return }
                self.lock.withLock { self.signalNumber = number }
            }
            source.resume()
            sources.append(source)
        }
    }

    var requestedSignal: Int32 { lock.withLock { signalNumber } }
}

struct CommandResult {
    let status: Int32
    let text: String
    let diagnostics: String
}

final class Runtime {
    let cancellation = Cancellation()
    let files = FileManager.default

    func temporaryDirectory(_ prefix: String) throws -> URL {
        let parent = ProcessInfo.processInfo.environment["RUNNER_TEMP"]
            ?? ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        let url = URL(fileURLWithPath: parent, isDirectory: true)
            .appendingPathComponent(prefix + UUID().uuidString, isDirectory: true)
        try files.createDirectory(at: url, withIntermediateDirectories: false,
                                  attributes: [.posixPermissions: 0o700])
        return url
    }

    func run(_ executable: String, _ arguments: [String], input: String? = nil,
             timeout: TimeInterval = 120, allowCancellation: Bool = true) throws -> CommandResult {
        if allowCancellation, cancellation.requestedSignal != 0 { throw DMGError("Interrupted") }
        let logs = try temporaryDirectory("dmg-command-")
        defer { try? files.removeItem(at: logs) }
        let stdoutURL = logs.appendingPathComponent("stdout"), stderrURL = logs.appendingPathComponent("stderr")
        let stdinURL = logs.appendingPathComponent("stdin")
        for url in [stdoutURL, stderrURL] { try Data().write(to: url) }
        try Data((input ?? "").utf8).write(to: stdinURL)
        let stdout = try FileHandle(forWritingTo: stdoutURL)
        defer { try? stdout.close() }
        let stderr = try FileHandle(forWritingTo: stderrURL)
        defer { try? stderr.close() }
        let stdin = try FileHandle(forReadingFrom: stdinURL)
        defer { try? stdin.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = stdout
        process.standardError = stderr
        process.environment = ProcessInfo.processInfo.environment.merging(["LC_ALL": "C"]) { _, value in value }
        process.standardInput = stdin
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var stopped: String?
        while process.isRunning {
            if allowCancellation, cancellation.requestedSignal != 0 { stopped = "Interrupted" }
            if ProcessInfo.processInfo.systemUptime >= deadline { stopped = "Command timed out" }
            if stopped != nil {
                process.terminate()
                let grace = ProcessInfo.processInfo.systemUptime + 2
                while process.isRunning, ProcessInfo.processInfo.systemUptime < grace {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        process.waitUntilExit()
        if let stopped { throw DMGError("\(stopped): \(executable)") }
        return CommandResult(status: process.terminationStatus,
                             text: String(decoding: try Data(contentsOf: stdoutURL), as: UTF8.self),
                             diagnostics: String(decoding: try Data(contentsOf: stderrURL), as: UTF8.self))
    }

    @discardableResult
    func checked(_ executable: String, _ arguments: [String], input: String? = nil,
                 timeout: TimeInterval = 120, allowCancellation: Bool = true) throws -> CommandResult {
        let result = try run(executable, arguments, input: input, timeout: timeout,
                             allowCancellation: allowCancellation)
        guard result.status == 0 else {
            throw DMGError("\(executable) exited \(result.status): \(result.diagnostics)\(result.text)")
        }
        return result
    }

    @discardableResult
    func hdiutil(_ arguments: [String], timeout: TimeInterval = 120,
                 allowCancellation: Bool = true) throws -> CommandResult {
        var attempt = 1
        while true {
            let result = try run("/usr/bin/hdiutil", arguments, timeout: timeout,
                                 allowCancellation: allowCancellation)
            if result.status == 0 { return result }
            guard attempt < 3, (result.text + result.diagnostics).contains("Resource busy") else {
                throw DMGError("hdiutil \(arguments.first ?? "") exited \(result.status): \(result.diagnostics)\(result.text)")
            }
            attempt += 1
            Thread.sleep(forTimeInterval: 2)
        }
    }

    func isMounted(_ url: URL) throws -> Bool {
        var item = stat(), parent = stat()
        guard lstat(url.path, &item) == 0 else {
            if errno == ENOENT { return false }
            throw DMGError("Cannot inspect mount point \(url.path)")
        }
        guard stat(url.deletingLastPathComponent().path, &parent) == 0 else {
            throw DMGError("Cannot inspect mount point parent")
        }
        return item.st_dev != parent.st_dev
    }

    func cleanup(_ work: URL, mount: URL) {
        do {
            if try isMounted(mount) {
                do {
                    try hdiutil(["detach", "-quiet", mount.path], timeout: 15, allowCancellation: false)
                } catch {
                    try checked("/usr/bin/hdiutil", ["detach", "-force", "-quiet", mount.path],
                                timeout: 15, allowCancellation: false)
                }
            }
            guard try !isMounted(mount) else { throw DMGError("Volume remains mounted") }
            try files.removeItem(at: work)
        } catch {
            writeError("Cleanup: \(error). Left \(work.path) in place.\n")
        }
    }
}
