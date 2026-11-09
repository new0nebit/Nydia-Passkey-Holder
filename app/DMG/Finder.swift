import Foundation

enum FinderScripts {
    static let diskHandler = #"""
    on diskAt(mountPoint)
        set deadline to (current date) + 20
        repeat
            try
                with timeout of 5 seconds
                    tell application "Finder" to return disk of (POSIX file mountPoint as alias)
                end timeout
            on error message number code
                if code is not in {-1728, -1712} then error message number code
                if (current date) > deadline then error "Finder does not see the disk: " & message number code
            end try
            delay 0.2
        end repeat
    end diskAt
    """#

    static let arrange = """
                set current view of win to icon view
                set toolbar visible of win to false
                if pass is 2 then
                    set bounds of win to {\(Layout.windowX), \(Layout.windowY), \(Layout.windowX + Layout.width - 8), \(Layout.windowY + Layout.height - 8)}
                    delay 0.2
                end if
                set bounds of win to {\(Layout.windowX), \(Layout.windowY), \(Layout.windowX + Layout.width), \(Layout.windowY + Layout.height)}
                tell icon view options of win
                    set icon size to \(Layout.iconSize)
                    set text size to \(Layout.textSize)
                    set arrangement to not arranged
                    set background picture to POSIX file (mountPoint & "/\(Layout.background)")
                end tell
                set position of item appName of win to {\(Layout.appPosition.0), \(Layout.appPosition.1)}
                set position of item "Applications" of win to {\(Layout.applicationsPosition.0), \(Layout.applicationsPosition.1)}
    """

    static func run(_ mount: URL, arrange: Bool, runtime: Runtime) throws {
        let script = """
        on run argv
            set mountPoint to item 1 of argv
            set appName to item 2 of argv
            set theDisk to my diskAt(mountPoint)
            with timeout of 60 seconds
                tell application "Finder"
                    repeat with pass from 1 to \(arrange ? 2 : 1)
                        set win to make new Finder window to theDisk
                        delay 0.3
        \(arrange ? Self.arrange : "")
                        set opts to icon view options of win
                        set p1 to position of item appName of win
                        set p2 to position of item "Applications" of win
                        set report to {(current view of win) as text, (toolbar visible of win) as text, ¬
                            icon size of opts, text size of opts, (arrangement of opts) as text, ¬
                            item 1 of p1, item 2 of p1, item 1 of p2, item 2 of p2}
                        close win
                        delay 0.4
                    end repeat
                end tell
            end timeout
            set AppleScript's text item delimiters to " "
            return report as text
        end run
        \(diskHandler)
        """
        let report = try runtime.checked("/usr/bin/osascript", ["-", mount.path, Layout.app], input: script, timeout: 180)
        guard report.text.trimmingCharacters(in: .whitespacesAndNewlines) == "icon view false \(Layout.iconSize) \(Layout.textSize) not arranged \(Layout.appPosition.0) \(Layout.appPosition.1) \(Layout.applicationsPosition.0) \(Layout.applicationsPosition.1)" else {
            throw DMGError("Finder shows a different window: \(report.text)")
        }
    }
}
