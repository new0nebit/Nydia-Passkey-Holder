//
//  ViewController.swift
//  Nydia
//
//  Created by Oleh Nypadymka on 13.04.2025.
//

import Cocoa
import SafariServices
import WebKit
import os

let extensionBundleIdentifier = Bundle.main.bundleIdentifier! + ".Extension"

private let logger = Logger(subsystem: Bundle.main.bundleIdentifier!, category: "app")

class ViewController: NSViewController, WKNavigationDelegate, WKScriptMessageHandler {

    // Built here, not in Main.storyboard: Interface Builder archives WKWebView with private
    // subviews from the build Mac's WebKit, and macOS versions without them show an empty window.
    private let webView = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())

    override func viewDidLoad() {
        super.viewDidLoad()

        self.webView.frame = self.view.bounds
        self.webView.autoresizingMask = [.width, .height]
        self.view.addSubview(self.webView)

        self.webView.navigationDelegate = self

        self.webView.configuration.userContentController.add(self, name: "controller")

        self.webView.loadFileURL(Bundle.main.url(forResource: "Main", withExtension: "html")!, allowingReadAccessTo: Bundle.main.resourceURL!)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Depends only on the macOS version, so set it before Safari answers (or fails to).
        if #available(macOS 13, *) {
            callJavaScript("useSettingsInsteadOfPreferences()")
        }

        SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: extensionBundleIdentifier) { (state, error) in
            DispatchQueue.main.async {
                guard let state = state, error == nil else {
                    self.report(error, while: "read the extension state")
                    return
                }

                self.callJavaScript("show(enabled)", arguments: ["enabled": state.isEnabled])
            }
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        if (message.body as! String != "open-preferences") {
            return;
        }

        SFSafariApplication.showPreferencesForExtension(withIdentifier: extensionBundleIdentifier) { error in
            DispatchQueue.main.async {
                if let error = error {
                    // Stay open so the user can still read how to turn the extension on manually.
                    self.report(error, while: "open the extension settings in Safari")
                    self.openSafari()
                    return
                }

                NSApplication.shared.terminate(nil)
            }
        }
    }

    private func openSafari() {
        guard let safari = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") else {
            report(nil, while: "find Safari")
            return
        }

        NSWorkspace.shared.openApplication(at: safari, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            guard let error = error else { return }
            DispatchQueue.main.async {
                self.report(error, while: "launch Safari")
            }
        }
    }

    /// `action` completes the sentence "Couldn't …", shown under the button and logged.
    private func report(_ error: Error?, while action: String) {
        let code = (error as NSError?).map { "\($0.domain) \($0.code)" } ?? ""
        logger.error("Couldn't \(action, privacy: .public) for \(extensionBundleIdentifier, privacy: .public): \(String(describing: error), privacy: .public)")
        callJavaScript("showError(action, code)", arguments: ["action": action, "code": code])
    }

    private func callJavaScript(_ body: String, arguments: [String: Any] = [:]) {
        webView.callAsyncJavaScript(body, arguments: arguments, in: nil, in: .page) { result in
            if case .failure(let error) = result {
                logger.error("JavaScript call \(body, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            }
        }
    }

}
