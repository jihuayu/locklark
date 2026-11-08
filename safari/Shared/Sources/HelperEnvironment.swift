import Foundation

/// The helper runs under the containing app, whose own environment comes from
/// launchd, a terminal or whatever parent process started the app. None of it
/// is trusted, so the child receives a fixed baseline rebuilt from scratch.
///
/// Only three keys exist and there is deliberately no API to add one:
///   * HOME   – the current user's home directory, so the Go helper resolves
///              the existing Locklark runtime and config exactly where an
///              ordinary `locklark` invocation already finds it.
///   * TMPDIR – the OS-provided temporary directory used for local IPC.
///   * PATH   – fixed system directories only; no user or package-manager
///              entries.
///
/// Never inherited: tokens and API keys, DYLD_* injection variables, proxy
/// settings (HTTP(S)_PROXY, ALL_PROXY, NO_PROXY), SSH_AUTH_SOCK, locale
/// variables, LOCKLARK_* overrides (including LOCKLARK_BROWSER_SOCKET) or any
/// other ambient variable. The function takes its values as arguments and reads
/// nothing from `ProcessInfo`, so the policy is pure and testable.
public enum HelperEnvironment {
    public static let path = "/usr/bin:/bin:/usr/sbin:/sbin"

    public static func minimal(
        home: String,
        temporaryDirectory: String
    ) -> [String: String] {
        ["HOME": home, "TMPDIR": temporaryDirectory, "PATH": path]
    }
}
