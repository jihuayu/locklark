import Foundation

/// Bounds shared by the Safari containing app, the app extension handler and
/// the embedded native helper relay. Every value is deliberately small and
/// fixed; none of them can be raised by page content or by an IPC peer.
public enum RelayLimits {
    public static let protocolVersion = 1
    public static let maxFrameBytes = 256 * 1024
    public static let maxFramesPerPoll = 64
    public static let maxReplyBytes = 1024 * 1024
    public static let maxJSONDepth = 16
    public static let maxCollectionEntries = 1024
    /// Upper bound on ready sessions **plus** in-flight opening reservations.
    public static let maxConnections = 8
    public static let maxQueuedFrames = 64
    public static let maxQueuedBytes = 2 * 1024 * 1024
    public static let sessionTTL: TimeInterval = 30 * 60
    /// An opening reservation only covers a helper launch, so it is released
    /// long before the session TTL. A completion after this is refused.
    public static let openingReservationTTL: TimeInterval = 60
    public static let socketTimeout: TimeInterval = 5
    public static let tokenBytes = 16
    public static let tokenLength = 32
    public static let maxProfileBytes = 256
    public static let helperName = "locklark-browser-safari"
    public static let relayDirectoryName = "native"
    public static let relaySocketName = "relay.sock"
}

public enum RelayError: Error, Equatable {
    case invalidEnvelope
    case invalidFrame
    case invalidIdentity
    case invalidConfiguration
    case unavailable
    case queueFull
    case closed
    case peerRejected
    case timeout
    case tooManyConnections
}
