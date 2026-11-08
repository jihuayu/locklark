import CoreFoundation
import Foundation

public enum RelayOperation: String, CaseIterable {
    case open
    case send
    case poll
    case close
}

/// Strict operation envelope for the extension <-> containing app channel.
/// Allowed keys are exact; unknown keys, booleans where integers are required,
/// uppercase tokens and out-of-bounds frames are all refused.
public struct RelayRequest {
    public let operation: RelayOperation
    public let token: String
    public let frame: [String: Any]?
    /// Opaque Safari profile identifier. Only the trusted native-hop parser
    /// fills it (from the native handler context) and it is then required on
    /// every send/poll/close for the same session. It is never derived from a
    /// page, a JS message field or a native frame.
    public let profileKey: String?

    public init(
        operation: RelayOperation,
        token: String,
        frame: [String: Any]? = nil,
        profileKey: String? = nil
    ) {
        self.operation = operation
        self.token = token
        self.frame = frame
        self.profileKey = profileKey
    }

    /// Strict browser-side parser. JavaScript/page content may only ever send
    /// v/op/token(/frame); a `profile` field from JS is refused, never honoured.
    public static func parse(_ raw: Any) -> RelayRequest? {
        parse(raw, allowNativeProfile: false)
    }

    /// Trusted parser for the app-group hop. Only the containing app calls it,
    /// and only after the SecCode/Team/bundle/UID peer check passed. It accepts
    /// the bounded `profile` field on *every* operation so send, poll and close
    /// stay bound to the profile the session was opened with.
    public static func parseNative(_ raw: Any) -> RelayRequest? {
        parse(raw, allowNativeProfile: true)
    }

    private static func parse(
        _ raw: Any,
        allowNativeProfile: Bool
    ) -> RelayRequest? {
        guard let object = RelayEnvelope.object(raw) else { return nil }
        guard let version = RelayEnvelope.integer(object["v"]),
              version == RelayLimits.protocolVersion
        else { return nil }
        guard let operationText = object["op"] as? String,
              let operation = RelayOperation(rawValue: operationText)
        else { return nil }
        guard let token = object["token"] as? String,
              RelayEnvelope.isValidToken(token)
        else { return nil }

        // JS must never supply a profile. Refuse it before any native-hop
        // handling, and only accept it from the already peer-verified hop as a
        // bounded, NUL-free value.
        let carriesProfile = object.keys.contains("profile")
        if carriesProfile, !allowNativeProfile { return nil }
        var profileKey: String?
        if carriesProfile {
            guard let rawProfile = object["profile"] as? String,
                  RelayEnvelope.isValidProfileKey(rawProfile)
            else { return nil }
            profileKey = rawProfile
        }

        switch operation {
        case .send:
            guard Set(object.keys) == Set(["v", "op", "token", "frame"]) ||
                (allowNativeProfile && Set(object.keys) ==
                    Set(["v", "op", "token", "frame", "profile"]))
            else { return nil }
            guard let rawFrame = object["frame"],
                  let frame = RelayEnvelope.object(rawFrame),
                  RelayEnvelope.isValidFrame(frame)
            else { return nil }
            guard RelayEnvelope.serializedSize(object) <=
                RelayLimits.maxFrameBytes + 4096
            else { return nil }
            return RelayRequest(
                operation: .send,
                token: token,
                frame: frame,
                profileKey: profileKey
            )
        case .open, .poll, .close:
            let exact: Set<String> = ["v", "op", "token"]
            let withProfile: Set<String> = ["v", "op", "token", "profile"]
            guard Set(object.keys) == exact ||
                (allowNativeProfile && Set(object.keys) == withProfile)
            else { return nil }
            guard RelayEnvelope.serializedSize(object) <= 4096 else {
                return nil
            }
            return RelayRequest(
                operation: operation,
                token: token,
                profileKey: profileKey
            )
        }
    }

    /// Rebuilds the app-bound envelope from validated fields. Unknown Safari
    /// message keys are never forwarded; only SFExtensionProfileKey can add
    /// the bounded profile field, and it is forwarded on every operation.
    public func forwardingEnvelope(profileKey: String? = nil) -> [String: Any] {
        var object: [String: Any] = [
            "v": RelayLimits.protocolVersion,
            "op": operation.rawValue,
            "token": token,
        ]
        if let frame { object["frame"] = frame }
        let effectiveProfile = profileKey ?? self.profileKey
        if let effectiveProfile,
           RelayEnvelope.isValidProfileKey(effectiveProfile) {
            object["profile"] = effectiveProfile
        }
        return object
    }
}

public enum RelayEnvelope {
    public static func object(_ value: Any?) -> [String: Any]? {
        guard let value else { return nil }
        if let dictionary = value as? [String: Any] { return dictionary }
        guard let dictionary = value as? NSDictionary else { return nil }
        var result: [String: Any] = [:]
        for (key, item) in dictionary {
            guard let key = key as? String else { return nil }
            result[key] = item
        }
        return result
    }

    public static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber else { return nil }
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
        let double = number.doubleValue
        guard double.isFinite,
              double == double.rounded(),
              double >= 0,
              double <= Double(Int.max)
        else { return nil }
        return Int(double)
    }

    public static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else { return nil }
        return number.boolValue
    }

    public static func isValidToken(_ token: String) -> Bool {
        guard token.utf8.count == RelayLimits.tokenLength else { return false }
        for byte in token.utf8 {
            switch byte {
            case 48...57, 97...102: continue
            default: return false
            }
        }
        return true
    }

    /// Bounded opaque profile identifier: 1...maxProfileBytes UTF-8 bytes, no
    /// embedded NUL and no control characters. Everything else fails closed.
    public static func isValidProfileKey(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 1, bytes.count <= RelayLimits.maxProfileBytes else {
            return false
        }
        for byte in bytes {
            if byte == 0x00 || byte < 0x20 || byte == 0x7F { return false }
        }
        return true
    }

    public static func isValidFrame(_ value: Any) -> Bool {
        guard let dictionary = object(value),
              isValidJSONValue(dictionary, depth: 0),
              JSONSerialization.isValidJSONObject(dictionary),
              let data = try? JSONSerialization.data(
                withJSONObject: dictionary,
                options: []
              ),
              data.count <= RelayLimits.maxFrameBytes
        else { return false }
        return true
    }

    public static func isValidJSONValue(_ value: Any, depth: Int) -> Bool {
        guard depth <= RelayLimits.maxJSONDepth else { return false }
        if value is NSNull { return true }
        if value is String { return true }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return true }
            return number.doubleValue.isFinite
        }
        if let array = value as? [Any] {
            guard array.count <= RelayLimits.maxCollectionEntries else {
                return false
            }
            return array.allSatisfy { isValidJSONValue($0, depth: depth + 1) }
        }
        if let dictionary = object(value) {
            guard dictionary.count <= RelayLimits.maxCollectionEntries else {
                return false
            }
            return dictionary.values.allSatisfy {
                isValidJSONValue($0, depth: depth + 1)
            }
        }
        return false
    }

    public static func serializedSize(_ value: Any) -> Int {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(
                withJSONObject: value,
                options: []
              )
        else { return Int.max }
        return data.count
    }
}

public enum RelayReply {
    public static func success(
        token: String,
        frames: [[String: Any]]
    ) -> [String: Any] {
        [
            "v": RelayLimits.protocolVersion,
            "token": token,
            "ok": true,
            "frames": frames,
        ]
    }

    /// Failure replies deliberately carry no error text, frames or approval.
    public static func failure(token: String) -> [String: Any] {
        ["v": RelayLimits.protocolVersion, "token": token, "ok": false]
    }

    public static func protocolFailure() -> [String: Any] {
        ["v": RelayLimits.protocolVersion, "ok": false]
    }

    /// Validates a containing-app reply before it is returned to Safari. This
    /// prevents a relay bug from being forwarded as a fabricated native frame.
    public static func parse(_ raw: Any, expectedToken: String) -> [String: Any]? {
        guard let object = RelayEnvelope.object(raw) else { return nil }
        guard Set(object.keys).isSubset(of: Set(["v", "token", "ok", "frames"])) else {
            return nil
        }
        guard let version = RelayEnvelope.integer(object["v"]),
              version == RelayLimits.protocolVersion,
              object["token"] as? String == expectedToken,
              let ok = RelayEnvelope.boolean(object["ok"])
        else { return nil }
        if !ok {
            guard !object.keys.contains("frames") else { return nil }
            return failure(token: expectedToken)
        }
        guard let rawFrames = object["frames"] as? [Any] else { return nil }
        guard rawFrames.count <= RelayLimits.maxFramesPerPoll else { return nil }
        var frames: [[String: Any]] = []
        for rawFrame in rawFrames {
            guard let frame = RelayEnvelope.object(rawFrame),
                  RelayEnvelope.isValidFrame(frame)
            else { return nil }
            frames.append(frame)
        }
        let reply = success(token: expectedToken, frames: frames)
        guard RelayEnvelope.serializedSize(reply) <= RelayLimits.maxReplyBytes
        else { return nil }
        return reply
    }
}
