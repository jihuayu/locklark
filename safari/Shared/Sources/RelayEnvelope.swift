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
    /// Opaque Safari profile identifier, only present on app-bound open
    /// envelopes. It is never derived from a page or native frame.
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

    public static func parse(_ raw: Any) -> RelayRequest? {
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

        switch operation {
        case .send:
            guard Set(object.keys) == Set(["v", "op", "token", "frame"]) else {
                return nil
            }
            guard let rawFrame = object["frame"],
                  let frame = RelayEnvelope.object(rawFrame),
                  RelayEnvelope.isValidFrame(frame)
            else { return nil }
            guard RelayEnvelope.serializedSize(object) <=
                RelayLimits.maxFrameBytes + 4096
            else { return nil }
            return RelayRequest(operation: .send, token: token, frame: frame)
        case .open:
            let allowed: Set<String> = ["v", "op", "token", "profile"]
            guard Set(object.keys).isSubset(of: allowed) else { return nil }
            let profileKey: String?
            if let rawProfile = object["profile"] {
                guard let profile = rawProfile as? String,
                      RelayEnvelope.isValidProfileKey(profile)
                else { return nil }
                profileKey = profile
            } else {
                profileKey = nil
            }
            guard RelayEnvelope.serializedSize(object) <= 4096 else {
                return nil
            }
            return RelayRequest(
                operation: .open,
                token: token,
                profileKey: profileKey
            )
        case .poll, .close:
            guard Set(object.keys) == Set(["v", "op", "token"]) else { return nil }
            guard RelayEnvelope.serializedSize(object) <= 4096 else {
                return nil
            }
            return RelayRequest(operation: operation, token: token)
        }
    }

    /// Rebuilds the app-bound envelope from validated fields. Unknown Safari
    /// message keys are never forwarded; only SFExtensionProfileKey can add
    /// the bounded open-time profile field.
    public func forwardingEnvelope(profileKey: String? = nil) -> [String: Any] {
        var object: [String: Any] = [
            "v": RelayLimits.protocolVersion,
            "op": operation.rawValue,
            "token": token,
        ]
        if let frame { object["frame"] = frame }
        let effectiveProfile = profileKey ?? self.profileKey
        if operation == .open, let effectiveProfile,
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

    public static func isValidProfileKey(_ value: String) -> Bool {
        guard value.utf8.count >= 1, value.utf8.count <= 256 else {
            return false
        }
        for scalar in value.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7F { return false }
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
              let ok = boolean(object["ok"])
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
