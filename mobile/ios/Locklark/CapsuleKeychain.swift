import Foundation
import LocalAuthentication
import Security

enum PlatformProtectionError: Error {
    case unavailable
    case authenticationCancelled
    case storageDenied
    case invalidCapsule
}

protocol KeychainClient {
    func add(_ attributes: [String: Any]) -> OSStatus
    func copy(_ query: [String: Any], result: inout CFTypeRef?) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

struct SystemKeychainClient: KeychainClient {
    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    func copy(_ query: [String: Any], result: inout CFTypeRef?) -> OSStatus {
        SecItemCopyMatching(query as CFDictionary, &result)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}

// This adapter persists only the core's encrypted, path/slot-bound capsule.
// Neither full factor is accepted here. There is no file/UserDefaults fallback.
final class CapsuleKeychain {
    private let service: String
    private let client: KeychainClient
    private let makeAccessControl: (CFString, SecAccessControlCreateFlags) throws -> SecAccessControl
    private let contextLock = NSLock()
    private var contexts: [UUID: LAContext] = [:]
    private var acceptingAuthentication = true

    init(service: String = "org.locklark.mobile.ios.system-unlock", client: KeychainClient = SystemKeychainClient(), makeAccessControl: ((CFString, SecAccessControlCreateFlags) throws -> SecAccessControl)? = nil) {
        self.service = service
        self.client = client
        self.makeAccessControl = makeAccessControl ?? { accessibility, flags in
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil, accessibility, flags, &error) else {
                throw PlatformProtectionError.unavailable
            }
            return control
        }
    }

    private func query(id: String) throws -> [String: Any] {
        guard !id.isEmpty, id.utf8.count <= 512, !id.contains("\0") else {
            throw PlatformProtectionError.invalidCapsule
        }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    func store(id: String, value: Data) throws {
        guard !value.isEmpty, value.count <= 65_536 else { throw PlatformProtectionError.invalidCapsule }
        let control = try makeAccessControl(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence)
        var attributes = try query(id: id)
        let removed = client.delete(attributes)
        guard removed == errSecSuccess || removed == errSecItemNotFound else {
            throw PlatformProtectionError.storageDenied
        }
        attributes[kSecAttrAccessControl as String] = control
        attributes[kSecValueData as String] = value
        guard client.add(attributes) == errSecSuccess else { throw PlatformProtectionError.storageDenied }
    }

    func load(id: String) throws -> Data {
        var attributes = try query(id: id)
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let token = UUID()
        contextLock.lock()
        guard acceptingAuthentication else {
            contextLock.unlock()
            throw PlatformProtectionError.authenticationCancelled
        }
        contexts[token] = context
        contextLock.unlock()
        defer {
            contextLock.lock()
            contexts.removeValue(forKey: token)
            contextLock.unlock()
            context.invalidate()
        }
        attributes[kSecUseAuthenticationContext as String] = context
        attributes[kSecUseOperationPrompt as String] = "解锁此设备上的 Locklark 金库"
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = client.copy(attributes, result: &result)
        guard status == errSecSuccess else {
            if status == errSecUserCanceled || status == errSecAuthFailed || status == errSecInteractionNotAllowed {
                throw PlatformProtectionError.authenticationCancelled
            }
            throw PlatformProtectionError.storageDenied
        }
        guard let data = result as? Data, !data.isEmpty, data.count <= 65_536 else {
            throw PlatformProtectionError.invalidCapsule
        }
        return data
    }

    func delete(id: String) throws {
        let status = client.delete(try query(id: id))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformProtectionError.storageDenied
        }
    }

    // Never hold a lock across Security.framework or an authentication dialog.
    func cancelAuthentication() {
        contextLock.lock()
        acceptingAuthentication = false
        let pending = Array(contexts.values)
        contextLock.unlock()
        pending.forEach { $0.invalidate() }
    }
}
