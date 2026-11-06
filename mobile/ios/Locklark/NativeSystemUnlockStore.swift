import Foundation

final class NativeSystemUnlockStore: NSObject, LLSystemUnlockStore {
    let keychain: CapsuleKeychain

    init(authorization: SystemAuthenticationAuthorization? = nil) {
        keychain = CapsuleKeychain(authorization: authorization)
        super.init()
    }

    func store(id: String, value: Data) throws {
        try keychain.store(id: id, value: value)
    }

    func load(id: String) throws -> Data {
        try keychain.load(id: id)
    }

    func delete(id: String) throws {
        try keychain.delete(id: id)
    }
}
