import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private let relay = ExtensionRelay()

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let rawMessage = item?.userInfo?[SFExtensionMessageKey]
        // SFExtensionProfileKey exists only on macOS 14+. The binding policy
        // is unchanged: the trusted native context is the only profile
        // source, so when the key is unavailable the value is nil and no
        // JS-supplied profile is ever substituted.
        let profileKey: String?
        if #available(macOS 14.0, *) {
            do {
                // Apple's example supplies the profile as a UUID; the shared
                // helper canonicalises it and refuses any other present type.
                profileKey = try TrustedSafariProfile.identifier(
                    item?.userInfo?[SFExtensionProfileKey]
                )
            } catch {
                // A present but mistyped profile is a mistake, never "no
                // profile": cancel before the relay sees the request so a
                // profiled session cannot be reached as an unprofiled one.
                context.cancelRequest(withError: RelayError.unavailable)
                return
            }
        } else {
            profileKey = nil
        }
        let response = relay.handle(
            rawMessage: rawMessage,
            profileKey: profileKey
        )
        let responseItem = NSExtensionItem()
        responseItem.userInfo = [SFExtensionMessageKey: response]
        context.completeRequest(
            returningItems: [responseItem],
            completionHandler: nil
        )
    }
}
