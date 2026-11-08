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
            profileKey = item?.userInfo?[SFExtensionProfileKey] as? String
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
