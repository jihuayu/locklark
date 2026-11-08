import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private let relay = ExtensionRelay()

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let rawMessage = item?.userInfo?[SFExtensionMessageKey]
        let profileKey = item?.userInfo?[SFExtensionProfileKey] as? String
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
