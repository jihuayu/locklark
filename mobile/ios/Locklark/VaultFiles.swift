import Foundation

enum VaultFiles {
    static func prepare(fileManager: FileManager = .default) throws -> URL {
        let support = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("Locklark", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        try protect(directory: directory, fileManager: fileManager)
        return directory.appendingPathComponent("personal.ll", isDirectory: false)
    }

    static func protect(directory: URL, fileManager: FileManager = .default) throws {
        var urls = [directory]
        var enumerationFailed = false
        guard let enumerator = fileManager.enumerator(at: directory, includingPropertiesForKeys: [.isSymbolicLinkKey], options: [], errorHandler: { _, _ in enumerationFailed = true; return false }) else {
            throw PlatformProtectionError.storageDenied
        }
        while let url = enumerator.nextObject() as? URL { urls.append(url) }
        guard !enumerationFailed else { throw PlatformProtectionError.storageDenied }
        for var url in urls {
            let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw PlatformProtectionError.storageDenied }
            var resource = URLResourceValues()
            resource.isExcludedFromBackup = true
            try url.setResourceValues(resource)
            try fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            guard try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
                throw PlatformProtectionError.storageDenied
            }
        }
        try verifyProtection(directory: directory, fileManager: fileManager)
    }

    // Called immediately after Go creates its database, before strengthening
    // existing attributes, to verify the actual native default on this OS.
    static func verifyProtection(directory: URL, fileManager: FileManager = .default) throws {
        var enumerationFailed = false
        guard let enumerator = fileManager.enumerator(at: directory, includingPropertiesForKeys: [.isSymbolicLinkKey], errorHandler: { _, _ in enumerationFailed = true; return false }) else {
            throw PlatformProtectionError.storageDenied
        }
        var urls = [directory]
        while let url = enumerator.nextObject() as? URL { urls.append(url) }
        guard !enumerationFailed else { throw PlatformProtectionError.storageDenied }
        for url in urls {
            guard try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true,
                  try fileManager.attributesOfItem(atPath: url.path)[.protectionKey] as? FileProtectionType == .complete else {
                throw PlatformProtectionError.storageDenied
            }
        }
    }
}
