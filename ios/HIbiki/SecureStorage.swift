import Foundation
import Security

struct SecureStorage {
    private static let service = "com.akinokaede.hibiki.identity"
    static func identity() throws -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: "device",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw keychainError(status) }
        return result as? Data
    }
    static func saveIdentity(_ data: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: "device",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false, kSecValueData as String: data]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw keychainError(status) }
    }
    private static func keychainError(_ status: OSStatus) -> Error {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil) as String? ?? "Keychain unavailable"])
    }
    static func directory() throws -> URL {
        var url = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("HIbiki", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.complete])
        var resources = URLResourceValues()
        resources.isExcludedFromBackup = true
        try url.setResourceValues(resources)
        return url
    }
}
