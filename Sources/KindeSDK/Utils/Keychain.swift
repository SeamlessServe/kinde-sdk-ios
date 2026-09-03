
import Foundation
import AppAuth

class Keychain {
    private static func addQuery(service: String, password: Data) -> [String: Any] {
        guard let encodedIdentifier: Data = service.data(using: String.Encoding.utf8) else {
            return [:]
        }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Bundle.main.bundleIdentifier ?? "KeychainWrapper",
                kSecAttrSynchronizable as String: false,
                kSecAttrGeneric as String: encodedIdentifier,
                kSecAttrAccount as String: encodedIdentifier,
                kSecValueData as String: password,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly] as [String : Any]
    }

    private static func retrieveQuery(service: String) -> [String: Any] {
        guard let encodedIdentifier: Data = service.data(using: String.Encoding.utf8) else {
            return [:]
        }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Bundle.main.bundleIdentifier ?? "KeychainWrapper",
                kSecAttrSynchronizable as String: false,
                kSecAttrGeneric as String: encodedIdentifier,
                kSecAttrAccount as String: encodedIdentifier,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnData as String: true] as [String : Any]
    }
    
    private static func searchQuery(service: String) -> [String: Any] {
        guard let encodedIdentifier: Data = service.data(using: String.Encoding.utf8) else {
            return [:]
        }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Bundle.main.bundleIdentifier ?? "KeychainWrapper",
                kSecAttrSynchronizable as String: false,
                kSecAttrGeneric as String: encodedIdentifier,
                kSecAttrAccount as String: encodedIdentifier] as [String : Any]
    }

    private static func updateQuery(password: Data) -> CFDictionary {
        [kSecValueData as String: password,
         kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly ] as [String : Any] as CFDictionary
    }

    private static func update(service: String, value: String) -> OSStatus {
        update(service: service, value: value.data(using: .utf8)!)
    }
    
    @discardableResult
    static func update(service: String, value: Data) -> OSStatus {
        let keychainQueryDictionary = addQuery(service: service, password: value)

        let status: OSStatus = SecItemAdd(keychainQueryDictionary as CFDictionary, nil)

        // A previous item can survive when the delete before this add could not run - most often
        // because the device was locked. Without this, SecItemAdd returns errSecDuplicateItem and the
        // refreshed auth state is silently dropped, leaving a stale (and, under refresh token
        // rotation, already consumed) token on disk. Update in place instead, which also restamps
        // kSecAttrAccessible so items written by earlier builds migrate off kSecAttrAccessibleWhenUnlocked.
        if status == errSecDuplicateItem {
            return SecItemUpdate(searchQuery(service: service) as CFDictionary,
                                 updateQuery(password: value))
        }

        return status
    }
    
    @discardableResult
    static func delete(service: String) -> OSStatus {
        let keychainQueryDictionary = searchQuery(service: service) as CFDictionary
        let status: OSStatus = SecItemDelete(keychainQueryDictionary)

        return status
    }
    
    static func set(state: NSCoding?, service: String) -> Bool {
        if let state = state {
            do {
                let data = try NSKeyedArchiver.archivedData(withRootObject: state,
                                                            requiringSecureCoding: true)
                return update(service: service, value: data) == errSecSuccess
            } catch {
                return false
            }
        } else {
            return delete(service: service) == errSecSuccess
        }
    }
    
    static func get(_ service: String) -> NSCoding? {
        var result: AnyObject?

        let status = SecItemCopyMatching(retrieveQuery(service: service) as CFDictionary, &result)
        
        if status == noErr,
           let data = result as? Data {
            do {
                let unarchivedObject = try NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: data)
                return unarchivedObject
            } catch {
                return nil
            }
        }
        return nil
    }
}
