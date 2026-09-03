import AppAuth
/// A repository for caching the current authentication state, and
/// storing it securely on the device keychain
class AuthStateRepository: NSObject {
    private let key: String
    private let logger: LoggerProtocol?
    @Atomic private var cachedState: OIDAuthState?
    
    init(key: String, logger: LoggerProtocol?) {
        self.key = key
        self.logger = logger
    }
    
    /// The current authentication state
    var state: OIDAuthState? {
        if let state = cachedState {
            return state
        }
        
        if let authState = Keychain.get(self.key) {
            self.logger?.debug(message: "Loaded authState from the keychain")
            cachedState = authState as? OIDAuthState
            
            // Register handlers for changes to authState (e.g., token refresh)
            cachedState?.stateChangeDelegate = self
            cachedState?.errorDelegate = self
            
            return cachedState
        } else {
            self.logger?.error(message: "Failed to load authState from the keychain")
            return nil
        }
    }
    
    /// Set the current authentication state
    func setState(_ state: OIDAuthState) -> Bool {
        cachedState = state
        
        // Register handlers for changes to authState (e.g., token refresh)
        cachedState?.stateChangeDelegate = self
        cachedState?.errorDelegate = self
        
        return persistToKeychain(state: state)
    }
    
    /// Clear the current authentication state
    func clear() -> Bool {
        cachedState = nil
        return removeFromKeychain()
    }
    
    private func persistToKeychain(state: OIDAuthState) -> Bool {
        removeFromKeychain()
        let persisted = Keychain.set(state: state, service: self.key)
        if !persisted {
            self.logger?.error(message: "Failed to persist authState to the keychain")
            return false
        }
        self.logger?.debug(message: "Persisted authState to the keychain")
        return true
    }
    
    @discardableResult
    private func removeFromKeychain() -> Bool {
        // Deliberately not gated on Keychain.get: that read fails while the device is locked, which
        // used to skip the delete and still report success. SecItemDelete is idempotent, so calling
        // it unconditionally is both simpler and honest about what happened.
        let status = Keychain.delete(service: self.key)
        if status != errSecSuccess && status != errSecItemNotFound {
            self.logger?.error(message: "Failed to remove authState from the keychain")
            return false
        }
        self.logger?.debug(message: "Removed authState from the keychain")
        return true
    }
}

/// OIDAuthState changed state handling
extension AuthStateRepository: OIDAuthStateChangeDelegate, OIDAuthStateErrorDelegate {
    public func didChange(_ state: OIDAuthState) {
        let updated = self.setState(state)
        if updated {
            self.logger?.debug(message: "Updated authState after change")
        } else {
            self.logger?.error(message: "Failed to update authState after change")
        }
    }

    public func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
        let updated = self.setState(state)
        if updated {
            self.logger?.debug(message: "Updated authState after change due to error \(error.localizedDescription)")
        } else {
            self.logger?.error(message: "Failed to update authState after change due to error \(error.localizedDescription)")
        }
    }
}
