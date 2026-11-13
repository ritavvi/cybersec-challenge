//
//  KeychainHelper.swift
//  m0insecure
//
//  Created by Srinidhi Narendran on 13/11/2026.
//

import Foundation
import LocalAuthentication

final class KeychainHelper {
    static let shared = KeychainHelper()
    private init() {}

    // MARK: - Save

    /// Stores the token in the Keychain using the given `account` identifier.
    /// The item is protected with `.biometryCurrentSet` so the user must authenticate
    /// with Face ID / Touch ID (or device passcode) each time it is read.
    func save(token: String, for account: String) throws {
        // Enforce strong token requirements (defense against brute-force / Hydra)
        guard token.count >= 8 else {
            throw KeychainError.weakToken("Must be at least 8 characters long.")
        }
        guard token.rangeOfCharacter(from: .uppercaseLetters) != nil else {
            throw KeychainError.weakToken("Must contain at least one uppercase letter.")
        }
        guard token.rangeOfCharacter(from: .decimalDigits) != nil else {
            throw KeychainError.weakToken("Must contain at least one number.")
        }
        let specialSet = CharacterSet(charactersIn: "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
        guard token.rangeOfCharacter(from: specialSet) != nil else {
            throw KeychainError.weakToken("Must contain at least one special character.")
        }

        guard let data = token.data(using: .utf8) else {
            throw KeychainError.invalidData
        }

        // Prepare the access control – require biometric auth each read.
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &error
        )
        if let err = error?.takeRetainedValue() {
            throw err
        }

        // Build the query
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access as Any,
            kSecUseOperationPrompt as String: "Authenticate to save your token"
        ]

        // Delete any existing item first (Keychain doesn't allow duplicate accounts)
        try? deleteToken(for: account)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandledOSStatus(status)
        }
    }

    // MARK: - Load

    /// Retrieves the token for the given `account`. This will automatically
    /// trigger a biometric prompt because of the access control we set above.
    func loadToken(for account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseOperationPrompt as String: "Authenticate to access your token"
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let token = String(data: data, encoding: .utf8) else {
                throw KeychainError.invalidData
            }
            return token
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandledOSStatus(status)
        }
    }

    // MARK: - Delete

    func deleteToken(for account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledOSStatus(status)
        }
    }

    // MARK: - Biometrics Authentication

    /// Prompts the user to authenticate using Face ID / Touch ID (or device passcode fallback).
    func authenticateUser(reason: String) async throws {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            if !success {
                throw KeychainError.authenticationFailed
            }
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            if !success {
                throw KeychainError.authenticationFailed
            }
        } else if let error = error {
            throw error
        }
    }

    // MARK: - Errors

    enum KeychainError: Error, LocalizedError {
        case invalidData
        case weakToken(String)
        case authenticationFailed
        case unhandledOSStatus(OSStatus)

        var errorDescription: String? {
            switch self {
            case .invalidData: return "Unable to encode/decode token data."
            case .weakToken(let reason): return "Weak token: \(reason)"
            case .authenticationFailed: return "Biometric authentication failed or was cancelled."
            case .unhandledOSStatus(let code):
                return "Keychain error (OSStatus: \(code))."
            }
        }
    }
}

// MARK: – Existence‑check helper (no biometric prompt)

extension KeychainHelper {

    /// Checks whether a stored token exists for the given account without triggering a biometric prompt.
    func tokenExists(for account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Returns whether a token exists for the given account without triggering a biometric prompt.
    /// If the item does not exist, returns `nil`. Any other error is thrown.
    func loadTokenWithoutPrompt(for account: String) throws -> String? {
        return tokenExists(for: account) ? "token_exists" : nil
    }
}
