import SwiftUI
import LocalAuthentication   // needed for the Keychain helper (already imported there)

struct TokenStorageDemo: View {
    // MARK: - UI state
    @State private var tokenInput: String = ""          // what the user is typing
    @State private var hasToken: Bool = false          // does a token already exist?
    @State private var creatingMode: Bool = true       // true = “create”, false = “replace/delete”
    @State private var showConfirmReplaceAlert = false // replace alert visibility
    @State private var showConfirmDeleteAlert = false  // delete alert visibility
    @State private var statusMessage: String? = nil    // error or status message
    @State private var isSuccessMessage: Bool = false  // style status message

    // MARK: - Constants
    private let keychainAccount = "com.example.authToken"
    private static let specialCharacterSet = CharacterSet(charactersIn: "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")

    // MARK: - Validation Properties

    private var hasMinLength: Bool { tokenInput.count >= 8 }
    private var hasUppercase: Bool { tokenInput.rangeOfCharacter(from: .uppercaseLetters) != nil }
    private var hasNumber: Bool { tokenInput.rangeOfCharacter(from: .decimalDigits) != nil }
    private var hasSpecialChar: Bool { tokenInput.rangeOfCharacter(from: Self.specialCharacterSet) != nil }

    private var isTokenValid: Bool {
        hasMinLength && hasUppercase && hasNumber && hasSpecialChar
    }

    private func validateToken(_ token: String) -> String? {
        if token.count < 8 {
            return "Token must be at least 8 characters long."
        }
        if token.rangeOfCharacter(from: .uppercaseLetters) == nil {
            return "Token must contain at least one uppercase letter."
        }
        if token.rangeOfCharacter(from: .decimalDigits) == nil {
            return "Token must contain at least one number."
        }
        if token.rangeOfCharacter(from: Self.specialCharacterSet) == nil {
            return "Token must contain at least one special character."
        }
        return nil
    }

    var body: some View {
        VStack(spacing: 20) {
            // -----------------------------------------------------------------
            // 1️⃣ Prompt / edit field
            // -----------------------------------------------------------------
            if creatingMode {
                // No token yet – ask to create one
                SecureField("Create new token", text: $tokenInput)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)

                tokenRequirementsView

                Button("Create") {
                    if let error = validateToken(tokenInput) {
                        isSuccessMessage = false
                        statusMessage = error
                        return
                    }
                    saveToken()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!isTokenValid)
            } else {
                // Token already exists – allow replace or delete
                Text("Token has been created.")
                    .font(.subheadline)
                    .foregroundColor(.green)

                SecureField("Type here to replace it", text: $tokenInput)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)

                tokenRequirementsView

                HStack(spacing: 16) {
                    Button("Replace") {
                        if let error = validateToken(tokenInput) {
                            isSuccessMessage = false
                            statusMessage = error
                            return
                        }
                        showConfirmReplaceAlert = true
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isTokenValid)

                    Button("Delete Token", role: .destructive) {
                        showConfirmDeleteAlert = true
                    }
                    .buttonStyle(.bordered)
                }
                .alert("Are you sure you want to replace the token?", isPresented: $showConfirmReplaceAlert) {
                    Button("Cancel", role: .cancel) {}
                    Button("Yes, replace", role: .destructive) {
                        replaceToken()
                    }
                }
                .alert("Are you sure you want to delete the token?", isPresented: $showConfirmDeleteAlert) {
                    Button("Cancel", role: .cancel) {}
                    Button("Yes, delete", role: .destructive) {
                        deleteTokenAction()
                    }
                }
            }

            if let message = statusMessage {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: isSuccessMessage ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundColor(isSuccessMessage ? .green : .red)
                    Text(message)
                        .font(.caption)
                        .foregroundColor(isSuccessMessage ? .green : .red)
                }
                .padding(8)
                .background(isSuccessMessage ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
                .cornerRadius(8)
                .padding(.horizontal)
            }

            Spacer()
        }
        .padding()
        .navigationTitle("Token Storage (Secure)")
        .task {
            // -----------------------------------------------------------------
            // 2️⃣ Determine at launch whether a token already exists
            // -----------------------------------------------------------------
            await checkIfTokenExists()
        }
    }

    // MARK: - Requirements View

    private var tokenRequirementsView: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Token Requirements (anti-brute-force):")
                .font(.caption.bold())
                .foregroundColor(.secondary)

            HStack {
                requirementBadge(label: "8+ chars", isMet: hasMinLength)
                requirementBadge(label: "Uppercase", isMet: hasUppercase)
            }
            HStack {
                requirementBadge(label: "Number", isMet: hasNumber)
                requirementBadge(label: "Special char", isMet: hasSpecialChar)
            }
        }
        .padding(.horizontal)
    }

    private func requirementBadge(label: String, isMet: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: isMet ? "checkmark.circle.fill" : "circle")
                .foregroundColor(isMet ? .green : .gray)
            Text(label)
                .font(.caption2)
                .foregroundColor(isMet ? .primary : .secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Helper functions

    /// Checks the Keychain without triggering biometric auth.
    private func checkIfTokenExists() async {
        let exists = KeychainHelper.shared.tokenExists(for: keychainAccount)
        await MainActor.run {
            hasToken = exists
            creatingMode = !exists
        }
    }

    /// Saves the token the first time (no previous token to delete).
    private func saveToken() {
        let tokenToSave = tokenInput
        Task {
            do {
                try InputSanitizer.shared.validateSafety(input: tokenToSave, fieldName: "Token")
                try KeychainHelper.shared.save(token: tokenToSave, for: keychainAccount)
                await MainActor.run {
                    hasToken = true
                    creatingMode = false
                    tokenInput = ""
                    statusMessage = nil
                }
            } catch {
                await MainActor.run {
                    isSuccessMessage = false
                    statusMessage = error.localizedDescription
                }
            }
        }
    }

    /// Authenticates with Face ID, then deletes the old token and saves the new one.
    private func replaceToken() {
        let tokenToSave = tokenInput
        Task {
            do {
                try InputSanitizer.shared.validateSafety(input: tokenToSave, fieldName: "Token")
                // 1️⃣ Require Face ID authentication
                try await KeychainHelper.shared.authenticateUser(reason: "Authenticate with Face ID to replace your token.")

                // 2️⃣ Delete the old entry
                try? KeychainHelper.shared.deleteToken(for: keychainAccount)

                // 3️⃣ Save the new token (biometric-protected)
                try KeychainHelper.shared.save(token: tokenToSave, for: keychainAccount)

                // 4️⃣ Update UI
                await MainActor.run {
                    tokenInput = ""
                    isSuccessMessage = true
                    statusMessage = "Token successfully replaced!"
                }
            } catch {
                await MainActor.run {
                    isSuccessMessage = false
                    statusMessage = error.localizedDescription
                }
            }
        }
    }

    /// Authenticates with Face ID, then deletes the token and returns to creation mode.
    private func deleteTokenAction() {
        Task {
            do {
                // 1️⃣ Require Face ID authentication
                try await KeychainHelper.shared.authenticateUser(reason: "Authenticate with Face ID to delete your token.")

                // 2️⃣ Delete token
                try KeychainHelper.shared.deleteToken(for: keychainAccount)

                // 3️⃣ Update UI
                await MainActor.run {
                    hasToken = false
                    creatingMode = true
                    tokenInput = ""
                    isSuccessMessage = true
                    statusMessage = "Token successfully deleted."
                }
            } catch {
                await MainActor.run {
                    isSuccessMessage = false
                    statusMessage = error.localizedDescription
                }
            }
        }
    }
}
