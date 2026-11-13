import SwiftUI
import LocalAuthentication

struct DeleteDemo: View {
    @State private var status = ""
    @State private var showAuthModal = false
    @State private var retrievedToken = ""
    @State private var modalErrorMessage: String? = nil
    @State private var isRetrieving = false

    private let keychainAccount = "com.example.authToken"

    var body: some View {
        VStack(spacing: 20) {
            Button("Delete Account") {
                retrievedToken = ""
                modalErrorMessage = nil
                showAuthModal = true
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)

            Text(status)
                .foregroundColor(.red)

            Spacer()
        }
        .padding()
        .navigationTitle("Delete Demo")
        .sheet(isPresented: $showAuthModal) {
            deleteAuthModalView
        }
    }

    // MARK: - Auth & Delete Modal View

    private var deleteAuthModalView: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // Header / Warning
                VStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 44))
                        .foregroundColor(.red)

                    Text("Confirm Account Deletion")
                        .font(.title2.bold())

                    Text("Are you sure you want to permanently delete? This action cannot be undone. To proceed, retrieve your authentication token using Face ID.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                .padding(.top)

                // Security Token Box (Masked, Read-Only)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Authentication Token")
                        .font(.caption.bold())
                        .foregroundColor(.secondary)

                    HStack {
                        Image(systemName: "lock.fill")
                            .foregroundColor(.secondary)

                        // Masked token display – not in plain text, user cannot type manually
                        SecureField("Token required to delete", text: $retrievedToken)
                            .disabled(true)
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(retrievedToken.isEmpty ? Color.gray.opacity(0.3) : Color.green, lineWidth: 1.5)
                    )

                    if !retrievedToken.isEmpty {
                        Label("Token verified via Face ID", systemImage: "checkmark.seal.fill")
                            .font(.caption)
                            .foregroundColor(.green)
                    }
                }
                .padding(.horizontal)

                if let errorMessage = modalErrorMessage {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                // Action Buttons
                if retrievedToken.isEmpty {
                    // Cancel on the left, Retrieve Token on the right
                    HStack(spacing: 16) {
                        Button("Cancel") {
                            showAuthModal = false
                        }
                        .buttonStyle(.bordered)
                        .frame(maxWidth: .infinity)

                        Button {
                            retrieveToken()
                        } label: {
                            HStack {
                                if isRetrieving {
                                    ProgressView()
                                        .padding(.trailing, 4)
                                } else {
                                    Image(systemName: "faceid")
                                }
                                Text("Retrieve Token")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isRetrieving)
                        .frame(maxWidth: .infinity)
                    }
                    .padding(.horizontal)
                } else {
                    // Bright red "Permanently Delete" button
                    VStack(spacing: 12) {
                        Button(role: .destructive) {
                            permanentlyDelete()
                        } label: {
                            HStack {
                                Image(systemName: "trash.fill")
                                Text("Permanently Delete")
                                    .fontWeight(.bold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 4)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)

                        Button("Cancel") {
                            showAuthModal = false
                        }
                        .foregroundColor(.secondary)
                    }
                    .padding(.horizontal)
                }

                Spacer()
            }
            .padding()
            .presentationDetents([.medium, .large])
            .presentationDragIndicator(.visible)
        }
    }

    // MARK: - Actions

    private func retrieveToken() {
        isRetrieving = true
        modalErrorMessage = nil
        Task {
            do {
                if let token = try KeychainHelper.shared.loadToken(for: keychainAccount) {
                    await MainActor.run {
                        retrievedToken = token
                        isRetrieving = false
                        modalErrorMessage = nil
                    }
                } else {
                    await MainActor.run {
                        isRetrieving = false
                        modalErrorMessage = "No token found in Keychain. Please create a token in Token Storage Demo first."
                    }
                }
            } catch {
                await MainActor.run {
                    isRetrieving = false
                    modalErrorMessage = "Face ID failed: \(error.localizedDescription)"
                }
            }
        }
    }

    private func permanentlyDelete() {
        Task {
            try? KeychainHelper.shared.deleteToken(for: keychainAccount)
            await MainActor.run {
                status = "Account permanently deleted ❌"
                showAuthModal = false
                retrievedToken = ""
            }
        }
    }
}

#Preview {
    DeleteDemo()
}
