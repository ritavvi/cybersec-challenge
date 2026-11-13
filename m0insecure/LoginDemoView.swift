import SwiftUI
import UIKit
import ActivityKit
import LocalAuthentication

struct LoginDemoView: View {
    @State private var email = ""
    @State private var password = ""
    @State private var isPasswordVisible = false
    @State private var errorMessage: String?
    @State private var successMessage: String?
    @FocusState private var emailFieldFocused: Bool
    @State private var walletActivity: Activity<WalletAuthActivityAttributes>?

    var body: some View {
        Form {
            Section(header: Text("Login")) {
                TextField("Email", text: $email)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.emailAddress)
                    .focused($emailFieldFocused)

                if emailFieldFocused {
                    Button {
                        authenticateAndFillFromWallet()
                    } label: {
                        Label("Saved in Password manager — Use Face ID", systemImage: "faceid")
                    }
                }

                HStack {
                    Group {
                        if isPasswordVisible {
                            TextField("Password", text: $password)
                        } else {
                            SecureField("Password", text: $password)
                        }
                    }
                    .textContentType(.password)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    Button {
                        isPasswordVisible.toggle()
                    } label: {
                        Image(systemName: isPasswordVisible ? "eye.slash" : "eye")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(isPasswordVisible ? "Hide password" : "Show password")
                }
            }

            Button("Login") {
                login()
            }

            if let error = errorMessage {
                Section {
                    Text(error)
                        .foregroundColor(.red)
                }
            }

            if let success = successMessage {
                Section {
                    Text(success)
                        .foregroundColor(.green)
                }
            }

            Section {
                NavigationLink {
                    AccountRecoveryView()
                } label: {
                    Text("I forgot my email and password")
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Login Demo")
    }

    private func login() {
        // Demo credentials only. Keep the response identical for either credential failure.
        let realEmail = "user@example.com"
        let realPassword = "Password123"

        guard email == realEmail && password == realPassword else {
            errorMessage = "Wrong credentials"
            successMessage = nil
            return
        }
        errorMessage = nil
        successMessage = "You successfully logged in"
    }

    private func authenticateAndFillFromWallet() {
        errorMessage = nil
        successMessage = nil

        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            #if targetEnvironment(simulator)
            errorMessage = "Face ID is not enrolled in this simulator. In Simulator, choose Features > Face ID > Enrolled, then try again."
            #else
            errorMessage = "Face ID is unavailable on this device."
            #endif
            return
        }

        Task {
            await startWalletActivity()
            do {
                let authenticated = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics,
                    localizedReason: "Use Face ID to fill the saved demo credentials"
                )
                if authenticated {
                    fillWalletCredentials()
                    await endWalletActivity(status: "Credentials filled")
                }
            } catch {
                errorMessage = "Face ID verification failed"
                successMessage = nil
                await endWalletActivity(status: "Verification cancelled")
            }
        }
    }

    private func fillWalletCredentials() {
        email = "user@example.com"
        password = "Password123"
        emailFieldFocused = false
        errorMessage = nil
        successMessage = nil
    }

    @MainActor
    private func startWalletActivity() async {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        let attributes = WalletAuthActivityAttributes(title: "Wallet")
        let content = ActivityContent(state: WalletAuthActivityAttributes.ContentState(status: "Reading Face ID"), staleDate: Date().addingTimeInterval(60))
        walletActivity = try? Activity.request(attributes: attributes, content: content)
    }

    @MainActor
    private func endWalletActivity(status: String) async {
        guard let walletActivity else { return }
        let finalContent = ActivityContent(state: WalletAuthActivityAttributes.ContentState(status: status), staleDate: nil)
        await walletActivity.end(finalContent, dismissalPolicy: .after(Date().addingTimeInterval(2)))
        self.walletActivity = nil
    }
}

private struct AccountRecoveryView: View {
    var body: some View {
        Form {
            Section {
                Text("Choose what you need help recovering.")
                    .foregroundStyle(.secondary)

                NavigationLink("I forgot my email") {
                    RecoveryVerificationView(kind: .email)
                }

                NavigationLink("I forgot my password") {
                    RecoveryVerificationView(kind: .password)
                }
            }
        }
        .navigationTitle("Account Recovery")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private enum RecoveryKind: Equatable {
    case email
    case password

    var title: String {
        self == .email ? "Recover Email" : "Reset Password"
    }

    var contactLabel: String {
        self == .email ? "Phone number" : "Email"
    }

    var contactContentType: UITextContentType {
        self == .email ? .telephoneNumber : .emailAddress
    }

    var keyboardType: UIKeyboardType {
        self == .email ? .phonePad : .emailAddress
    }

    var codeDestination: String {
        self == .email ? "your phone number" : "your email address"
    }
}

private struct RecoveryVerificationView: View {
    let kind: RecoveryKind
    @State private var contact = ""
    @State private var challenge = PictureCaptchaChallenge.make()
    @State private var selectedTiles: Set<Int> = []
    @State private var challengeVerified = false
    @State private var codeRequested = false
    @State private var message: String?

    private var selectedExactlyMatchesTargets: Bool {
        selectedTiles == challenge.targetIndices
    }

    var body: some View {
        Form {
            Section {
                Text("Verify you’re not a robot before requesting a verification code.")
                    .foregroundStyle(.secondary)
                Text("Select all the images that show \(challenge.targetName.lowercased()).")
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                    ForEach(challenge.tiles.indices, id: \.self) { index in
                        Button {
                            if selectedTiles.contains(index) {
                                selectedTiles.remove(index)
                            } else {
                                selectedTiles.insert(index)
                            }
                            challengeVerified = selectedExactlyMatchesTargets
                        } label: {
                            Text(challenge.tiles[index].symbol)
                                .font(.system(size: 48))
                            .frame(maxWidth: .infinity, minHeight: 82)
                            .background(selectedTiles.contains(index) ? Color.blue.opacity(0.16) : Color.secondary.opacity(0.08))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(selectedTiles.contains(index) ? Color.blue : .clear, lineWidth: 2))
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(challenge.tiles[index].caption)
                        .accessibilityAddTraits(selectedTiles.contains(index) ? .isSelected : [])
                    }
                }
                Button("Try another challenge") {
                    challenge = PictureCaptchaChallenge.make(excluding: challenge.targetName)
                    selectedTiles = []
                    challengeVerified = false
                    codeRequested = false
                    message = nil
                }
                Label(
                    challengeVerified ? "Verification complete" : "Select every matching image",
                    systemImage: challengeVerified ? "checkmark.circle.fill" : "circle"
                )
                .foregroundStyle(challengeVerified ? .green : .secondary)
            } header: {
                Text("Robot Check")
            }

            Section {
                TextField(kind.contactLabel, text: $contact)
                    .textContentType(kind.contactContentType)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(kind.keyboardType)

                Button("Send verification code") {
                    requestCode()
                }
                .disabled(!challengeVerified || contact.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            } header: {
                Text(kind.title)
            } footer: {
                Text("For privacy, the app should not reveal whether an account matches these details.")
            }

            if codeRequested, let message {
                Section {
                    Text(message)
                        .foregroundStyle(.green)
                }
            }

        }
        .navigationTitle(kind.title)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            challenge = PictureCaptchaChallenge.make()
            selectedTiles = []
            challengeVerified = false
        }
    }

    private func requestCode() {
        // Simulate delivery for this demo; no real SMS or email is sent.
        codeRequested = true
        message = "Verification code sent successfully"
    }
}


private struct CaptchaObject {
    let name: String
    let symbol: String
    var caption: String { name }
}

private struct PictureCaptchaChallenge {
    let targetName: String
    let tiles: [CaptchaObject]
    let targetIndices: Set<Int>

    static let objects = [
        CaptchaObject(name: "Traffic light", symbol: "🚦"),
        CaptchaObject(name: "School bus", symbol: "🚌"),
        CaptchaObject(name: "Bicycle", symbol: "🚲"),
        CaptchaObject(name: "Car", symbol: "🚗"),
        CaptchaObject(name: "Fire truck", symbol: "🚒"),
        CaptchaObject(name: "Crosswalk", symbol: "🚸"),
        CaptchaObject(name: "Motorcycle", symbol: "🏍️"),
        CaptchaObject(name: "Train", symbol: "🚆")
    ]

    static func make(excluding previousTarget: String? = nil) -> PictureCaptchaChallenge {
        let candidates = objects.filter { $0.name != previousTarget }
        let target = candidates.randomElement() ?? objects[0]
        let targetCount = Int.random(in: 2...3)
        let distractors = objects.filter { $0.name != target.name }.shuffled().prefix(9 - targetCount)
        let grid = (Array(repeating: target, count: targetCount) + Array(distractors)).shuffled()
        let indices = Set(grid.indices.filter { grid[$0].name == target.name })
        return PictureCaptchaChallenge(targetName: target.name, tiles: grid, targetIndices: indices)
    }
}
