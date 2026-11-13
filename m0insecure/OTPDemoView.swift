import SwiftUI

struct OTPDemoView: View {
    @State private var code = ""
    @State private var status = ""
    @State private var isError = false

    var body: some View {
        Form {
            Section(header: Text("OTP Entry")) {
                TextField("Enter 6-digit code", text: $code)
                    .keyboardType(.numberPad)
                    .onChange(of: code) { _, newValue in
                        // Sanitize OTP input to digits only, max 6 characters
                        code = InputSanitizer.shared.sanitizeOTP(newValue)
                    }
            }

            Section {
                Button("Verify") {
                    verify()
                }
                .disabled(code.count < 6)
            }

            if !status.isEmpty {
                Section {
                    HStack(spacing: 10) {
                        Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundColor(isError ? .red : .green)
                        Text(status)
                            .font(.subheadline)
                            .foregroundColor(isError ? .red : .green)
                    }
                    .padding(.vertical, 4)
                    .listRowBackground(isError ? Color.red.opacity(0.1) : Color.green.opacity(0.1))
                }
            }
        }
        .navigationTitle("OTP Demo")
    }

    func verify() {
        // Enforce input sanitization
        let sanitized = InputSanitizer.shared.sanitizeOTP(code)

        let realCode = "123456"  // hardcoded for demo
        if sanitized == realCode {
            isError = false
            status = "Verification success ✅"
        } else {
            isError = true
            status = "Verification failed ❌"
        }
    }
}
