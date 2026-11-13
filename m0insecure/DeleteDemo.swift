import SwiftUI

struct DeleteDemo: View {
    @State private var status = ""
    @State private var showDeleteConfirmation = false

    var body: some View {
        VStack(spacing: 20) {


            Button("Delete Account") {
                showDeleteConfirmation = true
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)

            Text(status)
                .foregroundColor(.red)

            Spacer()
        }
        .padding()
        .navigationTitle("Delete Demo")
        .alert("Delete Account?", isPresented: $showDeleteConfirmation) {
            Button("Cancel", role: .cancel) {
                // Account not deleted
            }

            Button("Delete", role: .destructive) {
                status = "Account deleted ❌"
            }
        } message: {
            Text("Are you sure you want to permanently delete? This action cannot be undone.")
        }
    }
}

#Preview {
    DeleteDemo()
}
