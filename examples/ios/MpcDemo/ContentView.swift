import SwiftUI

struct ContentView: View {
    @State private var output = "Run key generation and signing for one of the protocols."
    @State private var running = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Button("DKLs23 (ECDSA)") { run(dkls23) }
                    Button("FROST (Ed25519)") { run(frost) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(running)

                ScrollView {
                    Text(output)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding()
            .navigationTitle("mpc-sdk demo")
        }
    }

    private func run(_ demo: @escaping @Sendable () throws -> String) {
        running = true
        output = "Running…"
        Task.detached {
            let text: String
            do {
                text = try demo()
            } catch {
                text = "Error: \(error)"
            }
            await MainActor.run {
                output = text
                running = false
            }
        }
    }
}

private func dkls23() throws -> String {
    let result = try Dkls23Demo.run()
    return """
    DKLs23 2-of-2 (secp256k1)
    Public key: \(result.publicKey)

    Message hash (SHA-256): \(result.messageHash)
    Signature (r||s): \(result.signature)
    """
}

private func frost() throws -> String {
    let result = try FrostDemo.run()
    return """
    FROST 2-of-2 (Ed25519)
    Public key: \(result.publicKey)

    Message: \(result.message)
    Signature: \(result.signature)
    Verified: \(result.verified)
    """
}
