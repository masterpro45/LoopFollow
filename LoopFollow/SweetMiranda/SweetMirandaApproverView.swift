// LoopFollow
// SweetMirandaApproverView.swift

import CryptoKit
import LocalAuthentication
import Security
import SwiftUI

// Sweet Miranda (wilhq.com) ⇄ Trio: this phone as a second approver of settings proposals.
//
// A Secure Enclave key that only this phone's CURRENT Face ID can use (no passcode fallback)
// signs one exact proposal; Trio on Miranda's phone verifies the signature against the public
// key it enrolled (enrolment is approved on Miranda's phone) and applies the changes.
//
// Signing contract — must match Trio's SMApprovers (Services/SweetMiranda/SweetMirandaModels.swift):
//   payload   = "SMAPPROVE1|<smId>|<sha256 hex of the sorted-keys JSON of smChanges>|<smExpires as sent>"
//   signature = ECDSA P-256 over SHA-256(payload UTF-8), DER (.ecdsaSignatureMessageX962SHA256)
//   keyId     = first 16 hex characters of SHA-256(x9.63 public key bytes)
// Nothing here can dose.

enum SweetMirandaApprover {
    static let eventType = "Sweet Miranda Settings"
    static let payloadVersion = "SMAPPROVE1"
    private static let keyTag = Data("com.sweetmiranda.approver.key".utf8)

    enum Failure: LocalizedError {
        case message(String)
        var errorDescription: String? {
            switch self { case let .message(m): return m }
        }
    }

    // MARK: Key

    static func existingKey(context: LAContext? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    /// Face ID only: `.biometryCurrentSet` has no passcode fallback, and enrolling a new face
    /// on this phone makes the key unusable (Miranda's phone must then enrol a new one).
    static func createKey() throws -> SecKey {
        deleteKey()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error
        ) else {
            throw Failure.message("Face ID is not set up on this phone.")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Failure.message("Could not create the Face ID key: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")")
        }
        return key
    }

    static func deleteKey() {
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
        ] as CFDictionary)
    }

    static func publicKeyData(_ key: SecKey) -> Data? {
        guard let pub = SecKeyCopyPublicKey(key) else { return nil }
        return SecKeyCopyExternalRepresentation(pub, nil) as Data?
    }

    static func keyId(publicKey: Data) -> String {
        String(hex(SHA256.hash(data: publicKey)).prefix(16))
    }

    /// Blocks while Face ID runs — call off the main thread.
    static func sign(_ payload: String, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "" // Face ID only: no "Enter Password" button
        guard let key = existingKey(context: context) else {
            throw Failure.message("No Face ID key on this phone. Create one first.")
        }
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, Data(payload.utf8) as CFData, &error) else {
            let e = error?.takeRetainedValue()
            if let e, [LAError.userCancel.rawValue, Int(errSecUserCanceled)].contains(CFErrorGetCode(e)) {
                throw Failure.message("Face ID was cancelled. Nothing was approved.")
            }
            throw Failure.message("Face ID did not approve: \(e?.localizedDescription ?? "unknown error")")
        }
        return sig as Data
    }

    // MARK: Contract

    static func changesHash(_ changes: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: changes, options: [.sortedKeys]) else { return nil }
        return hex(SHA256.hash(data: data))
    }

    static func payload(id: String, changes: [String: Any], expiresRaw: String) -> String? {
        guard let hash = changesHash(changes) else { return nil }
        return [payloadVersion, id, hash, expiresRaw].joined(separator: "|")
    }

    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Nightscout

    static func request(path: String, query: [URLQueryItem], token: String, method: String = "GET", body: Any? = nil) throws -> URLRequest {
        guard var components = URLComponents(string: Storage.shared.url.value), !Storage.shared.url.value.isEmpty else {
            throw Failure.message("Set up Nightscout in Settings first.")
        }
        components.path = path
        components.queryItems = query + [URLQueryItem(name: "token", value: token)]
        guard let url = components.url else { throw Failure.message("The Nightscout address is not valid.") }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 20
        req.cachePolicy = .reloadIgnoringLocalCacheData
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        return req
    }

    static func fetch(kind: String, extra: [URLQueryItem] = [], token: String) async throws -> [[String: Any]] {
        let req = try request(path: "/api/v1/treatments.json", query: [
            URLQueryItem(name: "find[eventType]", value: eventType),
            URLQueryItem(name: "find[smKind]", value: kind),
            URLQueryItem(name: "count", value: "20"),
        ] + extra, token: token)
        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse, (200 ... 299).contains(http.statusCode) else {
            throw Failure.message("Nightscout refused the approver token (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
        return try (JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
    }

    static func post(_ doc: [String: Any], token: String) async throws {
        let req = try request(path: "/api/v1/treatments", query: [], token: token, method: "POST", body: [doc])
        let (_, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse, (200 ... 299).contains(http.statusCode) else {
            throw Failure.message("Nightscout did not accept it (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
    }

    static func now() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date())
    }
}

/// One pending proposal, exactly as Nightscout holds it (Trio reads the same document).
struct SMPendingProposal: Identifiable {
    let id: String
    let from: String
    let note: String
    let createdAt: String
    let expiresRaw: String
    let changes: [String: Any]

    init?(_ d: [String: Any]) {
        guard (d["smStatus"] as? String) == "pending",
              let id = d["smId"] as? String, !id.isEmpty,
              let changes = d["smChanges"] as? [String: Any], !changes.isEmpty
        else { return nil }
        self.id = id
        from = (d["smFrom"] as? String) ?? "Sweet Miranda"
        note = (d["smNote"] as? String) ?? ""
        createdAt = (d["created_at"] as? String) ?? ""
        expiresRaw = (d["smExpires"] as? String) ?? ""
        self.changes = changes
    }

    /// Adding/removing approvers is only ever approved on Miranda's phone.
    var needsHerPhone: Bool { changes.keys.contains { $0.hasPrefix("approver.") } }

    var lines: [(String, String)] {
        changes.keys.sorted().map { key in (Self.label(key), Self.describe(changes[key]!)) }
    }

    private static func label(_ key: String) -> String {
        switch key {
        case "basal": return "Basal schedule"
        case "isf": return "Correction factor (ISF)"
        case "cr": return "Carb ratio"
        case "targets": return "Glucose target"
        case "approver.add": return "Add Face ID approver"
        case "approver.remove": return "Remove Face ID approver"
        default:
            for prefix in ["pref.", "settings.", "pump."] where key.hasPrefix(prefix) {
                return String(key.dropFirst(prefix.count))
            }
            return key
        }
    }

    private static func describe(_ v: Any) -> String {
        if let rows = v as? [[String: Any]] {
            return rows.map { row -> String in
                let start = (row["start"] as? String).map { String($0.prefix(5)) } ?? "?"
                let value = ["rate", "sensitivity", "ratio", "low"].compactMap { row[$0] }.first.map { "\($0)" } ?? "?"
                return "\(start) \(value)"
            }.joined(separator: " · ")
        }
        if let d = v as? [String: Any] { return (d["name"] as? String) ?? "\(d)" }
        if let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue ? "On" : "Off" }
        return "\(v)"
    }
}

@MainActor
final class SweetMirandaApproverModel: ObservableObject {
    @Published var token: String = UserDefaults.standard.string(forKey: "smApproverToken") ?? "" {
        didSet { UserDefaults.standard.set(token, forKey: "smApproverToken") }
    }

    @Published var name: String = UserDefaults.standard.string(forKey: "smApproverName") ?? "" {
        didSet { UserDefaults.standard.set(name, forKey: "smApproverName") }
    }

    @Published var keyId: String?
    @Published var proposals: [SMPendingProposal] = []
    @Published var approvedIds: Set<String> = []
    @Published var status: String = ""
    @Published var working = false

    init() { refreshKey() }

    func refreshKey() {
        keyId = SweetMirandaApprover.existingKey()
            .flatMap(SweetMirandaApprover.publicKeyData)
            .map(SweetMirandaApprover.keyId(publicKey:))
    }

    func createKeyAndEnroll() async {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { status = "Enter a name for this phone first."
            return
        }
        guard !token.isEmpty else { status = "Enter the approver token first."
            return
        }
        working = true
        defer { working = false }
        do {
            let key = try SweetMirandaApprover.createKey()
            guard let pub = SweetMirandaApprover.publicKeyData(key) else { throw SweetMirandaApprover.Failure.message("Could not read the new key.") }
            let id = SweetMirandaApprover.keyId(publicKey: pub)
            // Prove Face ID works with this key before telling anyone about it.
            _ = try await Task.detached {
                try SweetMirandaApprover.sign("SMENROLL|\(id)", reason: "Confirm Face ID for Sweet Miranda approvals")
            }.value
            try await SweetMirandaApprover.post([
                "eventType": SweetMirandaApprover.eventType,
                "enteredBy": "LoopFollow",
                "created_at": SweetMirandaApprover.now(),
                "smKind": "enroll",
                "smKeyId": id,
                "smApprover": trimmedName,
                "smPublicKey": pub.base64EncodedString(),
                "notes": "Sweet Miranda approver enrolment",
            ], token: token)
            refreshKey()
            status = "Sent. In Sweet Miranda ▸ Trio, press “Send to Miranda’s phone”, then approve it on her phone once."
        } catch {
            SweetMirandaApprover.deleteKey()
            refreshKey()
            status = error.localizedDescription
        }
    }

    func deleteKey() {
        SweetMirandaApprover.deleteKey()
        refreshKey()
        status = "Key deleted. Also remove this phone on Miranda's phone or in Sweet Miranda."
    }

    func load() async {
        guard !token.isEmpty, !Storage.shared.url.value.isEmpty else { return }
        do {
            let docs = try await SweetMirandaApprover.fetch(kind: "proposal", extra: [
                URLQueryItem(name: "find[smStatus]", value: "pending"),
            ], token: token)
            proposals = docs.compactMap(SMPendingProposal.init).sorted { $0.createdAt > $1.createdAt }
            if let keyId {
                let mine = try await SweetMirandaApprover.fetch(kind: "approval", extra: [
                    URLQueryItem(name: "find[smKeyId]", value: keyId),
                ], token: token)
                approvedIds = Set(mine.compactMap { $0["smId"] as? String })
            }
            if status.hasPrefix("Nightscout") { status = "" }
        } catch {
            status = error.localizedDescription
        }
    }

    func approve(_ p: SMPendingProposal) async {
        guard let keyId else { status = "Create the Face ID key first."
            return
        }
        guard let payload = SweetMirandaApprover.payload(id: p.id, changes: p.changes, expiresRaw: p.expiresRaw) else {
            status = "Could not read this proposal."
            return
        }
        working = true
        defer { working = false }
        let reason = "Approve \(p.changes.count) setting change(s) on Miranda's Trio"
        do {
            let sig = try await Task.detached {
                try SweetMirandaApprover.sign(payload, reason: reason)
            }.value
            try await SweetMirandaApprover.post([
                "eventType": SweetMirandaApprover.eventType,
                "enteredBy": "LoopFollow",
                "created_at": SweetMirandaApprover.now(),
                "smKind": "approval",
                "smId": p.id,
                "smKeyId": keyId,
                "smApprover": name,
                "smPayload": payload,
                "smSig": sig.base64EncodedString(),
                "notes": "Sweet Miranda approval (Face ID)",
            ], token: token)
            approvedIds.insert(p.id)
            status = "Approved. Miranda's phone applies it at its next loop (usually within 5 minutes) and tells her."
        } catch {
            status = error.localizedDescription
        }
    }
}

struct SweetMirandaApproverView: View {
    @StateObject private var model = SweetMirandaApproverModel()
    private let timer = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    var body: some View {
        List {
            Section {
                TextField("This phone's name (e.g. Wilson's iPhone)", text: $model.name)
                    .textInputAutocapitalization(.words)
                SecureField("Approver token", text: $model.token)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if let keyId = model.keyId {
                    LabeledContent("Face ID key", value: String(keyId.prefix(8)))
                    Button("Delete this phone's key", role: .destructive) { model.deleteKey() }
                } else {
                    Button("Create Face ID key and send to Sweet Miranda") {
                        Task { await model.createKeyAndEnroll() }
                    }
                    .disabled(model.working)
                }
            } header: {
                Text("This phone")
            } footer: {
                Text("The key lives in this phone's Secure Enclave and works only with this phone's current Face ID — no passcode. Miranda's phone must approve this phone once before its approvals count.")
            }

            Section {
                if model.proposals.isEmpty {
                    Text("Nothing waiting.").foregroundStyle(.secondary)
                }
                ForEach(model.proposals) { p in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("From \(p.from)").font(.subheadline).foregroundStyle(.secondary)
                        if !p.note.isEmpty { Text(p.note) }
                        ForEach(p.lines, id: \.0) { label, value in
                            HStack(alignment: .top) {
                                Text(label).font(.callout)
                                Spacer()
                                Text(value).font(.callout.weight(.semibold)).multilineTextAlignment(.trailing)
                            }
                        }
                        if p.needsHerPhone {
                            Text("Approver changes can only be approved on Miranda's phone.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else if model.approvedIds.contains(p.id) {
                            Label("Approved — waiting for Miranda's phone", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                        } else {
                            Button {
                                Task { await model.approve(p) }
                            } label: {
                                Label("Approve with Face ID", systemImage: "faceid")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.working || model.keyId == nil)
                        }
                    }
                    .padding(.vertical, 4)
                }
            } header: {
                Text("Waiting for approval")
            } footer: {
                Text("Proposals are written in Sweet Miranda. Approving here sends a Face ID signature; Trio on Miranda's phone checks it, applies the change and notifies her. Nothing here doses insulin.")
            }

            if !model.status.isEmpty {
                Section { Text(model.status).font(.footnote) }
            }
        }
        .navigationTitle("Sweet Miranda")
        .refreshable { await model.load() }
        .task { await model.load() }
        .onReceive(timer) { _ in Task { await model.load() } }
    }
}
