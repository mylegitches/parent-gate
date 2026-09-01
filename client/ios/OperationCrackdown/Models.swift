import Foundation

struct ClientPolicy: Codable {
    var revision: Int
    var deviceId: String
    var profile: String
    var effectiveUntil: String?
    var services: [ServicePolicy]
    var customTargets: [CustomTarget]
    var pinVerifiers: [PinVerifier]
}

struct ServicePolicy: Codable, Identifiable {
    var id: String
    var displayName: String
    var category: String
    var blocked: Bool
    var warning: String?
    var ios: IOSMapping?
}

struct IOSMapping: Codable { var localSelectionKey: String }
struct CustomTarget: Codable { var key: String; var displayName: String; var blocked: Bool }
struct PinVerifier: Codable { var parentKeyId: String; var displayName: String; var verifier: String }

struct EnrollmentResponse: Codable {
    var deviceId: String
    var credential: String
    var serverUrl: String
}

struct LocalOperation: Codable {
    var operationId: String
    var deviceId: String
    var baseRevision: Int
    var source = "local-parent"
    var parentKeyId: String
    var targetType: String
    var targetId: String
    var action: String
    var effectiveUntil: String?
    var createdAt: String
}

struct LocalOperationResponse: Codable { var accepted: Bool; var policy: ClientPolicy }

