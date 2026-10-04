import Foundation
import UIKit

actor ApiClient {
    static let shared = ApiClient()

    private var decoder = JSONDecoder()
    private var encoder = JSONEncoder()

    func enroll(server: String, code: String, name: String) async throws -> EnrollmentResponse {
        let root = server.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let payload: [String: Any] = [
            "enrollmentCode": code.uppercased(),
            "name": name,
            "platform": "ios",
            "osVersion": await UIDevice.current.systemVersion,
            "clientVersion": "0.2.0",
            "capabilities": ["family-controls", "managed-settings", "device-activity", "local-pin"],
        ]
        let data = try await request(url: URL(string: "\(root)/api/client/v1/enroll")!, method: "POST", json: payload, authenticated: false)
        return try decoder.decode(EnrollmentResponse.self, from: data)
    }

    func policy(server: String, credential: String) async throws -> ClientPolicy {
        let data = try await request(url: URL(string: "\(server)/api/client/v1/policy")!, credential: credential)
        return try decoder.decode(ClientPolicy.self, from: data)
    }

    func localOperation(server: String, credential: String, operation: LocalOperation) async throws -> LocalOperationResponse {
        let body = try JSONSerialization.jsonObject(with: encoder.encode(operation)) as! [String: Any]
        let data = try await request(url: URL(string: "\(server)/api/client/v1/local-operations")!, method: "POST", json: body, credential: credential)
        return try decoder.decode(LocalOperationResponse.self, from: data)
    }

    func targets(server: String, credential: String, serviceKeys: [String]) async throws {
        let targets = serviceKeys.map { key in
            [
                "key": "ios-selection:\(key)",
                "displayName": key,
                "kind": "local-selection",
                "categoryGuess": "unknown",
                "source": "ios-family-activity-picker",
                "currentlyRunning": false,
                "mapping": ["localSelectionKey": key],
            ] as [String: Any]
        }
        _ = try await request(
            url: URL(string: "\(server)/api/client/v1/targets")!,
            method: "POST",
            json: ["targets": targets],
            credential: credential
        )
    }

    private func request(
        url: URL,
        method: String = "GET",
        json: [String: Any]? = nil,
        authenticated: Bool = true,
        credential: String? = nil
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authenticated, let credential { request.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization") }
        if let json {
            request.httpBody = try JSONSerialization.data(withJSONObject: json)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return data
    }
}
