import CryptoKit
import Foundation

enum PinVerifierUtil {
    static func parentKey(for pin: String, in policy: ClientPolicy) -> String? {
        policy.pinVerifiers.first { verify(pin: pin, encoded: $0.verifier) }?.parentKeyId
    }

    private static func verify(pin: String, encoded: String) -> Bool {
        let parts = encoded.split(separator: "$", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4, parts[0] == "pbkdf2-sha256",
              let rounds = Int(parts[1]),
              let salt = Data(base64URLEncoded: parts[2]),
              let expected = Data(base64URLEncoded: parts[3]) else { return false }
        let actual = pbkdf2(password: Data(pin.utf8), salt: salt, rounds: rounds, length: expected.count)
        return actual == expected
    }

    private static func pbkdf2(password: Data, salt: Data, rounds: Int, length: Int) -> Data {
        let key = SymmetricKey(data: password)
        var output = Data()
        var blockIndex: UInt32 = 1
        while output.count < length {
            var bigEndian = blockIndex.bigEndian
            var blockSalt = salt
            blockSalt.append(Data(bytes: &bigEndian, count: 4))
            var value = Data(HMAC<SHA256>.authenticationCode(for: blockSalt, using: key))
            var aggregate = value
            if rounds > 1 {
                for _ in 2...rounds {
                    value = Data(HMAC<SHA256>.authenticationCode(for: value, using: key))
                    for index in aggregate.indices { aggregate[index] ^= value[index] }
                }
            }
            output.append(aggregate)
            blockIndex += 1
        }
        return output.prefix(length)
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}

