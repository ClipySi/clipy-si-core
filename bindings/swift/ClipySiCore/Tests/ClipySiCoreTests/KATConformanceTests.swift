import XCTest
import Foundation
import ClipySiCore

/// Runs the language-independent KAT vectors (`kat/redaction.json`) through the Swift
/// binding so the Rust static library embedded in the XCFramework is proven to produce the
/// *same* verdicts as the Rust unit tests — the whole point of the shared core.
final class KATConformanceTests: XCTestCase {
    private struct KATCase: Decodable {
        let text: String
        let isSecret: Bool
        let kind: String?
        let maskFull: String?
        enum CodingKeys: String, CodingKey {
            case text
            case isSecret = "is_secret"
            case kind
            case maskFull = "mask_full"
        }
    }
    private struct KAT: Decodable {
        let rulesVersion: UInt32
        let cases: [KATCase]
        enum CodingKeys: String, CodingKey {
            case rulesVersion = "rules_version"
            case cases
        }
    }

    private func loadKAT() throws -> KAT {
        // #filePath -> .../clipy-si-core/bindings/swift/ClipySiCore/Tests/ClipySiCoreTests/<this>.swift
        // Walk up 6 components to the crate root, then into kat/.
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        url.appendPathComponent("kat/redaction.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(KAT.self, from: data)
    }

    func testRulesVersionMatches() throws {
        let kat = try loadKAT()
        XCTAssertEqual(rulesVersion(), kat.rulesVersion)
    }

    func testKATConformance() throws {
        let kat = try loadKAT()
        let config = defaultConfig()
        XCTAssertFalse(kat.cases.isEmpty)
        for c in kat.cases {
            XCTAssertEqual(isSecret(text: c.text, config: config), c.isSecret,
                           "is_secret mismatch for: \(c.text.prefix(24))…")
            if let expectedMask = c.maskFull {
                XCTAssertEqual(mask(text: c.text, config: config), expectedMask,
                               "mask mismatch for: \(c.text.prefix(24))…")
            }
            if let expectedKind = c.kind {
                let matches = detectSecrets(text: c.text, config: config)
                XCTAssertEqual(matches.first?.kind, expectedKind,
                               "kind mismatch for: \(c.text.prefix(24))…")
            }
        }
    }

    /// The FFI contract returns `start`/`end` as **Unicode scalar** offsets. Verify a token
    /// preceded by a non-BMP emoji (1 scalar, 2 UTF-16 units, 4 UTF-8 bytes) reports start=1.
    func testScalarOffsetContract() {
        let text = "\u{1F511}ghp_0000000000000000000000000000000000AB"
        let matches = detectSecrets(text: text, config: defaultConfig())
        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(matches.first?.start, 1, "start must be a Unicode scalar offset")
        // Slice via the scalar view using the reported offsets.
        if let m = matches.first {
            let scalars = Array(text.unicodeScalars)
            let token = String(String.UnicodeScalarView(scalars[Int(m.start)..<Int(m.end)]))
            XCTAssertTrue(token.hasPrefix("ghp_"))
        }
    }

    func testMaskingDisabledReturnsOriginal() {
        var config = defaultConfig()
        config.enabled = false
        let secret = "ghp_0000000000000000000000000000000000AB"
        XCTAssertEqual(mask(text: secret, config: config), secret)
    }
}
