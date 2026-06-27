import XCTest
import Foundation
import ClipySiCore

/// Runs the M10 crypto/KDF/record KAT vectors through the Swift binding, proving the Rust static
/// library embedded in the XCFramework reproduces the *same* bytes as the Rust unit tests — the
/// point of the shared core. The crypto vectors were produced by CryptoKit, so this re-proves the
/// interop kill-switch through the actually-shipped binding (design §13.3 KEEP-3).
final class M10FormatKATTests: XCTestCase {
    // MARK: - hex / file helpers

    private func unhex(_ s: String) -> Data {
        var data = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let next = s.index(i, offsetBy: 2)
            data.append(UInt8(s[i..<next], radix: 16)!)
            i = next
        }
        return data
    }

    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    /// crate root = up 6 components from this file, then `kat/<name>`.
    private func katData(_ name: String) throws -> Data {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        url.appendPathComponent("kat/\(name)")
        return try Data(contentsOf: url)
    }

    // MARK: - crypto.json (CryptoKit interop kill-switch)

    private struct CryptoKAT: Decodable {
        struct AeadCase: Decodable { let note: String; let plaintextHex: String; let combinedHex: String
            enum CodingKeys: String, CodingKey { case note; case plaintextHex = "plaintext_hex"; case combinedHex = "combined_hex" } }
        struct Aead: Decodable { let nonceHex: String; let cases: [AeadCase]
            enum CodingKeys: String, CodingKey { case nonceHex = "nonce_hex"; case cases } }
        struct HmacCase: Decodable { let note: String; let inputHex: String; let hmacHex: String
            enum CodingKeys: String, CodingKey { case note; case inputHex = "input_hex"; case hmacHex = "hmac_hex" } }
        struct Hmac: Decodable { let cases: [HmacCase] }
        let keyHex: String; let aeadCombined: Aead; let hmacSha256: Hmac
        enum CodingKeys: String, CodingKey { case keyHex = "key_hex"; case aeadCombined = "aead_combined"; case hmacSha256 = "hmac_sha256" }
    }

    func testCryptoInteropThroughBinding() throws {
        let kat = try JSONDecoder().decode(CryptoKAT.self, from: katData("crypto.json"))
        let key = unhex(kat.keyHex)
        let nonce = unhex(kat.aeadCombined.nonceHex)
        for c in kat.aeadCombined.cases {
            let combined = unhex(c.combinedHex)
            // KILL-SWITCH: CryptoKit-produced .combined opens in the shipped Rust binding.
            XCTAssertEqual(try localOpen(key: key, combined: combined), unhex(c.plaintextHex), "open \(c.note)")
            // And seal reproduces CryptoKit's exact bytes.
            XCTAssertEqual(hex(try localSeal(key: key, nonce: nonce, plaintext: unhex(c.plaintextHex))), c.combinedHex, "seal \(c.note)")
        }
        for c in kat.hmacSha256.cases {
            XCTAssertEqual(contentHash(key: key, payload: unhex(c.inputHex)), c.hmacHex, "hmac \(c.note)")
        }
    }

    // MARK: - kdf.json

    private struct KdfKAT: Decodable {
        struct Case: Decodable { let note: String; let passphraseHex: String; let iterations: UInt32; let keyHex: String
            enum CodingKeys: String, CodingKey { case note; case passphraseHex = "passphrase_hex"; case iterations; case keyHex = "key_hex" } }
        let saltHex: String; let cases: [Case]
        enum CodingKeys: String, CodingKey { case saltHex = "salt_hex"; case cases }
    }

    func testKdfThroughBinding() throws {
        let kat = try JSONDecoder().decode(KdfKAT.self, from: katData("kdf.json"))
        let salt = unhex(kat.saltHex)
        for c in kat.cases {
            let passphrase = String(data: unhex(c.passphraseHex), encoding: .utf8)!
            let descriptor = KdfDescriptorFfi(kind: .pbkdf2HmacSha256(iterations: c.iterations), salt: salt, kdfVersion: 1)
            XCTAssertEqual(hex(try deriveVaultKey(passphrase: passphrase, kdf: descriptor)), c.keyHex, "kdf \(c.note)")
        }
    }

    // MARK: - record.json (format freeze)

    private struct RecordKAT: Decodable {
        let keyHex: String; let nonceHex: String; let canonicalPayloadHex: String
        let bodyHex: String; let envelopeHex: String; let tombstoneHex: String
        let syncHash: String; let vaultJson: String
        enum CodingKeys: String, CodingKey {
            case keyHex = "key_hex"; case nonceHex = "nonce_hex"; case canonicalPayloadHex = "canonical_payload_hex"
            case bodyHex = "body_hex"; case envelopeHex = "envelope_hex"; case tombstoneHex = "tombstone_hex"
            case syncHash = "sync_hash"; case vaultJson = "vault_json"
        }
    }

    // Fixture matching tests/kat_record.rs.
    private func samplePlaintext() -> RecordPlaintextFfi {
        RecordPlaintextFfi(
            title: "hello clip",
            primaryType: "public.utf8-plain-text",
            sourceBundle: "com.example.app",
            isColorCode: false,
            representations: [RecordRepresentationFfi(uttype: "public.utf8-plain-text", data: Data("hello clip".utf8))]
        )
    }

    private func header(deleted: Bool) -> RecordHeaderFfi {
        let did = "11121314-1516-1718-191a-1b1c1d1e1f20"
        return RecordHeaderFfi(
            formatVersion: 1,
            recordId: "01020304-0506-0708-090a-0b0c0d0e0f10",
            originDeviceId: did,
            hlc: HlcFfi(wallMillis: 1_700_000_000_000, counter: 0, node: did),
            createdAt: 1_700_000_000,
            updatedAt: 1_700_000_000,
            deleted: deleted,
            syncHash: "deadbeef"
        )
    }

    func testRecordFormatFrozenThroughBinding() throws {
        let kat = try JSONDecoder().decode(RecordKAT.self, from: katData("record.json"))
        let key = unhex(kat.keyHex)
        let nonce = unhex(kat.nonceHex)

        let body = try sealRecord(vaultKey: key, nonce: nonce, plaintext: samplePlaintext())
        XCTAssertEqual(hex(body), kat.bodyHex, "sealed body drifted")

        // open round-trip.
        let opened = try openRecord(vaultKey: key, body: body)
        XCTAssertEqual(opened.title, "hello clip")
        XCTAssertEqual(opened.sourceBundle, "com.example.app")

        let live = RecordEnvelopeFfi(header: header(deleted: false), body: body)
        let liveBytes = try encodeEnvelope(envelope: live)
        XCTAssertEqual(hex(liveBytes), kat.envelopeHex, "envelope drifted")
        XCTAssertEqual(try decodeEnvelope(bytes: liveBytes).header.recordId, "01020304-0506-0708-090a-0b0c0d0e0f10")

        let tomb = RecordEnvelopeFfi(header: header(deleted: true), body: nil)
        XCTAssertEqual(hex(try encodeEnvelope(envelope: tomb)), kat.tombstoneHex, "tombstone drifted")

        XCTAssertEqual(try computeSyncHash(vaultKey: key, canonicalPayload: unhex(kat.canonicalPayloadHex)), kat.syncHash)
    }

    func testVaultManifestFrozenThroughBinding() throws {
        let kat = try JSONDecoder().decode(RecordKAT.self, from: katData("record.json"))
        let key = unhex(kat.keyHex)
        let nonce = unhex(kat.nonceHex)
        let descriptor = KdfDescriptorFfi(kind: .pbkdf2HmacSha256(iterations: 4096), salt: Data("0123456789abcdef".utf8), kdfVersion: 1)
        let manifestJson = try makeVaultManifest(
            vaultKey: key,
            vaultId: "21222324-2526-2728-292a-2b2c2d2e2f30",
            createdAt: 1_700_000_000,
            kdf: descriptor,
            verifierNonce: nonce
        )
        XCTAssertEqual(String(data: manifestJson, encoding: .utf8), kat.vaultJson, "vault.json drifted")
        XCTAssertTrue(try verifyPassphrase(vaultKey: key, manifestJson: manifestJson))
    }

    func testDecodeRejectsGarbage() {
        XCTAssertThrowsError(try decodeEnvelope(bytes: Data([0, 1, 2])))
    }

    func testRecordFormatVersionIsOne() {
        XCTAssertEqual(recordFormatVersion(), 1)
    }
}
