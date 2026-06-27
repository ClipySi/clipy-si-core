import XCTest
import Foundation
import ClipySiCore

/// Runs the M11 sync merge-rule KAT (`kat/sync.json`) through the Swift binding so the shipped
/// XCFramework provably makes the same decisions as the Rust unit tests — two devices that merge
/// differently never converge, so this is the protocol contract. Also covers manifestKdf (M10
/// hand-off: extract the KDF from an existing vault.json).
final class M11SyncKATTests: XCTestCase {
    // MARK: - KAT decoding

    private struct PartialHlc: Decodable {
        let wallMillis: Int64
        let counter: UInt32
        let node: String?
        enum CodingKeys: String, CodingKey {
            case wallMillis = "wall_millis"
            case counter
            case node
        }
    }
    private struct NextCase: Decodable {
        let note: String, nowMillis: Int64
        let prev: PartialHlc?, expect: PartialHlc
        enum CodingKeys: String, CodingKey {
            case note, prev, expect
            case nowMillis = "now_millis"
        }
    }
    private struct ReceiveCase: Decodable {
        let note: String, nowMillis: Int64
        let local: PartialHlc, remote: PartialHlc, expect: PartialHlc
        enum CodingKeys: String, CodingKey {
            case note, local, remote, expect
            case nowMillis = "now_millis"
        }
    }
    private struct CompareCase: Decodable { let note: String, a: PartialHlc, b: PartialHlc, expect: String }
    private struct MergeLocal: Decodable {
        let applied: Bool, appliedDeleted: Bool, liveDup: Bool
        let tombDupHlc: PartialHlc?
        enum CodingKeys: String, CodingKey {
            case applied
            case appliedDeleted = "applied_deleted"
            case liveDup = "live_dup"
            case tombDupHlc = "tomb_dup_hlc"
        }
    }
    private struct MergeCase: Decodable {
        let note: String, local: MergeLocal, remoteDeleted: Bool, remoteHlc: PartialHlc, expect: String
        enum CodingKeys: String, CodingKey {
            case note, local, expect
            case remoteDeleted = "remote_deleted"
            case remoteHlc = "remote_hlc"
        }
    }
    private struct GcCase: Decodable {
        let note: String, tombHlcWallMillis: Int64, devicesLastSeenSecs: [Int64], nowSecs: Int64, expect: Bool
        enum CodingKeys: String, CodingKey {
            case note, expect
            case tombHlcWallMillis = "tomb_hlc_wall_millis"
            case devicesLastSeenSecs = "devices_last_seen_secs"
            case nowSecs = "now_secs"
        }
    }
    private struct RejoinCase: Decodable {
        let note: String, selfLastSeenSecs: Int64, nowSecs: Int64, expect: String
        enum CodingKeys: String, CodingKey {
            case note, expect
            case selfLastSeenSecs = "self_last_seen_secs"
            case nowSecs = "now_secs"
        }
    }
    private struct Kat: Decodable {
        let nodeA: String, nodeB: String
        let hlcNext: [NextCase], hlcReceive: [ReceiveCase], hlcCompare: [CompareCase]
        let merge: [MergeCase], gc: [GcCase], rejoin: [RejoinCase]
        enum CodingKeys: String, CodingKey {
            case nodeA = "node_a"
            case nodeB = "node_b"
            case hlcNext = "hlc_next"
            case hlcReceive = "hlc_receive"
            case hlcCompare = "hlc_compare"
            case merge, gc, rejoin
        }
    }

    private func loadKAT() throws -> Kat {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        url.appendPathComponent("kat/sync.json")
        return try JSONDecoder().decode(Kat.self, from: Data(contentsOf: url))
    }

    private func hlc(_ p: PartialHlc, _ kat: Kat) -> HlcFfi {
        let node: String
        switch p.node {
        case "b": node = kat.nodeB
        default: node = kat.nodeA
        }
        return HlcFfi(wallMillis: p.wallMillis, counter: p.counter, node: node)
    }

    // MARK: - Vectors through the binding

    func testHlcNextVectors() throws {
        let kat = try loadKAT()
        for c in kat.hlcNext {
            let got = try hlcNext(prev: c.prev.map { hlc($0, kat) }, nowMillis: c.nowMillis, node: kat.nodeA)
            XCTAssertEqual(got.wallMillis, c.expect.wallMillis, c.note)
            XCTAssertEqual(got.counter, c.expect.counter, c.note)
            XCTAssertEqual(got.node, kat.nodeA, c.note)
        }
    }

    func testHlcReceiveVectors() throws {
        let kat = try loadKAT()
        for c in kat.hlcReceive {
            let got = try hlcReceive(local: hlc(c.local, kat), remote: hlc(c.remote, kat),
                                     nowMillis: c.nowMillis, node: kat.nodeA)
            XCTAssertEqual(got.wallMillis, c.expect.wallMillis, c.note)
            XCTAssertEqual(got.counter, c.expect.counter, c.note)
        }
    }

    func testHlcCompareVectors() throws {
        let kat = try loadKAT()
        for c in kat.hlcCompare {
            let want: Int8 = c.expect == "less" ? -1 : (c.expect == "greater" ? 1 : 0)
            XCTAssertEqual(try hlcCompare(a: hlc(c.a, kat), b: hlc(c.b, kat)), want, c.note)
        }
    }

    func testMergeCaseTable() throws {
        let kat = try loadKAT()
        for c in kat.merge {
            let local = LocalStateFfi(
                applied: c.local.applied,
                appliedDeleted: c.local.appliedDeleted,
                liveDuplicateSyncHash: c.local.liveDup,
                tombstonedDuplicateHlc: c.local.tombDupHlc.map { hlc($0, kat) }
            )
            let want: MergeActionFfi
            switch c.expect {
            case "apply_remote": want = .applyRemote
            case "apply_tombstone": want = .applyTombstone
            case "record_tombstone_only": want = .recordTombstoneOnly
            case "skip": want = .skip
            case "skip_duplicate_content": want = .skipDuplicateContent
            default: XCTFail("bad expect \(c.expect)"); return
            }
            let got = try mergeDecide(local: local, remoteDeleted: c.remoteDeleted, remoteHlc: hlc(c.remoteHlc, kat))
            XCTAssertEqual(got, want, c.note)
        }
    }

    func testGcVectors() throws {
        let kat = try loadKAT()
        for c in kat.gc {
            let tomb = HlcFfi(wallMillis: c.tombHlcWallMillis, counter: 0, node: kat.nodeA)
            XCTAssertEqual(
                try gcEligible(tombstoneHlc: tomb, devicesLastSeenSecs: c.devicesLastSeenSecs, nowSecs: c.nowSecs),
                c.expect, c.note
            )
        }
    }

    func testRejoinVectors() throws {
        let kat = try loadKAT()
        for c in kat.rejoin {
            let want: RejoinActionFfi = c.expect == "repush" ? .repush : .deleteLocally
            XCTAssertEqual(rejoinAction(selfLastSeenSecs: c.selfLastSeenSecs, nowSecs: c.nowSecs), want, c.note)
        }
    }

    // MARK: - manifestKdf (M10 hand-off)

    func testManifestKdfRoundTrip() throws {
        // Build a real vault.json, then extract its KDF and re-derive the same key.
        let salt = Data("0123456789abcdef".utf8)
        let descriptor = KdfDescriptorFfi(kind: .pbkdf2HmacSha256(iterations: 4096), salt: salt, kdfVersion: 1)
        let key = try deriveVaultKey(passphrase: "correct horse", kdf: descriptor)
        let nonce = Data(repeating: 0, count: 12)
        let manifest = try makeVaultManifest(vaultKey: key, vaultId: "21222324-2526-2728-292a-2b2c2d2e2f30",
                                             createdAt: 0, kdf: descriptor, verifierNonce: nonce)

        let extracted = try manifestKdf(manifestJson: manifest)
        XCTAssertEqual(extracted.salt, salt)
        XCTAssertEqual(extracted.kdfVersion, 1)
        guard case .pbkdf2HmacSha256(let iterations) = extracted.kind else {
            return XCTFail("unexpected kdf kind")
        }
        XCTAssertEqual(iterations, 4096)

        // The extracted descriptor derives a key that opens the verifier.
        let rederived = try deriveVaultKey(passphrase: "correct horse", kdf: extracted)
        XCTAssertEqual(rederived, key)
        XCTAssertTrue(try verifyPassphrase(vaultKey: rederived, manifestJson: manifest))

        XCTAssertThrowsError(try manifestKdf(manifestJson: Data("not json".utf8)))
    }
}
