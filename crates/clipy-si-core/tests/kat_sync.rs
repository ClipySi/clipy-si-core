//! M11.1 sync merge-rule KAT over `kat/sync.json` — the case-table contract every binding must
//! reproduce. If a decision here drifts, two devices stop converging; treat any change as a
//! breaking protocol change (add vectors, never edit).

use core::cmp::Ordering;
use std::collections::HashMap;

use clipy_si_core::sync::{
    gc_eligible, hlc_compare, hlc_next, hlc_receive, merge_decide, rejoin_action, DevicePresence,
    LocalState, MergeAction, RejoinAction,
};
use clipy_si_core::Hlc;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
struct Kat {
    node_a: Uuid,
    node_b: Uuid,
    hlc_next: Vec<NextCase>,
    hlc_receive: Vec<ReceiveCase>,
    hlc_compare: Vec<CompareCase>,
    merge: Vec<MergeCase>,
    gc: Vec<GcCase>,
    rejoin: Vec<RejoinCase>,
}

#[derive(Deserialize)]
struct PartialHlc {
    wall_millis: i64,
    counter: u32,
    #[serde(default)]
    node: Option<String>, // "a" | "b"; defaults to a
}

#[derive(Deserialize)]
struct NextCase {
    note: String,
    prev: Option<PartialHlc>,
    now_millis: i64,
    expect: PartialHlc,
}

#[derive(Deserialize)]
struct ReceiveCase {
    note: String,
    local: PartialHlc,
    remote: PartialHlc,
    now_millis: i64,
    expect: PartialHlc,
}

#[derive(Deserialize)]
struct CompareCase {
    note: String,
    a: PartialHlc,
    b: PartialHlc,
    expect: String, // "less" | "equal" | "greater"
}

#[derive(Deserialize)]
struct MergeLocal {
    applied: bool,
    applied_deleted: bool,
    live_dup: bool,
    tomb_dup_hlc: Option<PartialHlc>,
}

#[derive(Deserialize)]
struct MergeCase {
    note: String,
    local: MergeLocal,
    remote_deleted: bool,
    remote_hlc: PartialHlc,
    expect: String,
}

#[derive(Deserialize)]
struct GcCase {
    note: String,
    tomb_hlc_wall_millis: i64,
    devices_last_seen_secs: Vec<i64>,
    now_secs: i64,
    expect: bool,
}

#[derive(Deserialize)]
struct RejoinCase {
    note: String,
    self_last_seen_secs: i64,
    now_secs: i64,
    expect: String, // "delete_locally" | "repush"
}

fn load() -> Kat {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/sync.json");
    let data = std::fs::read_to_string(path).expect("read kat/sync.json");
    serde_json::from_str(&data).expect("parse kat/sync.json")
}

fn resolve(h: &PartialHlc, nodes: &HashMap<&str, Uuid>) -> Hlc {
    let node = match h.node.as_deref() {
        Some(label) => nodes[label],
        None => nodes["a"],
    };
    Hlc {
        wall_millis: h.wall_millis,
        counter: h.counter,
        node,
    }
}

fn nodes(kat: &Kat) -> HashMap<&'static str, Uuid> {
    HashMap::from([("a", kat.node_a), ("b", kat.node_b)])
}

#[test]
fn kat_file_has_no_unknown_sections() {
    // Guard against a typo'd section silently testing nothing.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/sync.json");
    let raw: Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid JSON");
    let known = [
        "_comment",
        "node_a",
        "node_b",
        "hlc_next",
        "hlc_receive",
        "hlc_compare",
        "merge",
        "gc",
        "rejoin",
    ];
    for key in raw.as_object().unwrap().keys() {
        assert!(known.contains(&key.as_str()), "unknown KAT section: {key}");
    }
}

#[test]
fn kat_hlc_next() {
    let kat = load();
    let nodes = nodes(&kat);
    for c in &kat.hlc_next {
        let prev = c.prev.as_ref().map(|p| resolve(p, &nodes));
        let got = hlc_next(prev.as_ref(), c.now_millis, kat.node_a);
        assert_eq!(
            (got.wall_millis, got.counter),
            (c.expect.wall_millis, c.expect.counter),
            "hlc_next: {}",
            c.note
        );
        assert_eq!(got.node, kat.node_a, "hlc_next stamps own node: {}", c.note);
    }
}

#[test]
fn kat_hlc_receive() {
    let kat = load();
    let nodes = nodes(&kat);
    for c in &kat.hlc_receive {
        let local = resolve(&c.local, &nodes);
        let remote = resolve(&c.remote, &nodes);
        let got = hlc_receive(Some(&local), &remote, c.now_millis, kat.node_a);
        assert_eq!(
            (got.wall_millis, got.counter),
            (c.expect.wall_millis, c.expect.counter),
            "hlc_receive: {}",
            c.note
        );
    }
}

#[test]
fn kat_hlc_compare() {
    let kat = load();
    let nodes = nodes(&kat);
    for c in &kat.hlc_compare {
        let expect = match c.expect.as_str() {
            "less" => Ordering::Less,
            "equal" => Ordering::Equal,
            "greater" => Ordering::Greater,
            other => panic!("bad expect {other}"),
        };
        assert_eq!(
            hlc_compare(&resolve(&c.a, &nodes), &resolve(&c.b, &nodes)),
            expect,
            "hlc_compare: {}",
            c.note
        );
    }
}

#[test]
fn kat_merge_case_table() {
    let kat = load();
    let nodes = nodes(&kat);
    for c in &kat.merge {
        let local = LocalState {
            applied: c.local.applied,
            applied_deleted: c.local.applied_deleted,
            live_duplicate_sync_hash: c.local.live_dup,
            tombstoned_duplicate_hlc: c.local.tomb_dup_hlc.as_ref().map(|h| resolve(h, &nodes)),
        };
        let expect = match c.expect.as_str() {
            "apply_remote" => MergeAction::ApplyRemote,
            "apply_tombstone" => MergeAction::ApplyTombstone,
            "record_tombstone_only" => MergeAction::RecordTombstoneOnly,
            "skip" => MergeAction::Skip,
            "skip_duplicate_content" => MergeAction::SkipDuplicateContent,
            other => panic!("bad expect {other}"),
        };
        let got = merge_decide(&local, c.remote_deleted, &resolve(&c.remote_hlc, &nodes));
        assert_eq!(got, expect, "merge: {}", c.note);
    }
}

#[test]
fn kat_gc() {
    let kat = load();
    for c in &kat.gc {
        let tomb = Hlc {
            wall_millis: c.tomb_hlc_wall_millis,
            counter: 0,
            node: kat.node_a,
        };
        let devices: Vec<DevicePresence> = c
            .devices_last_seen_secs
            .iter()
            .map(|s| DevicePresence { last_seen_secs: *s })
            .collect();
        assert_eq!(
            gc_eligible(&tomb, &devices, c.now_secs),
            c.expect,
            "gc: {}",
            c.note
        );
    }
}

#[test]
fn kat_rejoin() {
    let kat = load();
    for c in &kat.rejoin {
        let expect = match c.expect.as_str() {
            "delete_locally" => RejoinAction::DeleteLocally,
            "repush" => RejoinAction::Repush,
            other => panic!("bad expect {other}"),
        };
        assert_eq!(
            rejoin_action(c.self_last_seen_secs, c.now_secs),
            expect,
            "rejoin: {}",
            c.note
        );
    }
}
