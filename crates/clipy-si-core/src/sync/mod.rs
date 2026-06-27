//! Sync merge rules (M11) — the pure decision core for ClipySi's local-folder sync.
//!
//! Everything here is a **pure function over values** (no I/O, no clock, no RNG — the shell
//! supplies `now`). The Swift `SyncEngine` lists the vault folder, summarises local state, asks
//! these functions what to do, and executes the answers. Correctness is pinned by the case-table
//! KAT (`kat/sync.json`, tests/kat_sync.rs) so every OS shell merges identically.
//!
//! Model (design m11 §5 / §14 Rev 2.1):
//! - A record is immutable once published; the ONLY update is a tombstone. Reorder bumps are
//!   local-only. Hence merge needs no HLC comparison for known ids: **a tombstone always wins**;
//!   a re-copy survives as a NEW record once the tombstone has been applied locally.
//! - Pull is a filename-set diff against the local `syncApplied` set (no cursor): immune to
//!   out-of-order / delayed file arrival. Tombstones are processed BEFORE live records, and an
//!   unknown tombstone is *recorded* ([`MergeAction::RecordTombstoneOnly`]) so a late-arriving
//!   `records/{id}` file can never resurrect it.
//! - Cross-device content dedupe uses `sync_hash` and only ever *suppresses an insert* — it
//!   never merges record ids.
//!
//! Units (design §14 FIX-3): `Hlc.wall_millis` = unix **milliseconds**; device `last_seen` =
//! unix **seconds**. [`gc_eligible`] converts explicitly.

use core::cmp::Ordering;
use uuid::Uuid;

use crate::record::Hlc;

/// Tombstone files younger than this are never GC'd (seconds).
pub const TOMBSTONE_RETENTION_SECS: i64 = 35 * 86_400;
/// A device whose `last_seen` is older than this no longer blocks GC and must run the
/// stale-rejoin protocol when it returns (seconds). Invariant: RETENTION > STALE.
pub const STALE_DEVICE_SECS: i64 = 30 * 86_400;
/// A remote HLC wall further than this ahead of local `now` is clamped before merging into the
/// local clock (milliseconds). Headers themselves are never rewritten.
pub const MAX_DRIFT_MILLIS: i64 = 24 * 3_600_000;

// MARK: - HLC

/// Total order over HLC stamps: (wall, counter, node-bytes). `node` makes the order total even
/// when two devices stamp the same (wall, counter).
pub fn hlc_compare(a: &Hlc, b: &Hlc) -> Ordering {
    a.wall_millis
        .cmp(&b.wall_millis)
        .then(a.counter.cmp(&b.counter))
        .then(a.node.as_bytes().cmp(b.node.as_bytes()))
}

/// The next stamp this device issues (before publishing a record/tombstone). Monotonic even if
/// the wall clock steps backwards; counter saturation rolls the wall forward by 1ms.
pub fn hlc_next(prev: Option<&Hlc>, now_millis: i64, node: Uuid) -> Hlc {
    let Some(prev) = prev else {
        return Hlc {
            wall_millis: now_millis,
            counter: 0,
            node,
        };
    };
    let wall = prev.wall_millis.max(now_millis);
    if wall == prev.wall_millis {
        match prev.counter.checked_add(1) {
            Some(counter) => Hlc {
                wall_millis: wall,
                counter,
                node,
            },
            None => Hlc {
                wall_millis: wall.saturating_add(1),
                counter: 0,
                node,
            },
        }
    } else {
        Hlc {
            wall_millis: wall,
            counter: 0,
            node,
        }
    }
}

/// Merge a received stamp into the local clock (standard HLC receive). The remote wall is
/// clamped to `now + MAX_DRIFT_MILLIS` so a badly-skewed device cannot poison the local clock
/// (design §14 FIX-5: the clamp affects ONLY the local clock — the record's header keeps and is
/// always compared by its original stamp).
pub fn hlc_receive(local: Option<&Hlc>, remote: &Hlc, now_millis: i64, node: Uuid) -> Hlc {
    let remote_wall = remote
        .wall_millis
        .min(now_millis.saturating_add(MAX_DRIFT_MILLIS));
    let local_wall = local.map(|l| l.wall_millis);
    let wall = local_wall
        .unwrap_or(i64::MIN)
        .max(remote_wall)
        .max(now_millis);

    let local_part = match local {
        Some(l) if l.wall_millis == wall => Some(l.counter),
        _ => None,
    };
    let remote_part = if remote_wall == wall {
        Some(remote.counter)
    } else {
        None
    };
    let counter = match (local_part, remote_part) {
        (Some(a), Some(b)) => a.max(b).saturating_add(1),
        (Some(a), None) => a.saturating_add(1),
        (None, Some(b)) => b.saturating_add(1),
        (None, None) => 0,
    };
    Hlc {
        wall_millis: wall,
        counter,
        node,
    }
}

// MARK: - Merge decision

/// What the shell knows locally about one incoming record id (+ its content hash neighborhood).
/// `applied`/`applied_deleted` come from the `syncApplied` table; the duplicate fields are
/// sync_hash lookups over live rows and over tombstoned entries respectively.
#[derive(Debug, Clone, Default)]
pub struct LocalState {
    /// This record id is in the applied set (was applied or published by this device).
    pub applied: bool,
    /// ... and its applied state is "deleted" (tombstone known).
    pub applied_deleted: bool,
    /// A *different* live local clip has the same `sync_hash`.
    pub live_duplicate_sync_hash: bool,
    /// A *different* record with the same `sync_hash` was tombstoned; the newest such tombstone's
    /// stamp. Used to decide whether an incoming same-content record post- or pre-dates the wipe.
    pub tombstoned_duplicate_hlc: Option<Hlc>,
}

/// The engine's marching orders for one incoming envelope.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAction {
    /// Insert the record locally (decrypt body, write blobs, insert row) and mark applied.
    ApplyRemote,
    /// Soft-delete the local row (blob GC included) and mark applied-deleted.
    ApplyTombstone,
    /// Unknown record's tombstone: apply nothing, but record applied-deleted so a late-arriving
    /// live file for this id can never resurrect it (transport-race zombie guard).
    RecordTombstoneOnly,
    /// Nothing to do (already applied / known-immutable / already deleted). Mark applied.
    Skip,
    /// Same content already lives (or was deliberately wiped) locally under another id — suppress
    /// the insert. Mark applied so the file is never re-read.
    SkipDuplicateContent,
}

/// Decide what to do with one incoming envelope. `remote_deleted` / `remote_hlc` come from the
/// plaintext header. Pull MUST process tombstones before live records (Rev 2.1).
pub fn merge_decide(local: &LocalState, remote_deleted: bool, remote_hlc: &Hlc) -> MergeAction {
    if local.applied {
        if remote_deleted && !local.applied_deleted {
            // The only possible update to a known record: delete wins, unconditionally.
            return MergeAction::ApplyTombstone;
        }
        // Known records are immutable (reorder is local-only); known tombstones are final.
        return MergeAction::Skip;
    }
    if remote_deleted {
        return MergeAction::RecordTombstoneOnly;
    }
    // Unknown live record: content-level dedupe.
    if let Some(tomb_hlc) = &local.tombstoned_duplicate_hlc {
        if hlc_compare(remote_hlc, tomb_hlc) != Ordering::Greater {
            // Captured before (or at) the wipe of identical content: the wipe covers it.
            return MergeAction::SkipDuplicateContent;
        }
        // Re-copy after deletion: a legitimate new record — unless a live copy already exists.
    }
    if local.live_duplicate_sync_hash {
        return MergeAction::SkipDuplicateContent;
    }
    MergeAction::ApplyRemote
}

// MARK: - GC / stale rejoin

/// One participating device's presence, from `devices/{id}.json`. `last_seen_secs` is unix
/// seconds (the wire unit of `DeviceDescriptor.last_seen`).
#[derive(Debug, Clone, Copy)]
pub struct DevicePresence {
    pub last_seen_secs: i64,
}

/// Whether a device is stale (no longer blocks GC; must run stale-rejoin when it returns).
pub fn device_is_stale(last_seen_secs: i64, now_secs: i64) -> bool {
    now_secs.saturating_sub(last_seen_secs) > STALE_DEVICE_SECS
}

/// May this tombstone file be removed from the provider? True iff it is older than the retention
/// period AND every non-stale device has completed a sync session after it was written.
/// Deterministic over the same inputs, so concurrent GC runs on different devices are idempotent.
/// Note the unit conversion: `last_seen` is seconds, `hlc.wall_millis` milliseconds (FIX-3).
pub fn gc_eligible(tombstone_hlc: &Hlc, devices: &[DevicePresence], now_secs: i64) -> bool {
    let age_millis = (now_secs * 1000).saturating_sub(tombstone_hlc.wall_millis);
    if age_millis <= TOMBSTONE_RETENTION_SECS * 1000 {
        return false;
    }
    devices
        .iter()
        .filter(|d| !device_is_stale(d.last_seen_secs, now_secs))
        .all(|d| d.last_seen_secs * 1000 >= tombstone_hlc.wall_millis)
}

/// What to do, during rejoin, with a local record we previously published (`applied`, not
/// deleted) that is now absent from BOTH `records/` and `tombs/` listings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejoinAction {
    /// We were away longer than the stale window: its tombstone may legitimately have been GC'd —
    /// treat as remotely deleted; do NOT re-publish (the zombie guard).
    DeleteLocally,
    /// We are fresh, so by the RETENTION > STALE invariant a tombstone could not have been GC'd
    /// past us: the provider lost data (manual tampering). Restore the user's record.
    Repush,
}

/// Decide the rejoin behaviour from this device's own staleness.
pub fn rejoin_action(self_last_seen_secs: i64, now_secs: i64) -> RejoinAction {
    if device_is_stale(self_last_seen_secs, now_secs) {
        RejoinAction::DeleteLocally
    } else {
        RejoinAction::Repush
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> Uuid {
        Uuid::from_u128(n as u128)
    }
    fn hlc(wall: i64, counter: u32, n: u8) -> Hlc {
        Hlc {
            wall_millis: wall,
            counter,
            node: node(n),
        }
    }

    #[test]
    fn hlc_next_is_monotonic_against_backwards_clock() {
        let prev = hlc(1_000, 3, 1);
        let next = hlc_next(Some(&prev), 500, node(1)); // clock stepped back
        assert_eq!(next.wall_millis, 1_000);
        assert_eq!(next.counter, 4);
        let fresh = hlc_next(Some(&prev), 2_000, node(1));
        assert_eq!((fresh.wall_millis, fresh.counter), (2_000, 0));
    }

    #[test]
    fn hlc_counter_saturation_rolls_wall() {
        let prev = hlc(1_000, u32::MAX, 1);
        let next = hlc_next(Some(&prev), 1_000, node(1));
        assert_eq!((next.wall_millis, next.counter), (1_001, 0));
    }

    #[test]
    fn hlc_receive_clamps_skewed_remote_wall() {
        let local = hlc(1_000, 0, 1);
        let skewed = hlc(MAX_DRIFT_MILLIS * 10, 0, 2);
        let merged = hlc_receive(Some(&local), &skewed, 1_000, node(1));
        assert!(merged.wall_millis <= 1_000 + MAX_DRIFT_MILLIS);
        // The remote header itself still compares by its original (unclamped) value.
        assert_eq!(hlc_compare(&skewed, &merged), Ordering::Greater);
    }

    #[test]
    fn hlc_compare_is_total_via_node() {
        let a = hlc(5, 1, 1);
        let b = hlc(5, 1, 2);
        assert_eq!(hlc_compare(&a, &b), Ordering::Less);
        assert_eq!(hlc_compare(&a, &a), Ordering::Equal);
    }

    #[test]
    fn tombstone_always_wins_for_known_record() {
        let local = LocalState {
            applied: true,
            ..Default::default()
        };
        assert_eq!(
            merge_decide(&local, true, &hlc(1, 0, 2)),
            MergeAction::ApplyTombstone
        );
        // Known live record never changes.
        assert_eq!(
            merge_decide(&local, false, &hlc(9, 0, 2)),
            MergeAction::Skip
        );
    }

    #[test]
    fn unknown_tombstone_is_recorded_not_skipped() {
        let local = LocalState::default();
        assert_eq!(
            merge_decide(&local, true, &hlc(1, 0, 2)),
            MergeAction::RecordTombstoneOnly
        );
    }

    #[test]
    fn duplicate_content_suppresses_insert_unless_recopied_after_wipe() {
        // Live duplicate: suppress.
        let live_dup = LocalState {
            live_duplicate_sync_hash: true,
            ..Default::default()
        };
        assert_eq!(
            merge_decide(&live_dup, false, &hlc(10, 0, 2)),
            MergeAction::SkipDuplicateContent
        );
        // Same content was wiped at hlc 100: an older capture is covered by the wipe...
        let wiped = LocalState {
            tombstoned_duplicate_hlc: Some(hlc(100, 0, 1)),
            ..Default::default()
        };
        assert_eq!(
            merge_decide(&wiped, false, &hlc(50, 0, 2)),
            MergeAction::SkipDuplicateContent
        );
        // ...but a re-copy after the wipe is a legitimate new record.
        assert_eq!(
            merge_decide(&wiped, false, &hlc(150, 0, 2)),
            MergeAction::ApplyRemote
        );
    }

    #[test]
    fn gc_blocks_on_fresh_unacked_device_and_respects_units() {
        let day = 86_400_i64;
        let tomb = hlc(day * 1000, 0, 1); // written day 1 (ms)
        let now = 40 * day; // day 40 (s) → age 39d > 35d retention
        let acked = DevicePresence {
            last_seen_secs: 39 * day,
        };
        let fresh_unacked = DevicePresence {
            last_seen_secs: 12 * day, // ← seconds; *1000 must compare correctly against ms
        };
        // Wait: last_seen day 12 vs now day 40 → 28d < 30d ⇒ fresh; 12d*1000ms ≥ 1d*1000ms ⇒ acked.
        assert!(gc_eligible(&tomb, &[acked, fresh_unacked], now));

        // A fresh device that last synced BEFORE the tombstone blocks GC.
        let blocking = DevicePresence {
            last_seen_secs: 12 * day,
        };
        let late_tomb = hlc(20 * day * 1000, 0, 1); // written day 20, after blocking's last sync
        let now2 = 56 * day; // age 36d > 35d; blocking is 44d-old → stale → ignored
        assert!(gc_eligible(&late_tomb, &[blocking], now2));
        let now3 = 41 * day; // blocking is 29d-old → fresh and unacked → blocks
        assert!(!gc_eligible(&late_tomb, &[blocking], now3));
    }

    #[test]
    fn gc_respects_retention_age() {
        let day = 86_400_i64;
        let tomb = hlc(day * 1000, 0, 1);
        assert!(!gc_eligible(&tomb, &[], 30 * day)); // age 29d < 35d
        assert!(gc_eligible(&tomb, &[], 37 * day)); // age 36d > 35d
    }

    #[test]
    fn rejoin_stale_deletes_fresh_repushes() {
        let day = 86_400_i64;
        assert_eq!(rejoin_action(0, 31 * day), RejoinAction::DeleteLocally);
        assert_eq!(rejoin_action(10 * day, 31 * day), RejoinAction::Repush);
    }
}
