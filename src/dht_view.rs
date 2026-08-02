//! Pure aggregation for `GET /dht` + `GET /dht.json` — a view of the network's CONTENT layer, built
//! from what connected nodes report about their DHT provider stores (dig_ecosystem #1935).
//!
//! # Where the data comes from, and what it is NOT
//!
//! The relay is not a DHT node and holds no provider records. It does hold a live reservation to
//! every registered peer, so it ASKS them (RLY-009). Because a Kademlia node stores records for keys
//! near its OWN `peer_id`, each answer describes MANY OTHER peers' content rather than the answering
//! node's own holdings — so the union across connected nodes is a broad slice of the real DHT.
//!
//! It is a **sample, not the global DHT.** Coverage is proportional to how well the connected peers'
//! ids spread across the keyspace; with a handful of peers this is a partial view that approaches
//! global only as the network grows. [`DhtView::reporting_peers`] is published precisely so a
//! consumer can say what the view is OF, rather than presenting a four-peer sample as "the DHT".
//!
//! # Privacy
//!
//! Same contract as `/map` (see [`crate::map`]): no `peer_id`, no raw IP, ever. A provider record is
//! a `(peer_id, content_key)` pair, and publishing that linkage is exactly what `/map` refuses to
//! do; RLY-009 carries counts only, and nothing here re-introduces an identity.
//!
//! # Trust
//!
//! Every number here is SELF-REPORTED by an untrusted peer. This is observability only: it must
//! never feed peer selection, routing, or any limit. Aggregation is bounded so a Sybil cannot make
//! the endpoint's response grow without limit.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::wire::DhtRecordEntry;

/// The `/dht.json` schema version. Bumped when the shape changes incompatibly.
pub const DHT_SCHEMA_VERSION: u32 = 1;

/// Hard ceiling on how many content keys `/dht.json` will publish, whatever the peers report. The
/// inputs are attacker-influenced, so the endpoint's own size must not be a function of what peers
/// choose to say.
pub const MAX_PUBLISHED_KEYS: usize = 2000;

/// One content key in the published view.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DhtViewEntry {
    /// The 64-hex content key.
    pub content_key: String,
    /// The largest live-provider count any single reporting node knows for this key.
    ///
    /// MAX, deliberately not a sum: nodes near the same key hold OVERLAPPING provider sets, so
    /// summing would double-count the same provider once per node that happens to know it. The max
    /// is an honest lower bound — "at least this many distinct providers exist" — which is the claim
    /// the data actually supports.
    pub providers: usize,
    /// How many reporting nodes knew about this key at all. A key seen by several independent nodes
    /// is better corroborated than one a single node asserts.
    pub reported_by: usize,
}

/// The `/dht.json` body: what the connected nodes collectively know about the content layer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DhtView {
    /// The `/dht.json` schema version ([`DHT_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Unix seconds the view was built.
    pub generated_at: u64,
    /// How many connected nodes contributed an answer. The view is a union of THESE nodes' stores,
    /// not a global crawl — a small number here means a correspondingly partial picture.
    pub reporting_peers: usize,
    /// Distinct content keys across every answer, BEFORE [`MAX_PUBLISHED_KEYS`] truncation.
    pub total_keys: usize,
    /// Whether any reporting node truncated its own answer, or this view truncated the union — so a
    /// partial picture is never presented as complete.
    pub truncated: bool,
    /// The keys, ordered by corroboration then provider count then key, capped at
    /// [`MAX_PUBLISHED_KEYS`].
    pub keys: Vec<DhtViewEntry>,
}

/// One node's RLY-009 answer, as handed to [`build_dht_view`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnswer {
    /// The content keys this node reported.
    pub records: Vec<DhtRecordEntry>,
    /// Whether the node truncated its own answer against the relay's `max_keys`.
    pub truncated: bool,
}

/// Build the published view from the answers the relay collected. PURE — no I/O, no locks, no clock
/// (the caller supplies `generated_at`), so the whole aggregation + ordering + bounding is testable.
pub fn build_dht_view(answers: &[PeerAnswer], generated_at: u64) -> DhtView {
    // Keyed on the content key so the union is deduped across nodes; BTreeMap so the pre-sort order
    // is deterministic rather than hash-seeded.
    let mut union: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for answer in answers {
        for record in &answer.records {
            let slot = union.entry(record.content_key.as_str()).or_insert((0, 0));
            slot.0 = slot.0.max(record.providers);
            slot.1 += 1;
        }
    }

    let total_keys = union.len();
    // A node that hit its own cap means the union is incomplete even before ours applies.
    let any_peer_truncated = answers.iter().any(|a| a.truncated);

    let mut keys: Vec<DhtViewEntry> = union
        .into_iter()
        .map(|(content_key, (providers, reported_by))| DhtViewEntry {
            content_key: content_key.to_string(),
            providers,
            reported_by,
        })
        .collect();

    // Best-corroborated first, then best-replicated, then by key for a stable tie-break. When the
    // cap bites, this keeps the keys the network agrees most about rather than an arbitrary slice —
    // and it means a Sybil inventing many single-node keys cannot push real content out of the view.
    keys.sort_by(|a, b| {
        b.reported_by
            .cmp(&a.reported_by)
            .then(b.providers.cmp(&a.providers))
            .then(a.content_key.cmp(&b.content_key))
    });

    let truncated = any_peer_truncated || total_keys > MAX_PUBLISHED_KEYS;
    keys.truncate(MAX_PUBLISHED_KEYS);

    DhtView {
        schema_version: DHT_SCHEMA_VERSION,
        generated_at,
        reporting_peers: answers.len(),
        total_keys,
        truncated,
        keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: &str, providers: usize) -> DhtRecordEntry {
        DhtRecordEntry {
            content_key: key.to_string(),
            providers,
        }
    }

    fn answer(records: Vec<DhtRecordEntry>) -> PeerAnswer {
        PeerAnswer {
            records,
            truncated: false,
        }
    }

    fn entry<'a>(view: &'a DhtView, key: &str) -> &'a DhtViewEntry {
        view.keys
            .iter()
            .find(|e| e.content_key == key)
            .unwrap_or_else(|| panic!("key {key} missing from the view"))
    }

    #[test]
    fn overlapping_reports_take_the_max_rather_than_summing() {
        // Two nodes near the same key hold OVERLAPPING provider sets. Summing would claim 7
        // providers where there may be 4 — inventing replication that does not exist.
        let view = build_dht_view(
            &[answer(vec![rec("aa", 4)]), answer(vec![rec("aa", 3)])],
            100,
        );
        assert_eq!(view.total_keys, 1);
        assert_eq!(entry(&view, "aa").providers, 4, "max, not 7");
        assert_eq!(entry(&view, "aa").reported_by, 2);
    }

    #[test]
    fn the_union_dedupes_keys_across_nodes() {
        let view = build_dht_view(
            &[
                answer(vec![rec("aa", 1), rec("bb", 1)]),
                answer(vec![rec("bb", 2), rec("cc", 1)]),
            ],
            100,
        );
        assert_eq!(view.total_keys, 3);
        assert_eq!(entry(&view, "bb").providers, 2);
        assert_eq!(entry(&view, "bb").reported_by, 2);
        assert_eq!(entry(&view, "aa").reported_by, 1);
        assert_eq!(view.reporting_peers, 2);
    }

    #[test]
    fn a_peer_that_truncated_its_own_answer_makes_the_view_truncated() {
        // The union is incomplete even though OUR cap never bit — saying otherwise would present a
        // partial picture as complete.
        let view = build_dht_view(
            &[PeerAnswer {
                records: vec![rec("aa", 1)],
                truncated: true,
            }],
            100,
        );
        assert!(view.truncated);
        assert_eq!(view.total_keys, 1, "the true count is still reported");
    }

    #[test]
    fn best_corroborated_keys_survive_truncation() {
        // A Sybil inventing many single-node keys must not push genuinely-corroborated content out
        // of the view: ordering is by how many independent nodes reported the key.
        let sybil: Vec<DhtRecordEntry> = (0..(MAX_PUBLISHED_KEYS + 50))
            .map(|i| rec(&format!("{i:064x}"), 1))
            .collect();
        let real = "ff".repeat(32);
        let view = build_dht_view(
            &[
                answer(sybil),
                answer(vec![rec(&real, 5)]),
                answer(vec![rec(&real, 5)]),
            ],
            100,
        );
        assert!(view.truncated);
        assert_eq!(view.keys.len(), MAX_PUBLISHED_KEYS);
        assert_eq!(
            view.keys[0].content_key, real,
            "the twice-reported key ranks first"
        );
    }

    #[test]
    fn the_published_view_is_capped_regardless_of_what_peers_report() {
        // The endpoint's own size must not be a function of what untrusted peers choose to say.
        let flood: Vec<DhtRecordEntry> = (0..(MAX_PUBLISHED_KEYS * 2))
            .map(|i| rec(&format!("{i:064x}"), 1))
            .collect();
        let view = build_dht_view(&[answer(flood)], 100);
        assert_eq!(view.keys.len(), MAX_PUBLISHED_KEYS);
        assert_eq!(
            view.total_keys,
            MAX_PUBLISHED_KEYS * 2,
            "true total survives"
        );
        assert!(view.truncated);
    }

    #[test]
    fn no_peer_identity_can_appear_in_the_serialized_view() {
        // Same property /map enforces. A provider record is (peer_id, content_key); this endpoint
        // publishes counts only.
        let view = build_dht_view(&[answer(vec![rec("aa", 2)])], 100);
        let raw = serde_json::to_string(&view).unwrap();
        assert!(!raw.contains("peer_id"), "{raw}");
    }

    #[test]
    fn an_empty_network_yields_an_empty_but_well_formed_view() {
        let view = build_dht_view(&[], 100);
        assert_eq!(view.schema_version, DHT_SCHEMA_VERSION);
        assert_eq!(view.reporting_peers, 0);
        assert_eq!(view.total_keys, 0);
        assert!(!view.truncated);
        assert!(view.keys.is_empty());
    }

    #[test]
    fn ordering_is_deterministic_for_equally_corroborated_keys() {
        // Ties break on the key, so repeated builds return the same order and a polling consumer
        // does not see content shuffle.
        let a = build_dht_view(&[answer(vec![rec("bb", 1), rec("aa", 1)])], 100);
        let b = build_dht_view(&[answer(vec![rec("aa", 1), rec("bb", 1)])], 100);
        assert_eq!(a.keys, b.keys);
    }
}
