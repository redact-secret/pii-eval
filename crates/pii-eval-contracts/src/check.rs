//! Small shared structural checks used by the document validators.

use std::collections::BTreeSet;

use crate::reason::{Collector, Meta, Path, ReasonCode};

/// Record `limit-exceeded` when `len > max`. Returns whether the bound holds,
/// so callers can skip per-item work on an oversized collection.
pub(crate) fn within_limit(len: usize, max: usize, path: &Path<'_>, c: &mut Collector) -> bool {
    if len > max {
        c.push_with(
            ReasonCode::LimitExceeded,
            path,
            Meta::limit(max as u64, len as u64),
        );
        false
    } else {
        true
    }
}

/// Require a collection to be in strictly ascending key order with no
/// duplicates. Reports `duplicate-identity` for each repeated key and
/// `non-canonical-order` once for the first out-of-order pair. A correctly
/// ordered collection is checked in constant extra memory; only after an
/// ordering violation does the check fall back to a set to find duplicates.
pub(crate) fn sorted_unique<'a, T, K: Ord>(
    items: &'a [T],
    key: impl Fn(&'a T) -> K,
    path: &Path<'_>,
    c: &mut Collector,
) {
    let mut previous: Option<K> = None;
    let mut unordered = false;
    for (i, item) in items.iter().enumerate() {
        let k = key(item);
        if let Some(prev) = &previous {
            match k.cmp(prev) {
                std::cmp::Ordering::Equal => c.push(ReasonCode::DuplicateIdentity, &path.index(i)),
                std::cmp::Ordering::Less => {
                    if !unordered {
                        c.push(ReasonCode::NonCanonicalOrder, &path.index(i));
                    }
                    unordered = true;
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        previous = Some(k);
    }
    if unordered {
        // Order is already reported; still surface repeated identities.
        let mut seen: BTreeSet<K> = BTreeSet::new();
        for (i, item) in items.iter().enumerate() {
            if !seen.insert(key(item)) {
                c.push(ReasonCode::DuplicateIdentity, &path.index(i));
            }
        }
    }
}

/// Require a collection to be non-empty.
pub(crate) fn non_empty<T>(items: &[T], path: &Path<'_>, c: &mut Collector) {
    if items.is_empty() {
        c.push(ReasonCode::EmptyCollection, path);
    }
}
