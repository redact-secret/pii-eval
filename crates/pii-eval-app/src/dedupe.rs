//! Delivery replay protection: a bounded set of recently seen delivery ids.
//!
//! GitHub redelivers with the same `X-GitHub-Delivery`, and a captured valid
//! delivery can be replayed by anyone who saw it. The store remembers ids for a
//! TTL and up to a capacity (oldest evicted first). It is deliberately not the
//! only defence: a delivery that outlives the TTL or the capacity yields the
//! same deterministic job id, which the job store coalesces.

use std::collections::{HashMap, VecDeque};

/// Result of [`DeliveryStore::begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Begin {
    /// First sighting (now remembered).
    New,
    /// Already seen within the TTL.
    Duplicate,
}

/// Bounded, TTL-limited set of delivery ids.
#[derive(Debug)]
pub struct DeliveryStore {
    capacity: usize,
    ttl_secs: u64,
    seen: HashMap<String, u64>,
    order: VecDeque<(String, u64)>,
}

impl DeliveryStore {
    /// An empty store.
    pub fn new(capacity: usize, ttl_secs: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl_secs,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn expire(&mut self, now: u64) {
        while let Some((id, at)) = self.order.front() {
            let expired = now.saturating_sub(*at) >= self.ttl_secs;
            let over = self.order.len() > self.capacity;
            if !(expired || over) {
                break;
            }
            // `forget` leaves stale queue entries; only drop the map entry when
            // it still points at this queue entry.
            if self.seen.get(id) == Some(at) {
                self.seen.remove(id);
            }
            self.order.pop_front();
        }
    }

    /// Record `id` at `now` unless it is already remembered.
    pub fn begin(&mut self, id: &str, now: u64) -> Begin {
        self.expire(now);
        if self.seen.contains_key(id) {
            return Begin::Duplicate;
        }
        self.seen.insert(id.to_owned(), now);
        self.order.push_back((id.to_owned(), now));
        self.expire(now);
        Begin::New
    }

    /// Whether `id` is remembered at `now` (does not record it).
    pub fn contains(&mut self, id: &str, now: u64) -> bool {
        self.expire(now);
        self.seen.contains_key(id)
    }

    /// Remember `id` at `now` (no effect if it is already remembered).
    pub fn record(&mut self, id: &str, now: u64) {
        let _ = self.begin(id, now);
    }

    /// Forget `id` (a transient failure: GitHub's redelivery must be accepted).
    pub fn forget(&mut self, id: &str) {
        self.seen.remove(id);
    }

    /// Remembered ids (for tests and metrics).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_detected_until_the_ttl_passes() {
        let mut s = DeliveryStore::new(10, 100);
        assert_eq!(s.begin("a", 0), Begin::New);
        assert_eq!(s.begin("a", 50), Begin::Duplicate);
        assert_eq!(s.begin("a", 99), Begin::Duplicate);
        assert_eq!(s.begin("a", 100), Begin::New, "expired at the TTL");
    }

    #[test]
    fn capacity_evicts_the_oldest_and_stays_bounded() {
        let mut s = DeliveryStore::new(3, 1_000);
        for (i, id) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            assert_eq!(s.begin(id, i as u64), Begin::New);
            assert!(s.len() <= 3);
        }
        assert_eq!(s.begin("e", 10), Begin::Duplicate);
        assert_eq!(s.begin("a", 10), Begin::New, "oldest was evicted");
    }

    #[test]
    fn forgetting_allows_a_redelivery_and_stale_queue_entries_do_not_evict_it() {
        let mut s = DeliveryStore::new(10, 100);
        s.begin("a", 0);
        s.forget("a");
        assert_eq!(s.begin("a", 50), Begin::New);
        // The queue still holds the (a, 0) entry; expiring it must not drop (a, 50).
        assert_eq!(s.begin("b", 100), Begin::New);
        assert_eq!(s.begin("a", 100), Begin::Duplicate);
        assert!(!s.is_empty());
    }
}
