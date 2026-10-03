//! The legacy scanner inventory and what this crate does with each entry.
//!
//! Source: the ownership map (`docs/migration/ownership-map.md`, "Legacy
//! scanner list and pins") at oracle commit
//! 4b846967346505baca11e0b98cab1475fbce6773. An entry is a PII-observation
//! adapter only when the oracle maps that scanner's findings to PII families;
//! otherwise it is out of scope with the reason recorded here, so the decision
//! is reviewable and tested rather than implied by absence.

/// What this crate provides for a legacy scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// A PII-observation adapter exists; the field names its adapter id.
    PiiObservation {
        /// Adapter identifier.
        adapter_id: &'static str,
    },
    /// No PII-observation adapter, for the stated reason.
    OutOfScope {
        /// Why.
        reason: &'static str,
    },
}

/// One legacy scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Scanner name as the ownership map writes it.
    pub scanner: &'static str,
    /// Package or binary and its oracle pin.
    pub pin: &'static str,
    /// Disposition in this crate.
    pub disposition: Disposition,
}

const THROUGHPUT_ONLY: &str = "Throughput-only in the oracle: it is timed through redact(text) \
(qualification/peer-pii-runtime-throughput-v1.json, supportClaims false) and its findings are \
never mapped to PII families, ranges or sensitivity there. An adapter would have to invent a \
mapping the oracle does not have. Add one only with a reviewed mapping and its own conformance \
vectors.";

const CREDENTIAL_ONLY: &str = "Credential scanner (credential suite only); the oracle has no \
PII adapter for it.";

/// Every scanner in the ownership map's legacy list, in map order.
pub const INVENTORY: [InventoryEntry; 5] = [
    InventoryEntry {
        scanner: "redact-secret",
        pin: "@redact-secret/core 0.1.0-beta.12",
        disposition: Disposition::PiiObservation {
            adapter_id: crate::redact_secret::ADAPTER_ID,
        },
    },
    InventoryEntry {
        scanner: "flare-redact",
        pin: "flare-redact 1.6.1",
        disposition: Disposition::OutOfScope {
            reason: THROUGHPUT_ONLY,
        },
    },
    InventoryEntry {
        scanner: "openredaction",
        pin: "@openredaction/core 1.1.5",
        disposition: Disposition::OutOfScope {
            reason: THROUGHPUT_ONLY,
        },
    },
    InventoryEntry {
        scanner: "gitleaks",
        pin: "gitleaks 8.30.1",
        disposition: Disposition::OutOfScope {
            reason: CREDENTIAL_ONLY,
        },
    },
    InventoryEntry {
        scanner: "trufflehog",
        pin: "trufflehog 3.97.4",
        disposition: Disposition::OutOfScope {
            reason: CREDENTIAL_ONLY,
        },
    },
];
