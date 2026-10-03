//! Isolated, removable legacy compatibility support for `pii-eval`.
//!
//! Implemented: the `legacy-first-overlap` matching mode ([`legacy`]), a
//! faithful port of the oracle's `interpretPiiOutcome` and `rangeOutcome`
//! (`benchmarks/evaluation/domains/pii/contract-model.ts` at oracle commit
//! `4b846967346505baca11e0b98cab1475fbce6773`). It exists so migration parity
//! can name and reproduce the legacy behavior exactly, quirks included; it is
//! not the canonical model and nothing outside this crate may depend on it. It
//! is removed when its last consumer is gone.
//!
//! Implemented in P9: [`legacy_accounting`], the oracle's metric accounting
//! (`accounting.ts`, `primitives.ts`) as a named mode with switchable quirks
//! (binary64 arithmetic included), used by the oracle parity suite
//! (`crates/pii-eval-cli/tests/oracle_parity.rs`, ADR 0011) to prove the
//! compatibility protocol against the oracle's own output and to attribute
//! every difference of the canonical accounting.

pub mod legacy;
pub mod legacy_accounting;

use pii_eval_contracts::{CrateIdentity, Role};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Compat,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Compat);
        assert_eq!(IDENTITY.package, "pii-eval-compat");
    }
}
