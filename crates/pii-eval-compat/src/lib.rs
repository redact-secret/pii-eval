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
//! No other legacy projection or parity support exists yet.

pub mod legacy;

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
