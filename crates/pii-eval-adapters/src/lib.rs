//! Scanner adapters for `pii-eval`.
//!
//! Bootstrap placeholder: no adapter, process runner or observation
//! normalization exists yet. Adapters never score expected outcomes.

use pii_eval_contracts::{CrateIdentity, Role};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Adapters,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Adapters);
        assert_eq!(IDENTITY.package, "pii-eval-adapters");
    }
}
