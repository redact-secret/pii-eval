//! Isolated, removable legacy compatibility support for `pii-eval`.
//!
//! Bootstrap placeholder: no legacy projection or parity support exists yet.
//! Nothing outside this crate may depend on it; it is removed when its last
//! consumer is gone.

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
