//! Measurement kernel for `pii-eval`.
//!
//! Bootstrap placeholder: no methods, outcome interpretation, range
//! relationships or accounting exist yet. The kernel must never spawn
//! processes, use the network, publish, or encode product support policy; the
//! dependency guard in `pii-eval-cli/tests/dependency_policy.rs` enforces the
//! dependency side of that rule.

use pii_eval_contracts::{CrateIdentity, Role};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Kernel,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Kernel);
        assert_eq!(IDENTITY.package, "pii-eval-kernel");
    }
}
