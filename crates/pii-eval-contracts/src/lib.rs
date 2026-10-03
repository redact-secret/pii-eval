//! Typed contracts for `pii-eval`.
//!
//! Bootstrap placeholder: only crate identity exists here. `CorpusSnapshot`,
//! `RunPlan`, `ObservationSet` and `RunArtifact` are proposed and are frozen in
//! a later phase (P2). Nothing in this crate is a consumer contract.

/// Product name used in identity output.
pub const ENGINE_NAME: &str = "pii-eval";

/// Engine implementation version (workspace version, pre-release bootstrap).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lifecycle label for output that must not be read as a capability claim.
pub const WORKSPACE_STAGE: &str = "bootstrap";

/// The role a workspace crate plays. One variant per crate in ARCHITECTURE.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Contracts,
    Kernel,
    Adapters,
    Cli,
    Compat,
}

impl Role {
    /// Stable lowercase name of the role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Contracts => "contracts",
            Role::Kernel => "kernel",
            Role::Adapters => "adapters",
            Role::Cli => "cli",
            Role::Compat => "compat",
        }
    }
}

/// Identity of one workspace crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrateIdentity {
    pub role: Role,
    pub package: &'static str,
    pub version: &'static str,
}

impl CrateIdentity {
    pub const fn new(role: Role, package: &'static str, version: &'static str) -> Self {
        Self {
            role,
            package,
            version,
        }
    }
}

/// Identity of this crate.
pub const IDENTITY: CrateIdentity = CrateIdentity::new(
    Role::Contracts,
    env!("CARGO_PKG_NAME"),
    env!("CARGO_PKG_VERSION"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_names_its_role() {
        assert_eq!(IDENTITY.role, Role::Contracts);
        assert_eq!(IDENTITY.package, "pii-eval-contracts");
        assert_eq!(IDENTITY.role.as_str(), "contracts");
    }
}
