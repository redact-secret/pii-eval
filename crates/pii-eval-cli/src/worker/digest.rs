//! Typed digests. Five different things are hashed in this protocol and none of
//! them may stand in for another, so each has its own type and there is no
//! `From`, `Into`, `Deref` or `AsRef` between them. A conversion exists only
//! where it is meaningful, as a named function.
//!
//! | Type | What | Syntax |
//! | --- | --- | --- |
//! | [`CustodianDigest`] | SHA-256 of exact file bytes, the custodian's syntax | `sha256:` + 64 lowercase hex |
//! | [`EngineDigest`] | the engine's digests (population, tree) | 64 lowercase hex |
//! | [`BundleDigest`] | the staged archive FILE (a custodian-side identity) | custodian syntax |
//! | [`TreeDigest`] | the extracted package TREE (an engine-side identity) | engine syntax |
//! | [`RuntimeDigest`] | the staged Node runtime file | custodian syntax |
//!
//! ```compile_fail
//! use pii_eval_cli::worker::digest::{BundleDigest, TreeDigest};
//! fn needs_tree(_: &TreeDigest) {}
//! let bundle: BundleDigest = unimplemented!();
//! needs_tree(&bundle); // a bundle digest is not a tree digest
//! ```
//!
//! ```compile_fail
//! use pii_eval_cli::worker::digest::{CustodianDigest, EngineDigest};
//! let c: CustodianDigest = unimplemented!();
//! let _e: EngineDigest = c.into(); // no conversion between syntaxes
//! ```

use std::io::Read;
use std::path::Path;

use pii_eval_contracts::Sha256Digest;

/// Largest file hashed (the custodian's staged-artifact bound, 1 GiB).
pub const MAX_HASHED_FILE_BYTES: u64 = 1 << 30;

/// Why a digest could not be parsed or computed. No value is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    /// The text is not in the syntax of the type.
    Syntax,
    /// The file could not be read or is over the bound.
    Unreadable,
}

/// `sha256:` plus 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianDigest(Sha256Digest);

impl CustodianDigest {
    /// The prefix of the syntax.
    pub const PREFIX: &'static str = "sha256:";

    /// Parse the custodian syntax.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        let hex = text.strip_prefix(Self::PREFIX).ok_or(DigestError::Syntax)?;
        Sha256Digest::new(hex)
            .map(Self)
            .map_err(|_| DigestError::Syntax)
    }

    /// The digest of exact file bytes.
    pub fn from_file_bytes(bytes: &[u8]) -> Self {
        Self(Sha256Digest::of_bytes(bytes))
    }

    /// The digest of a file, streamed, at most [`MAX_HASHED_FILE_BYTES`].
    pub fn from_file(path: &Path) -> Result<Self, DigestError> {
        let file = std::fs::File::open(path).map_err(|_| DigestError::Unreadable)?;
        Sha256Digest::of_reader(file.take(MAX_HASHED_FILE_BYTES + 1), MAX_HASHED_FILE_BYTES)
            .map(Self)
            .map_err(|_| DigestError::Unreadable)
    }

    /// `sha256:<hex>`.
    pub fn render(&self) -> String {
        format!("{}{}", Self::PREFIX, self.0.as_str())
    }
}

/// 64 lowercase hex digits: the engine's own syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDigest(Sha256Digest);

impl EngineDigest {
    /// Parse the engine syntax (a `sha256:` prefix is refused).
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        Sha256Digest::new(text)
            .map(Self)
            .map_err(|_| DigestError::Syntax)
    }

    /// Wrap a contract digest (a population's semantic digest, a tree digest).
    pub fn from_contract(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    /// The contract digest.
    pub fn as_contract(&self) -> &Sha256Digest {
        &self.0
    }

    /// The bare hex text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The digest of a staged archive FILE, as the custodian pins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDigest(CustodianDigest);

impl BundleDigest {
    /// Wrap a file digest as a bundle digest.
    pub fn new(digest: CustodianDigest) -> Self {
        Self(digest)
    }

    /// Parse the custodian syntax.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        CustodianDigest::parse(text).map(Self)
    }

    /// The custodian-syntax view (the staged file's identity). This is NOT a
    /// tree digest and cannot be used as one.
    pub fn as_custodian(&self) -> &CustodianDigest {
        &self.0
    }
}

/// The digest of an extracted package TREE, as the engine defines it
/// (`pii_eval_adapters::pin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDigest(EngineDigest);

impl TreeDigest {
    /// Wrap an engine digest as a tree digest.
    pub fn new(digest: EngineDigest) -> Self {
        Self(digest)
    }

    /// Parse the engine syntax.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        EngineDigest::parse(text).map(Self)
    }

    /// The engine-syntax view. NOT a bundle digest.
    pub fn as_engine(&self) -> &EngineDigest {
        &self.0
    }
}

/// The digest of the staged Node runtime file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDigest(CustodianDigest);

impl RuntimeDigest {
    /// Wrap a file digest as a runtime digest.
    pub fn new(digest: CustodianDigest) -> Self {
        Self(digest)
    }

    /// Parse the custodian syntax.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        CustodianDigest::parse(text).map(Self)
    }

    /// The custodian-syntax view.
    pub fn as_custodian(&self) -> &CustodianDigest {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_two_syntaxes_never_parse_as_each_other() {
        assert!(CustodianDigest::parse(HEX).is_err());
        assert!(EngineDigest::parse(&format!("sha256:{HEX}")).is_err());
        assert!(CustodianDigest::parse(&format!("sha256:{HEX}")).is_ok());
        assert!(EngineDigest::parse(HEX).is_ok());
        assert!(BundleDigest::parse(HEX).is_err());
        assert!(TreeDigest::parse(&format!("sha256:{HEX}")).is_err());
        assert!(RuntimeDigest::parse(HEX).is_err());
        // Upper case is not the syntax of either.
        assert!(EngineDigest::parse(&HEX.to_uppercase()).is_err());
        assert!(CustodianDigest::parse(&format!("sha256:{}", HEX.to_uppercase())).is_err());
    }

    #[test]
    fn a_file_digest_is_the_digest_of_its_bytes() {
        let a = CustodianDigest::from_file_bytes(b"abc");
        assert_eq!(
            a.render(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
