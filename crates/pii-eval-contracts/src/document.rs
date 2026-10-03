//! The document envelope: parsing, validation, sealing and serialization.
//!
//! Every top-level contract is a [`Document`] with the same envelope:
//!
//! ```text
//! { "schema": "...", "schemaVersion": "1.0", "semanticDigest": "<sha256>",
//!   "semantic": { ... }, "diagnostics": { ... } }   // diagnostics optional
//! ```
//!
//! Only `semantic` is digested. `diagnostics` (timing, host details) has its
//! own types that are not reachable from the digest by construction.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::canonical::{
    ParseLimits, canonical_bytes_of, classify_parse_error, parse_strict, semantic_digest,
};
use crate::ident::Sha256Digest;
use crate::reason::{Collector, ContractError, Path, ReasonCode, Violations};
use crate::version::{DocumentKind, SchemaVersion, check_envelope};

/// A top-level contract document.
pub trait Document: Serialize + DeserializeOwned + Sized {
    /// The semantic body type that the digest covers.
    type Body: Serialize;

    /// The document kind.
    const KIND: DocumentKind;

    /// Declared schema version.
    fn schema_version(&self) -> SchemaVersion;

    /// Declared semantic digest.
    fn claimed_digest(&self) -> &Sha256Digest;

    /// Replace the declared semantic digest.
    fn set_digest(&mut self, digest: Sha256Digest);

    /// The digested body.
    fn body(&self) -> &Self::Body;

    /// Structural validation of the body. Called with the path of the body.
    fn validate_body(&self, path: &Path<'_>, c: &mut Collector);
}

/// Digest domain for a document kind and schema major version.
pub fn digest_domain(kind: DocumentKind, version: SchemaVersion) -> String {
    format!("{}/{}", kind.schema_id(), version.major)
}

/// Recompute the semantic digest of a document body.
pub fn compute_digest<D: Document>(doc: &D) -> Result<Sha256Digest, ContractError> {
    let canonical = canonical_bytes_of(doc.body())?;
    Ok(semantic_digest(
        &digest_domain(D::KIND, doc.schema_version()),
        &canonical,
    ))
}

/// Set the document's declared digest to the recomputed one.
pub fn seal<D: Document>(doc: &mut D) -> Result<(), ContractError> {
    let digest = compute_digest(doc)?;
    doc.set_digest(digest);
    Ok(())
}

/// Validate structure and digest of a typed document.
pub fn validate<D: Document>(doc: &D) -> Result<(), Violations> {
    let mut c = Collector::new();
    if let Err(code) = doc.schema_version().readable() {
        c.push(code, &Path::ROOT.field("schemaVersion"));
    }
    doc.validate_body(&Path::ROOT.field("semantic"), &mut c);
    match compute_digest(doc) {
        Ok(d) if d == *doc.claimed_digest() => {}
        _ => c.push(
            ReasonCode::SemanticDigestMismatch,
            &Path::ROOT.field("semanticDigest"),
        ),
    }
    c.finish()
}

/// Parse and validate a document from bytes: strict parse, envelope check,
/// typed parse, structural validation and digest verification.
pub fn parse<D: Document>(bytes: &[u8], limits: &ParseLimits) -> Result<D, Violations> {
    let value = parse_strict(bytes, limits)?;
    check_envelope(&value, D::KIND)?;
    let doc: D = serde_json::from_slice(bytes).map_err(|e| classify_parse_error(&e))?;
    validate(&doc)?;
    Ok(doc)
}

/// Parse with default limits.
pub fn parse_default<D: Document>(bytes: &[u8]) -> Result<D, Violations> {
    parse(bytes, &ParseLimits::default())
}

/// Pretty JSON with object keys in ascending order, a trailing newline, for
/// committed fixtures and human review. This is a presentation of the
/// document, not the digest's canonical form (see ADR 0003).
pub fn to_pretty_json<D: Document>(doc: &D) -> Result<String, ContractError> {
    let value =
        serde_json::to_value(doc).map_err(|_| ContractError::root(ReasonCode::SchemaViolation))?;
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|_| ContractError::root(ReasonCode::SchemaViolation))?;
    text.push('\n');
    Ok(text)
}

macro_rules! schema_tag {
    ($(#[$doc:meta])* $name:ident, $text:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
        pub enum $name {
            /// The only value.
            #[serde(rename = $text)]
            Only,
        }
    };
}
pub(crate) use schema_tag;

/// Implements [`Document`] for a struct with `schema_version`, `semantic_digest`
/// and `semantic` fields.
macro_rules! impl_document {
    ($doc:ident, $body:ident, $kind:expr) => {
        impl $crate::document::Document for $doc {
            type Body = $body;
            const KIND: $crate::version::DocumentKind = $kind;
            fn schema_version(&self) -> $crate::version::SchemaVersion {
                self.schema_version
            }
            fn claimed_digest(&self) -> &$crate::ident::Sha256Digest {
                &self.semantic_digest
            }
            fn set_digest(&mut self, digest: $crate::ident::Sha256Digest) {
                self.semantic_digest = digest;
            }
            fn body(&self) -> &$body {
                &self.semantic
            }
            fn validate_body(
                &self,
                path: &$crate::reason::Path<'_>,
                c: &mut $crate::reason::Collector,
            ) {
                self.semantic.validate(path, c);
            }
        }
    };
}
pub(crate) use impl_document;
