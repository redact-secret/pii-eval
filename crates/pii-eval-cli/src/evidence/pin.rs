//! The snapshot pin (`pii-eval-evidence-pin/1`): the exact snapshot a run may
//! consume. There is no floating reference: a snapshot is pinned by id plus
//! manifest digest plus content digest, and the consumer contract it is read
//! under. The release block (tag, commit, archive digests) is for the fetch
//! tool; the loader itself never needs the network and ignores it except for
//! echoing it into the binding.

use pii_eval_contracts::{ParseLimits, Sha256Digest, parse_strict};
use serde_json::{Map, Value};

use super::{CONTRACT_NAME, CONTRACT_VERSION, DIGEST_SPEC, EvidenceError, reason};

/// `schema` of a pin file.
pub const PIN_SCHEMA: &str = "pii-eval-evidence-pin/1";

/// Archive pin of the release (what the fetch tool verifies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivePin {
    /// Archive file name.
    pub name: String,
    /// SHA-256 of the published `.tar.gz`.
    pub tar_gz_sha256: String,
    /// SHA-256 of the deterministic tar inside it.
    pub tar_sha256: String,
}

/// Release pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePin {
    /// Repository, `owner/name`.
    pub repository: String,
    /// Git tag.
    pub tag: String,
    /// Full commit the tag must resolve to.
    pub commit: String,
    /// The archive.
    pub archive: ArchivePin,
}

/// The pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPin {
    /// Snapshot id (`public-pii-phi/<date>/<12 hex>`).
    pub id: String,
    /// SHA-256 of `manifest.json`.
    pub manifest_sha256: String,
    /// Content digest (`files-v1`).
    pub content_digest: String,
    /// SHA-256 of `sources.jsonl`.
    pub source_manifest_digest: String,
    /// The release.
    pub release: ReleasePin,
}

fn bad(field: &str) -> EvidenceError {
    EvidenceError::invalid(reason::PIN_INVALID, field)
}

fn object<'a>(
    v: &'a Value,
    at: &str,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, EvidenceError> {
    let m = v.as_object().ok_or_else(|| bad(at))?;
    if m.len() != keys.len() || keys.iter().any(|k| !m.contains_key(*k)) {
        return Err(bad(at));
    }
    Ok(m)
}

fn text(m: &Map<String, Value>, key: &str, at: &str) -> Result<String, EvidenceError> {
    m.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| bad(&format!("{at}.{key}")))
}

fn digest(m: &Map<String, Value>, key: &str, at: &str) -> Result<String, EvidenceError> {
    let t = text(m, key, at)?;
    Sha256Digest::new(t.clone())
        .map(|_| t)
        .map_err(|_| bad(&format!("{at}.{key}")))
}

impl SnapshotPin {
    /// Parse a pin file strictly (closed fields, no duplicate key, no null,
    /// integers only). The contract and digest construction must be exactly
    /// the ones this loader implements.
    pub fn parse(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let value = parse_strict(bytes, &ParseLimits::default()).map_err(|_| bad("pin"))?;
        let root = object(
            &value,
            "pin",
            &["contract", "release", "schema", "snapshot"],
        )?;
        if root.get("schema").and_then(Value::as_str) != Some(PIN_SCHEMA) {
            return Err(bad("schema"));
        }
        let contract = object(
            &root["contract"],
            "contract",
            &["digestSpec", "name", "version"],
        )?;
        if text(contract, "name", "contract")? != CONTRACT_NAME
            || text(contract, "version", "contract")? != CONTRACT_VERSION
            || text(contract, "digestSpec", "contract")? != DIGEST_SPEC
        {
            return Err(bad("contract"));
        }
        let snap = object(
            &root["snapshot"],
            "snapshot",
            &[
                "contentDigest",
                "id",
                "manifestSha256",
                "sourceManifestDigest",
            ],
        )?;
        let rel = object(
            &root["release"],
            "release",
            &["archive", "commit", "repository", "tag"],
        )?;
        let arc = object(
            &rel["archive"],
            "release.archive",
            &["name", "tarGzSha256", "tarSha256"],
        )?;
        let commit = text(rel, "commit", "release")?;
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(bad("release.commit"));
        }
        Ok(Self {
            id: text(snap, "id", "snapshot")?,
            manifest_sha256: digest(snap, "manifestSha256", "snapshot")?,
            content_digest: digest(snap, "contentDigest", "snapshot")?,
            source_manifest_digest: digest(snap, "sourceManifestDigest", "snapshot")?,
            release: ReleasePin {
                repository: text(rel, "repository", "release")?,
                tag: text(rel, "tag", "release")?,
                commit,
                archive: ArchivePin {
                    name: text(arc, "name", "release.archive")?,
                    tar_gz_sha256: digest(arc, "tarGzSha256", "release.archive")?,
                    tar_sha256: digest(arc, "tarSha256", "release.archive")?,
                },
            },
        })
    }
}
