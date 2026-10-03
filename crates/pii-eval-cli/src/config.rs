//! The run configuration (`pii-eval-run-config/1`) and the custodian job
//! context (`pii-eval-job-context/1`), parsed strictly from JSON (ADR 0010).
//!
//! Both are closed: an unknown field, a repeated key, `null`, a float or a wrong
//! type is `config-invalid` naming the field. Errors never echo a value.
//! Relative paths in a configuration are resolved against the directory that
//! holds the configuration file, so a checked-out example runs from anywhere.

use std::path::{Path, PathBuf};

use pii_eval_adapters::redact_secret::{PINNED_VERSION, REAL_ENTRY_RELATIVE};
use pii_eval_contracts::{Id, ParseLimits, RunClass, Sha256Digest, VersionString, parse_strict};
use serde_json::{Map, Value};

use crate::exec::ResourcePolicy;
use crate::status::{Exit, Failure, reason};
use crate::write::OverwritePolicy;

/// `schema` of a run configuration.
pub const CONFIG_SCHEMA: &str = "pii-eval-run-config/1";
/// `schema` of a job context.
pub const JOB_CONTEXT_SCHEMA: &str = "pii-eval-job-context/1";
/// Largest configuration or job-context file, in bytes.
pub const MAX_CONFIG_BYTES: usize = 1 << 20;
/// The only adapter kind this release can build.
pub const ADAPTER_REDACT_SECRET_CORE: &str = "redact-secret-core";

/// Exploratory or official.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Local investigation: identity pins are optional (checked when present),
    /// resource limits may be unenforced.
    Exploratory,
    /// A run whose artifact may be cited: every identity is pinned, resource
    /// limits are enforced, an existing result is never replaced.
    Official,
}

impl Mode {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Exploratory => "exploratory",
            Mode::Official => "official",
        }
    }
}

/// Released or candidate product identity (independent of the run class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductKind {
    /// The released package.
    Released,
    /// A candidate build identified by its package digest.
    Candidate,
}

impl ProductKind {
    /// Stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProductKind::Released => "released",
            ProductKind::Candidate => "candidate",
        }
    }
}

/// A file and, optionally, the semantic digest it must have.
#[derive(Debug, Clone)]
pub struct PinnedDocument {
    /// Resolved path.
    pub path: PathBuf,
    /// Pinned semantic digest.
    pub digest: Option<Sha256Digest>,
}

/// A further pinned file or tree (for example a native addon).
#[derive(Debug, Clone)]
pub struct ExtraPin {
    /// Resolved path.
    pub path: PathBuf,
    /// `true` for a directory tree.
    pub tree: bool,
    /// Pinned digest.
    pub sha256: Sha256Digest,
}

/// One scanner of the run.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// `node`, when given in the file (the command line may override it).
    pub node: Option<PathBuf>,
    /// The shim file.
    pub shim: PathBuf,
    /// The scanner package directory.
    pub package_dir: PathBuf,
    /// Entry file relative to the package directory.
    pub entry: PathBuf,
    /// Package version (candidate) or the released version.
    pub version: VersionString,
    /// Package tree digest. Required for a candidate; for a released package it
    /// must be the released digest when given.
    pub tree_sha256: Option<Sha256Digest>,
    /// Further pinned artifacts.
    pub extra: Vec<ExtraPin>,
    /// Startup timeout of one scanner process, milliseconds.
    pub startup_timeout_ms: Option<u64>,
    /// Timeout of one scan call, milliseconds.
    pub call_timeout_ms: Option<u64>,
}

/// Host-side execution settings (they never enter the manifest or a digest).
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Hard cap on concurrent sessions.
    pub max_workers: usize,
    /// Resource enforcement.
    pub resources: ResourcePolicy,
    /// Attach non-semantic diagnostics (timestamps, timings).
    pub diagnostics: bool,
    /// Parent of the run's scratch directories.
    pub scratch_dir: Option<PathBuf>,
    /// Smallest memory share per session, bytes.
    pub min_session_memory_bytes: Option<u64>,
}

/// Where the run's documents go.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output directory (the command line may override it).
    pub dir: Option<PathBuf>,
    /// What to do when a destination file exists.
    pub overwrite: OverwritePolicy,
}

/// A parsed run configuration.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Exploratory or official.
    pub mode: Mode,
    /// The run class the operator claims; must equal the manifest's.
    pub run_class: RunClass,
    /// Released or candidate; must equal every scanner identity's.
    pub product: ProductKind,
    /// Engine version the operator expects.
    pub engine_version: Option<String>,
    /// Protocol `(id, revision)` the operator expects.
    pub protocol: Option<(String, u32)>,
    /// The population.
    pub snapshot: PinnedDocument,
    /// The plan.
    pub manifest: PinnedDocument,
    /// The scanners, in any order (matched to the manifest by identity).
    pub scanners: Vec<ScannerConfig>,
    /// Host settings.
    pub host: HostConfig,
    /// Output settings.
    pub output: OutputConfig,
}

// ---------------------------------------------------------------------------
// Strict field access
// ---------------------------------------------------------------------------

struct Fields<'a> {
    map: &'a Map<String, Value>,
    at: String,
}

fn bad(field: &str) -> Failure {
    Failure::config(field)
}

impl<'a> Fields<'a> {
    fn of(value: &'a Value, at: &str, allowed: &[&str]) -> Result<Self, Failure> {
        let map = value.as_object().ok_or_else(|| bad(at))?;
        if map.keys().any(|k| !allowed.contains(&k.as_str())) {
            return Err(bad(&format!("{at} (unknown field)")));
        }
        Ok(Self {
            map,
            at: at.to_owned(),
        })
    }

    fn name(&self, key: &str) -> String {
        if self.at.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", self.at)
        }
    }

    fn get(&self, key: &str) -> Option<&'a Value> {
        self.map.get(key)
    }

    fn req(&self, key: &str) -> Result<&'a Value, Failure> {
        self.get(key).ok_or_else(|| bad(&self.name(key)))
    }

    fn str(&self, key: &str) -> Result<&'a str, Failure> {
        self.req(key)?.as_str().ok_or_else(|| bad(&self.name(key)))
    }

    fn opt_str(&self, key: &str) -> Result<Option<&'a str>, Failure> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v.as_str().map(Some).ok_or_else(|| bad(&self.name(key))),
        }
    }

    fn opt_u64(&self, key: &str) -> Result<Option<u64>, Failure> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v.as_u64().map(Some).ok_or_else(|| bad(&self.name(key))),
        }
    }

    fn opt_bool(&self, key: &str) -> Result<Option<bool>, Failure> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v.as_bool().map(Some).ok_or_else(|| bad(&self.name(key))),
        }
    }

    fn digest(&self, key: &str) -> Result<Sha256Digest, Failure> {
        Sha256Digest::new(self.str(key)?).map_err(|_| bad(&self.name(key)))
    }

    fn opt_digest(&self, key: &str) -> Result<Option<Sha256Digest>, Failure> {
        match self.opt_str(key)? {
            None => Ok(None),
            Some(s) => Sha256Digest::new(s)
                .map(Some)
                .map_err(|_| bad(&self.name(key))),
        }
    }

    fn path(&self, key: &str, base: &Path) -> Result<PathBuf, Failure> {
        resolve(self.str(key)?, base).ok_or_else(|| bad(&self.name(key)))
    }

    fn opt_path(&self, key: &str, base: &Path) -> Result<Option<PathBuf>, Failure> {
        match self.opt_str(key)? {
            None => Ok(None),
            Some(s) => resolve(s, base)
                .map(Some)
                .ok_or_else(|| bad(&self.name(key))),
        }
    }

    fn sub(&self, key: &str, allowed: &[&str]) -> Result<Fields<'a>, Failure> {
        Fields::of(self.req(key)?, &self.name(key), allowed)
    }

    fn opt_sub(&self, key: &str, allowed: &[&str]) -> Result<Option<Fields<'a>>, Failure> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => Fields::of(v, &self.name(key), allowed).map(Some),
        }
    }
}

/// Resolve a configured path: relative paths are relative to `base`. Empty
/// strings and strings with a NUL are not paths.
fn resolve(text: &str, base: &Path) -> Option<PathBuf> {
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    let p = Path::new(text);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    })
}

fn parse_json(bytes: &[u8], what: &'static str) -> Result<Value, Failure> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(Failure::new(Exit::Invalid, reason::INPUT_TOO_LARGE).with_detail(what));
    }
    parse_strict(
        bytes,
        &ParseLimits {
            max_bytes: MAX_CONFIG_BYTES,
            max_depth: 16,
        },
    )
    .map_err(|e| {
        Failure::new(Exit::Invalid, reason::CONFIG_INVALID)
            .with_detail(what)
            .with_codes([e.code])
    })
}

impl RunConfig {
    /// Parse a configuration file's bytes. `base` is the directory relative
    /// paths resolve against.
    pub fn parse(bytes: &[u8], base: &Path) -> Result<Self, Failure> {
        let value = parse_json(bytes, "run-config")?;
        let top = Fields::of(
            &value,
            "",
            &[
                "schema",
                "mode",
                "runClass",
                "product",
                "engineVersion",
                "protocol",
                "snapshot",
                "manifest",
                "scanners",
                "host",
                "output",
            ],
        )?;
        if top.str("schema")? != CONFIG_SCHEMA {
            return Err(bad("schema"));
        }
        let mode = match top.str("mode")? {
            "exploratory" => Mode::Exploratory,
            "official" => Mode::Official,
            _ => return Err(bad("mode")),
        };
        let run_class = match top.str("runClass")? {
            "public-synthetic" => RunClass::PublicSynthetic,
            "protected" => RunClass::Protected,
            _ => return Err(bad("runClass")),
        };
        let product = match top.str("product")? {
            "released" => ProductKind::Released,
            "candidate" => ProductKind::Candidate,
            _ => return Err(bad("product")),
        };
        let engine_version = top.opt_str("engineVersion")?.map(str::to_owned);
        let protocol = match top.opt_sub("protocol", &["id", "revision"])? {
            None => None,
            Some(p) => {
                let revision = p
                    .req("revision")?
                    .as_u64()
                    .and_then(|r| u32::try_from(r).ok())
                    .ok_or_else(|| bad("protocol.revision"))?;
                Some((p.str("id")?.to_owned(), revision))
            }
        };
        let pinned = |key: &str| -> Result<PinnedDocument, Failure> {
            let f = top.sub(key, &["path", "semanticDigest"])?;
            Ok(PinnedDocument {
                path: f.path("path", base)?,
                digest: f.opt_digest("semanticDigest")?,
            })
        };
        let snapshot = pinned("snapshot")?;
        let manifest = pinned("manifest")?;

        let scanner_values = top
            .req("scanners")?
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= pii_eval_contracts::limits::MAX_SCANNERS)
            .ok_or_else(|| bad("scanners"))?;
        let mut scanners = Vec::new();
        for (i, v) in scanner_values.iter().enumerate() {
            scanners.push(parse_scanner(v, &format!("scanners[{i}]"), base)?);
        }

        let host = top.sub(
            "host",
            &[
                "maxWorkers",
                "resources",
                "diagnostics",
                "scratchDir",
                "minSessionMemoryBytes",
            ],
        )?;
        let max_workers = host
            .req("maxWorkers")?
            .as_u64()
            .filter(|n| {
                (1..=u64::from(pii_eval_contracts::limits::execution::MAX_WORKERS)).contains(n)
            })
            .ok_or_else(|| bad("host.maxWorkers"))? as usize;
        let resources = match host.str("resources")? {
            "enforce" => ResourcePolicy::Enforce,
            "unenforced" => ResourcePolicy::Unenforced,
            _ => return Err(bad("host.resources")),
        };
        let host = HostConfig {
            max_workers,
            resources,
            diagnostics: host.opt_bool("diagnostics")?.unwrap_or(false),
            scratch_dir: host.opt_path("scratchDir", base)?,
            min_session_memory_bytes: host.opt_u64("minSessionMemoryBytes")?,
        };

        let output = match top.opt_sub("output", &["dir", "overwrite"])? {
            None => OutputConfig {
                dir: None,
                overwrite: OverwritePolicy::Refuse,
            },
            Some(o) => OutputConfig {
                dir: o.opt_path("dir", base)?,
                overwrite: match o.opt_str("overwrite")? {
                    None | Some("refuse") => OverwritePolicy::Refuse,
                    Some("replace") => OverwritePolicy::Replace,
                    Some(_) => return Err(bad("output.overwrite")),
                },
            },
        };

        let config = RunConfig {
            mode,
            run_class,
            product,
            engine_version,
            protocol,
            snapshot,
            manifest,
            scanners,
            host,
            output,
        };
        config.check_mode_rules()?;
        Ok(config)
    }

    /// The rules that make a run official (and a protected run official).
    fn check_mode_rules(&self) -> Result<(), Failure> {
        let official = self.mode == Mode::Official;
        if official || self.run_class == RunClass::Protected {
            let missing = |field: &str| Err(bad(&format!("{field} (required)")));
            if self.engine_version.is_none() {
                return missing("engineVersion");
            }
            if self.protocol.is_none() {
                return missing("protocol");
            }
            if self.snapshot.digest.is_none() {
                return missing("snapshot.semanticDigest");
            }
            if self.manifest.digest.is_none() {
                return missing("manifest.semanticDigest");
            }
            if self.host.resources != ResourcePolicy::Enforce {
                return Err(bad("host.resources (must be enforce)"));
            }
            if self.output.overwrite != OverwritePolicy::Refuse {
                return Err(bad("output.overwrite (must be refuse)"));
            }
        }
        if self.run_class == RunClass::Protected && !official {
            return Err(bad("mode (a protected run is official)"));
        }
        Ok(())
    }
}

fn parse_scanner(value: &Value, at: &str, base: &Path) -> Result<ScannerConfig, Failure> {
    let f = Fields::of(
        value,
        at,
        &[
            "adapter",
            "node",
            "shim",
            "package",
            "extraArtifacts",
            "limits",
        ],
    )?;
    if f.str("adapter")? != ADAPTER_REDACT_SECRET_CORE {
        return Err(bad(&f.name("adapter")));
    }
    let shim = f.sub("shim", &["path"])?.path("path", base)?;
    let package = f.sub("package", &["dir", "entry", "treeSha256", "version"])?;
    let entry = package
        .opt_str("entry")?
        .unwrap_or(REAL_ENTRY_RELATIVE)
        .to_owned();
    let entry_path = Path::new(&entry);
    let entry_ok = !entry.is_empty()
        && !entry.contains('\0')
        && entry_path.is_relative()
        && entry_path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !entry_ok {
        return Err(bad(&package.name("entry")));
    }
    let version = match package.opt_str("version")? {
        None => PINNED_VERSION,
        Some(v) => v,
    };
    let version = VersionString::new(version).map_err(|_| bad(&package.name("version")))?;
    let mut extra = Vec::new();
    if let Some(list) = f.get("extraArtifacts") {
        let list = list
            .as_array()
            .filter(|a| a.len() <= 16)
            .ok_or_else(|| bad(&f.name("extraArtifacts")))?;
        for (i, v) in list.iter().enumerate() {
            let e = Fields::of(
                v,
                &format!("{}[{i}]", f.name("extraArtifacts")),
                &["path", "target", "sha256"],
            )?;
            extra.push(ExtraPin {
                path: e.path("path", base)?,
                tree: match e.str("target")? {
                    "file" => false,
                    "tree" => true,
                    _ => return Err(bad(&e.name("target"))),
                },
                sha256: e.digest("sha256")?,
            });
        }
    }
    let (startup, call) = match f.opt_sub("limits", &["startupTimeoutMs", "callTimeoutMs"])? {
        None => (None, None),
        Some(l) => (l.opt_u64("startupTimeoutMs")?, l.opt_u64("callTimeoutMs")?),
    };
    Ok(ScannerConfig {
        node: f.opt_path("node", base)?,
        shim,
        package_dir: package.path("dir", base)?,
        entry: PathBuf::from(entry),
        version,
        tree_sha256: package.opt_digest("treeSha256")?,
        extra,
        startup_timeout_ms: startup,
        call_timeout_ms: call,
    })
}

// ---------------------------------------------------------------------------
// Job context
// ---------------------------------------------------------------------------

/// The custodian-supplied description of one protected job. The CLI validates
/// it and binds the run to it; it **grants no access**: it cannot make an
/// unreadable path readable, and a context that validates is not an
/// authorization decision (the custodian's isolation is).
#[derive(Debug, Clone)]
pub struct JobContext {
    /// Custodian job identifier.
    pub job_id: Id,
    /// Custodian identifier.
    pub custodian: Id,
    /// Semantic digest of the snapshot the job is for.
    pub population_digest: Sha256Digest,
    /// Semantic digest of the manifest the job is for.
    pub manifest_digest: Sha256Digest,
    /// Candidate digest, for a candidate product.
    pub candidate_digest: Option<Sha256Digest>,
    /// Canonical directory protected inputs must lie inside.
    pub input_root: PathBuf,
    /// Canonical directory the output directory must lie inside.
    pub output_root: PathBuf,
}

impl JobContext {
    /// Read and validate a job-context file: a regular file the group and
    /// others cannot write (Unix), at most [`MAX_CONFIG_BYTES`], strict JSON,
    /// closed fields, existing absolute directories.
    pub fn load(path: &Path) -> Result<Self, Failure> {
        let invalid = |detail: &str| {
            Failure::new(Exit::ProtectedContext, reason::PROTECTED_CONTEXT_INVALID)
                .with_detail(detail)
        };
        let meta = std::fs::metadata(path).map_err(|_| invalid("unreadable"))?;
        if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES as u64 {
            return Err(invalid("not-a-regular-file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o022 != 0 {
                return Err(invalid("writable-by-others"));
            }
        }
        let bytes = std::fs::read(path).map_err(|_| invalid("unreadable"))?;
        let value = parse_json(&bytes, "job-context").map_err(|_| invalid("malformed"))?;
        let f = Fields::of(
            &value,
            "",
            &[
                "schema",
                "jobId",
                "custodian",
                "runClass",
                "populationDigest",
                "manifestDigest",
                "candidateDigest",
                "inputRoot",
                "outputRoot",
            ],
        )
        .map_err(|_| invalid("closed-fields"))?;
        fn field<T>(
            r: Result<T, Failure>,
            name: &str,
            invalid: &dyn Fn(&str) -> Failure,
        ) -> Result<T, Failure> {
            r.map_err(|_| invalid(name))
        }
        if field(f.str("schema"), "schema", &invalid)? != JOB_CONTEXT_SCHEMA {
            return Err(invalid("schema"));
        }
        if field(f.str("runClass"), "runClass", &invalid)? != "protected" {
            return Err(invalid("runClass"));
        }
        let id = |key: &str| -> Result<Id, Failure> {
            Id::new(field(f.str(key), key, &invalid)?).map_err(|_| invalid(key))
        };
        let root = |key: &str| -> Result<PathBuf, Failure> {
            let text = field(f.str(key), key, &invalid)?;
            let p = Path::new(text);
            if !p.is_absolute() || text.contains('\0') {
                return Err(invalid(key));
            }
            std::fs::canonicalize(p)
                .ok()
                .filter(|c| c.is_dir())
                .ok_or_else(|| invalid(key))
        };
        Ok(JobContext {
            job_id: id("jobId")?,
            custodian: id("custodian")?,
            population_digest: field(f.digest("populationDigest"), "populationDigest", &invalid)?,
            manifest_digest: field(f.digest("manifestDigest"), "manifestDigest", &invalid)?,
            candidate_digest: field(f.opt_digest("candidateDigest"), "candidateDigest", &invalid)?,
            input_root: root("inputRoot")?,
            output_root: root("outputRoot")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn config(extra: &str) -> String {
        format!(
            r#"{{"schema":"{CONFIG_SCHEMA}","mode":"exploratory","runClass":"public-synthetic",
"product":"candidate","snapshot":{{"path":"s.json"}},"manifest":{{"path":"m.json"}},
"scanners":[{{"adapter":"redact-secret-core","shim":{{"path":"shim.mjs"}},
"package":{{"dir":"pkg","entry":"lib/index.js","treeSha256":"{D}","version":"0.1.0-beta.12"}}}}],
"host":{{"maxWorkers":2,"resources":"enforce"}}{extra}}}"#
        )
    }

    #[test]
    fn a_valid_configuration_parses_and_resolves_paths_against_the_base() {
        let c = RunConfig::parse(config("").as_bytes(), Path::new("/base")).unwrap();
        assert_eq!(c.snapshot.path, Path::new("/base/s.json"));
        assert_eq!(c.scanners[0].package_dir, Path::new("/base/pkg"));
        assert_eq!(c.mode, Mode::Exploratory);
        assert_eq!(c.output.overwrite, OverwritePolicy::Refuse);
    }

    #[test]
    fn unknown_fields_wrong_types_duplicates_and_nulls_are_rejected_without_echo() {
        let secret = "zq-secret-value-7731";
        let cases = [
            config(&format!(r#","{secret}":1"#)),
            config("").replace("\"maxWorkers\":2", "\"maxWorkers\":\"2\""),
            config("").replace("\"maxWorkers\":2", "\"maxWorkers\":0"),
            config("").replace(
                "\"mode\":\"exploratory\"",
                "\"mode\":\"exploratory\",\"mode\":\"official\"",
            ),
            config("").replace("\"product\":\"candidate\"", "\"product\":null"),
            config("").replace("\"maxWorkers\":2", "\"maxWorkers\":2.5"),
            config("").replace("\"dir\":\"pkg\"", "\"dir\":\"\""),
            config("").replace("lib/index.js", "../escape.js"),
            config("").replace("lib/index.js", "/abs.js"),
            config("").replace(CONFIG_SCHEMA, "pii-eval-run-config/2"),
        ];
        for text in cases {
            let err = RunConfig::parse(text.as_bytes(), Path::new("/b")).unwrap_err();
            assert_eq!(err.exit, Exit::Invalid, "{text}");
            assert!(!err.human().contains(secret));
        }
    }

    #[test]
    fn official_and_protected_runs_require_every_pin() {
        let official = config("").replace("exploratory", "official");
        let err = RunConfig::parse(official.as_bytes(), Path::new("/b")).unwrap_err();
        assert!(err.detail.unwrap().contains("required"));
        let protected = config("").replace("public-synthetic", "protected");
        let err = RunConfig::parse(protected.as_bytes(), Path::new("/b")).unwrap_err();
        assert_eq!(err.reason, reason::CONFIG_INVALID);
    }
}
