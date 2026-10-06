//! Stable reason codes and bounded, safe error metadata.
//!
//! A [`ContractError`] never carries input text, identifiers taken from the
//! input, scanner output or filesystem paths. Its location is a structural
//! path built only from this crate's field names and array indices, and its
//! metadata is numeric. Human-readable text is derived from the code and is
//! not semantic evidence.

use std::fmt;

use crate::limits::{MAX_PATH_BYTES, MAX_VIOLATIONS};

macro_rules! reason_codes {
    ($($(#[$doc:meta])* $variant:ident => $text:literal),+ $(,)?) => {
        /// Stable, machine-readable reason a contract was rejected.
        ///
        /// The string form is part of the contract: codes are never renamed or
        /// reused; a retired code stays reserved (ADR 0002).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ReasonCode {
            $($(#[$doc])* $variant),+
        }

        impl ReasonCode {
            /// Every code, in declaration order.
            pub const ALL: &'static [ReasonCode] = &[$(ReasonCode::$variant),+];

            /// The stable kebab-case string for this code.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ReasonCode::$variant => $text),+
                }
            }
        }
    };
}

reason_codes! {
    // Parsing and canonical form.
    /// The bytes are not one well-formed JSON document.
    MalformedJson => "malformed-json",
    /// The document exceeds the byte limit.
    DocumentTooLarge => "document-too-large",
    /// The document nests deeper than the limit.
    NestingTooDeep => "nesting-too-deep",
    /// An object repeats a key.
    DuplicateKey => "duplicate-key",
    /// A `null` appeared; contracts use absence, never `null`.
    NullNotAllowed => "null-not-allowed",
    /// A non-integer number (or negative zero) appeared; contracts carry no floats.
    FloatNotAllowed => "float-not-allowed",
    /// An integer exceeds the safe-integer range.
    IntegerOutOfRange => "integer-out-of-range",
    // Envelope and versions.
    /// The document root is not an object.
    NotAnObject => "not-an-object",
    /// `schema` is missing or not a string.
    MissingSchema => "missing-schema",
    /// `schema` names no known document kind.
    UnknownSchema => "unknown-schema",
    /// `schema` names a different document kind than the one requested.
    SchemaKindMismatch => "schema-kind-mismatch",
    /// `schemaVersion` is missing or not `<major>.<minor>`.
    MalformedSchemaVersion => "malformed-schema-version",
    /// `schemaVersion` has a major version this reader does not support.
    IncompatibleSchemaMajor => "incompatible-schema-major",
    /// `schemaVersion` has a minor version newer than this reader.
    SchemaMinorTooNew => "schema-minor-too-new",
    /// The document does not match the typed schema (unknown or missing field,
    /// wrong type, unknown enum value).
    SchemaViolation => "schema-violation",
    /// A string identifier does not match its required format.
    InvalidIdentifier => "invalid-identifier",
    /// The declared semantic digest does not match the recomputed digest.
    SemanticDigestMismatch => "semantic-digest-mismatch",
    // Structure.
    /// A collection or value exceeds a stated limit.
    LimitExceeded => "limit-exceeded",
    /// Two entries share an identity that must be unique.
    DuplicateIdentity => "duplicate-identity",
    /// A collection is not in canonical ascending order.
    NonCanonicalOrder => "non-canonical-order",
    /// A collection that must not be empty is empty.
    EmptyCollection => "empty-collection",
    /// A byte range is empty or inverted (`start >= end`).
    RangeInvalid => "range-invalid",
    /// A byte range extends past the end of its text.
    RangeOutOfBounds => "range-out-of-bounds",
    /// A byte range starts or ends inside a UTF-8 character.
    RangeNotOnCharBoundary => "range-not-on-char-boundary",
    /// A scaled decimal is not in normalized form or is out of range.
    DecimalInvalid => "decimal-invalid",
    /// A variant digest does not match its text.
    TextDigestMismatch => "text-digest-mismatch",
    /// Derivation fields contradict the declared strategy.
    DerivationInvalid => "derivation-invalid",
    /// A family scope disagrees with the case jurisdiction.
    FamilyScopeMismatch => "family-scope-mismatch",
    /// A context-discrimination case does not hold at least one frame in every context class (ADR 0008).
    IncompleteContextTrio => "incomplete-context-trio",
    /// A collision declaration and the case method disagree, or it is malformed.
    CollisionInvalid => "collision-invalid",
    /// Execution limits are zero or exceed the allowed bound.
    LimitsInvalid => "limits-invalid",
    /// Accounting mechanics are outside their allowed range.
    MechanicsInvalid => "mechanics-invalid",
    /// Product identity fields are inconsistent (for example a candidate without a digest).
    ProductIdentityInvalid => "product-identity-invalid",
    /// Variant expectations disagree on the context class.
    ContextClassConflict => "context-class-conflict",
    /// Diagnostics are out of order, unbounded or self-contradictory.
    DiagnosticsInvalid => "diagnostics-invalid",
    // Bindings.
    /// Population id, version or digest differ between documents.
    PopulationBindingMismatch => "population-binding-mismatch",
    /// The run class differs from the population visibility.
    RunClassMismatch => "run-class-mismatch",
    /// Language or jurisdiction is outside the declared scope.
    ScopeViolation => "scope-violation",
    /// Generator or seed derivation differs between plan and snapshot.
    GenerationBindingMismatch => "generation-binding-mismatch",
    /// Engine identity differs between documents.
    EngineBindingMismatch => "engine-binding-mismatch",
    /// Protocol, method or metric identity or version differs from the frozen registry or plan.
    ProtocolBindingMismatch => "protocol-binding-mismatch",
    /// A scanner is not part of the plan.
    UnknownScanner => "unknown-scanner",
    /// Scanner, adapter, configuration or activation identity differs from the plan.
    ConfigurationBindingMismatch => "configuration-binding-mismatch",
    /// A configuration or activation digest does not match its content.
    ConfigurationDigestMismatch => "configuration-digest-mismatch",
    /// An observation refers to a variant that the snapshot does not contain.
    UnknownVariant => "unknown-variant",
    /// An observation's input digest differs from the snapshot variant.
    InputDigestMismatch => "input-digest-mismatch",
    /// A complete observation set misses a variant, or an artifact misses a scanner-by-occurrence row.
    ObservationIncomplete => "observation-incomplete",
    /// A scanner status contradicts its inputs, replays or capabilities.
    StatusInconsistent => "status-inconsistent",
    /// A finding claims something the declared capabilities say the scanner cannot do.
    CapabilityContradiction => "capability-contradiction",
    // Outcomes and accounting.
    /// An outcome state contradicts its expectation or the scanner status.
    OutcomeContradiction => "outcome-contradiction",
    /// Metric counts do not satisfy the accounting identities.
    MetricCountsInconsistent => "metric-counts-inconsistent",
    /// A metric value contradicts its counts, mechanics or definition.
    MetricValueInconsistent => "metric-value-inconsistent",
    /// A metric result differs from the frozen metric definition.
    MetricDefinitionMismatch => "metric-definition-mismatch",
    /// A counter overflowed or a count disagrees with the rows it summarizes.
    CountMismatch => "count-mismatch",
    // Publication.
    /// A protected-class record cannot be projected into a public-synthetic artifact.
    PublicProjectionForbidden => "public-projection-forbidden",
    // Not-established identity (schema 1.3, ADR 0017).
    /// An authored `not-established` type identity, or its `unresolved`
    /// observation, is declared under a schema older than 1.3.
    IdentityNotEstablishedGate => "identity-not-established-gate",
    // Product projection (schema 1.2, ADR 0016).
    /// The product-projection block is malformed: declared under a schema or
    /// protocol that has no such block, a row for a view the roster did not
    /// require, or rows of mixed modes.
    ProjectionInvalid => "projection-invalid",
    /// A required view has no row for a scanner.
    ProjectionViewMissing => "projection-view-missing",
    /// A projection row's scanner, configuration, activation, product or
    /// population binding differs from the artifact that holds it.
    ProjectionBindingMismatch => "projection-binding-mismatch",
    /// A projection row or stratum counts more cases than it holds, or the rows
    /// of one scanner add up to more than the population: a denominator was pooled.
    ProjectionPooledDenominator => "projection-pooled-denominator",
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded numeric metadata. Numbers only: nothing here can echo input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Meta {
    /// The limit that was exceeded, when the code concerns a limit.
    pub limit: Option<u64>,
    /// The observed value, when the code concerns a limit or a count.
    pub actual: Option<u64>,
    /// One-based line in the input document, for parse-level errors.
    pub line: Option<u64>,
    /// One-based column in the input document, for parse-level errors.
    pub column: Option<u64>,
}

impl Meta {
    /// No metadata.
    pub const NONE: Meta = Meta {
        limit: None,
        actual: None,
        line: None,
        column: None,
    };

    /// Metadata for a limit violation.
    pub const fn limit(limit: u64, actual: u64) -> Meta {
        Meta {
            limit: Some(limit),
            actual: Some(actual),
            line: None,
            column: None,
        }
    }

    /// Metadata for a parse position.
    pub const fn position(line: u64, column: u64) -> Meta {
        Meta {
            limit: None,
            actual: None,
            line: Some(line),
            column: Some(column),
        }
    }
}

/// One rejection: a stable code, a structural location and numeric metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    /// Why the input was rejected.
    pub code: ReasonCode,
    /// JSON-pointer-like location built from field names and indices only.
    pub path: String,
    /// Bounded numeric metadata.
    pub meta: Meta,
}

impl ContractError {
    /// An error at the document root.
    pub fn root(code: ReasonCode) -> Self {
        Self {
            code,
            path: String::new(),
            meta: Meta::NONE,
        }
    }

    /// An error at the document root with metadata.
    pub fn root_with(code: ReasonCode, meta: Meta) -> Self {
        Self {
            code,
            path: String::new(),
            meta,
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if !self.path.is_empty() {
            write!(f, " at {}", self.path)?;
        }
        if let (Some(limit), Some(actual)) = (self.meta.limit, self.meta.actual) {
            write!(f, " (limit {limit}, actual {actual})")?;
        }
        if let (Some(line), Some(column)) = (self.meta.line, self.meta.column) {
            write!(f, " (line {line}, column {column})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ContractError {}

/// A bounded list of rejections from one validation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations {
    /// Collected errors, at most [`MAX_VIOLATIONS`].
    pub errors: Vec<ContractError>,
    /// True when further violations were dropped after the bound.
    pub truncated: bool,
}

impl Violations {
    /// A single-error result.
    pub fn single(error: ContractError) -> Self {
        Self {
            errors: vec![error],
            truncated: false,
        }
    }

    /// The first (and for parse failures, only) reason code.
    pub fn first_code(&self) -> Option<ReasonCode> {
        self.errors.first().map(|e| e.code)
    }

    /// True when any collected error has this code.
    pub fn contains(&self, code: ReasonCode) -> bool {
        self.errors.iter().any(|e| e.code == code)
    }
}

impl fmt::Display for Violations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.errors.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{e}")?;
        }
        if self.truncated {
            f.write_str("; (further violations omitted)")?;
        }
        Ok(())
    }
}

impl std::error::Error for Violations {}

impl From<ContractError> for Violations {
    fn from(error: ContractError) -> Self {
        Violations::single(error)
    }
}

#[derive(Debug, Clone, Copy)]
enum Seg {
    Root,
    Field(&'static str),
    Index(usize),
}

/// Structural location under construction. Cheap to extend, rendered only when
/// an error is recorded.
#[derive(Debug, Clone, Copy)]
pub struct Path<'a> {
    parent: Option<&'a Path<'a>>,
    seg: Seg,
}

impl Path<'static> {
    /// The document root.
    pub const ROOT: Path<'static> = Path {
        parent: None,
        seg: Seg::Root,
    };
}

impl<'a> Path<'a> {
    /// A child addressed by a field name of this crate's types.
    pub fn field<'b>(&'b self, name: &'static str) -> Path<'b> {
        Path {
            parent: Some(self),
            seg: Seg::Field(name),
        }
    }

    /// A child addressed by array index.
    pub fn index<'b>(&'b self, index: usize) -> Path<'b> {
        Path {
            parent: Some(self),
            seg: Seg::Index(index),
        }
    }

    fn render_into(&self, out: &mut String) {
        if let Some(parent) = self.parent {
            parent.render_into(out);
        }
        match self.seg {
            Seg::Root => {}
            Seg::Field(name) => {
                out.push('/');
                out.push_str(name);
            }
            Seg::Index(i) => {
                out.push('/');
                out.push_str(&i.to_string());
            }
        }
    }

    /// Render as a JSON-pointer-like string, truncated to [`MAX_PATH_BYTES`].
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        if out.len() > MAX_PATH_BYTES {
            // Paths consist of ASCII field names and digits, so any byte index
            // is a character boundary.
            out.truncate(MAX_PATH_BYTES);
        }
        out
    }
}

/// Accumulates violations up to [`MAX_VIOLATIONS`].
#[derive(Debug, Default)]
pub struct Collector {
    errors: Vec<ContractError>,
    truncated: bool,
}

impl Collector {
    /// An empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a violation at `path`.
    pub fn push(&mut self, code: ReasonCode, path: &Path<'_>) {
        self.push_with(code, path, Meta::NONE);
    }

    /// Record a violation with metadata.
    pub fn push_with(&mut self, code: ReasonCode, path: &Path<'_>, meta: Meta) {
        if self.errors.len() >= MAX_VIOLATIONS {
            self.truncated = true;
            return;
        }
        self.errors.push(ContractError {
            code,
            path: path.render(),
            meta,
        });
    }

    /// True when nothing was recorded.
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// True when the bound was reached; callers may stop early.
    pub fn is_full(&self) -> bool {
        self.truncated
    }

    /// Finish: `Ok` when clean, otherwise the collected violations.
    pub fn finish(self) -> Result<(), Violations> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(Violations {
                errors: self.errors,
                truncated: self.truncated,
            })
        }
    }
}
