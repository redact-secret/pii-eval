//! Indexed accounting of the ten `pii-v1` metrics (canonical accounting rule).
//!
//! Identity: [`ACCOUNTING_RULE_ID`] `pii-v1-canonical-accounting`,
//! protocol revision [`ACCOUNTING_PROTOCOL_REVISION`] 2, next to the matching
//! rule of ADR 0004 and the statistics rule of [`crate::stats`]. Specified in
//! `docs/adr/0005-indexed-accounting-and-metric-statistics.md`.
//!
//! # Model
//!
//! * The **sample** is one authored case within its method, per scanner (the
//!   registry's `authored-case-method`; `context-trio` for the context metric,
//!   `axis-assertion` for `measurable-share`). Variants and expected
//!   occurrences of a case are rows *inside* that sample: they never add
//!   samples. Replays are not rows at all: an observation set carries one
//!   result per scanner and input, and the replay record only says whether the
//!   replays agreed.
//! * Rows are interned once ([`AuthoredIndex`]) into dense indices, and each
//!   outcome row is folded **once** into a 32-bit flag word of its
//!   (scanner, case) group. Every metric of the group is then derived from
//!   that word, and the group is added to the overall tally and to its
//!   language, jurisdiction and method strata. No metric rescans the rows.
//! * A group's outcome per metric is one of five buckets (numerator, other,
//!   unresolved, not-measured, not-applicable), exactly as in the oracle's
//!   `metricBuckets`. Flags are OR-accumulated, so the result cannot depend on
//!   row order, and every counter is a checked `u64` increment.
//!
//! Untrusted rows never panic: every defect (unknown scanner, variant or
//! occurrence, mismatched case or method, duplicate row, unreachable state,
//! missing rows, limits) is a typed [`AccountError`] with numeric payload only.
//!
//! # Differences from the oracle's grouping
//!
//! See ADR 0005 section "Compatibility". In short: eligibility for the
//! valid-type metrics is decided per **occurrence** (a case is eligible when
//! it has a valid-type occurrence and only those occurrences are judged),
//! where the oracle used the first variant after a locale-dependent sort of
//! variant ids; the context metric requires complete trios, which the snapshot
//! contract already guarantees, and an incomplete one is an error instead of
//! being scored partially.

use std::collections::BTreeMap;
use std::fmt;

use pii_eval_contracts::axes::OutcomeRow;
use pii_eval_contracts::limits::{MAX_CASES, MAX_OUTCOMES, MAX_SCANNERS};
use pii_eval_contracts::{
    AxisStatus, CaseOutcome, Collector, ContextClass, CorpusSnapshotBody, EffectiveNBasis,
    ExpectedType, JurisdictionCode, LanguageTag, METHODS, METRICS, Mechanics, MethodId,
    MetricCounts, MetricId, MetricRef, MetricResult, MetricStatus, MetricValue, Path,
    PopulationCounts, PublicOutcome, RangeState, SampleUnit, ScannerId, ScannerStatus,
    SensitivityExpectation, SensitivityState, TypeState,
};

use crate::stats::{StatsError, published_value};

/// Identifier of the canonical accounting rule.
pub const ACCOUNTING_RULE_ID: &str = "pii-v1-canonical-accounting";

/// Protocol revision this accounting rule belongs to: revision 2, bound in
/// every revision-2 document by `ProtocolIdentity::CANONICAL_V2` (ADR 0008).
/// Since ADR 0008 the benign and collision buckets require ALL rows to pass
/// (A8); a test pins that these constants equal the contracts' identities.
pub const ACCOUNTING_PROTOCOL_REVISION: u32 = 2;

/// Most distinct values of one stratum dimension (languages, jurisdictions).
pub const MAX_STRATA_PER_DIMENSION: usize = 1024;

/// How an interval must be read. Part of every [`MetricAccount`] by reference
/// (`SampleBasis::interpretation`).
pub const INTERVAL_INTERPRETATION: &str = "The Wilson endpoint treats each effective-N sample as an independent \
trial. Authored cases are not a random draw from real-world data, variants and axis assertions of one case are \
correlated, and the corpus is synthetic. It is sampling arithmetic conditional on the corpus design, not \
real-world confidence.";

/// A defect of the authored snapshot that makes accounting meaningless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotDefect {
    /// Cases are not strictly ascending by case id.
    CaseOrder,
    /// A case has no variant, or a variant no expected occurrence.
    EmptyGroup,
    /// A variant id appears twice.
    DuplicateVariant,
    /// Occurrence ids of a variant are not strictly ascending.
    OccurrenceOrder,
    /// A context-discrimination case does not hold at least one frame in every context class (ADR 0008).
    IncompleteContextTrio,
    /// A variant's expectations disagree on the context class.
    ContextClassConflict,
}

/// Which bound was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Authored cases.
    Cases,
    /// Expected occurrences (one scanner's rows).
    Occurrences,
    /// Scanners.
    Scanners,
    /// Scanner-by-occurrence rows.
    Rows,
    /// Distinct languages.
    Languages,
    /// Distinct jurisdictions.
    Jurisdictions,
}

/// Why accounting was refused. Numeric payloads only: never text or identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    /// Mechanics outside their allowed range.
    InvalidMechanics,
    /// The authored snapshot is not accountable.
    InvalidSnapshot(SnapshotDefect),
    /// An explicit limit was exceeded.
    TooMany {
        /// Which limit.
        limit: Limit,
        /// Its value.
        max: u64,
        /// The observed value.
        actual: u64,
    },
    /// A scanner id was supplied twice.
    DuplicateScanner,
    /// A row names a scanner that was not supplied (row index).
    UnknownScanner(u64),
    /// A row names a variant or occurrence the snapshot does not contain (row index).
    UnknownOccurrence(u64),
    /// A row's case or method differs from the authored case (row index).
    CaseMismatch(u64),
    /// A second row for the same scanner and occurrence (row index).
    DuplicateRow(u64),
    /// A row's state is unreachable under its authored expectation, or a
    /// scanner that did not complete reports a measured axis (row index).
    OutcomeContradiction(u64),
    /// A scanner has fewer rows than the snapshot has occurrences.
    MissingRows {
        /// Zero-based index of the scanner in ascending id order.
        scanner: u64,
        /// Occurrences in the snapshot.
        expected: u64,
        /// Rows received.
        found: u64,
    },
    /// A counter would exceed `u64` (unreachable within the explicit limits).
    CounterOverflow,
    /// Statistics refused the counts or mechanics.
    Stats(StatsError),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountError::InvalidMechanics => f.write_str("invalid accounting mechanics"),
            AccountError::InvalidSnapshot(d) => write!(f, "snapshot not accountable: {d:?}"),
            AccountError::TooMany { limit, max, actual } => {
                write!(f, "{limit:?} limit {max} exceeded: {actual}")
            }
            AccountError::DuplicateScanner => f.write_str("duplicate scanner"),
            AccountError::UnknownScanner(i) => write!(f, "row {i}: unknown scanner"),
            AccountError::UnknownOccurrence(i) => write!(f, "row {i}: unknown occurrence"),
            AccountError::CaseMismatch(i) => write!(f, "row {i}: case or method mismatch"),
            AccountError::DuplicateRow(i) => write!(f, "row {i}: duplicate"),
            AccountError::OutcomeContradiction(i) => write!(f, "row {i}: contradicts expectation"),
            AccountError::MissingRows {
                scanner,
                expected,
                found,
            } => write!(
                f,
                "scanner {scanner}: expected {expected} rows, found {found}"
            ),
            AccountError::CounterOverflow => f.write_str("counter overflow"),
            AccountError::Stats(e) => write!(f, "statistics: {e:?}"),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<StatsError> for AccountError {
    fn from(e: StatsError) -> Self {
        AccountError::Stats(e)
    }
}

// ---------------------------------------------------------------------------
// Authored index
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct CaseInfo<'a> {
    id: &'a str,
    method: MethodId,
    language: u16,
    jurisdiction: u16,
    variants: u32,
    occurrences: u32,
    has_not_established: bool,
    jurisdictional: bool,
}

#[derive(Debug, Clone, Copy)]
struct OccInfo {
    case: u32,
    expected: ExpectedType,
    sensitivity: SensitivityExpectation,
    endpoint: bool,
}

#[derive(Debug, Clone, Copy)]
struct VariantInfo<'a> {
    first: u32,
    expectations: &'a [pii_eval_contracts::Expectation],
}

/// The authored snapshot interned into dense indices: cases, occurrences and
/// stratum values. Built once per run; read-only afterwards.
#[derive(Debug)]
pub struct AuthoredIndex<'a> {
    cases: Vec<CaseInfo<'a>>,
    occurrences: Vec<OccInfo>,
    variants: BTreeMap<&'a str, VariantInfo<'a>>,
    languages: Vec<&'a LanguageTag>,
    jurisdictions: Vec<Option<&'a JurisdictionCode>>,
    counts: PopulationCounts,
}

fn check_limit(limit: Limit, max: usize, actual: usize) -> Result<(), AccountError> {
    if actual > max {
        Err(AccountError::TooMany {
            limit,
            max: max as u64,
            actual: actual as u64,
        })
    } else {
        Ok(())
    }
}

impl<'a> AuthoredIndex<'a> {
    /// Intern a snapshot body. The body is expected to have passed
    /// `pii_eval_contracts::validate`; the properties accounting relies on are
    /// re-checked here and reported as [`AccountError::InvalidSnapshot`].
    pub fn new(body: &'a CorpusSnapshotBody) -> Result<Self, AccountError> {
        check_limit(Limit::Cases, MAX_CASES, body.cases.len())?;
        let mut languages: BTreeMap<&LanguageTag, ()> = BTreeMap::new();
        let mut jurisdictions: BTreeMap<Option<&JurisdictionCode>, ()> = BTreeMap::new();
        for case in &body.cases {
            languages.insert(&case.language, ());
            jurisdictions.insert(case.jurisdiction.as_ref(), ());
        }
        check_limit(Limit::Languages, MAX_STRATA_PER_DIMENSION, languages.len())?;
        check_limit(
            Limit::Jurisdictions,
            MAX_STRATA_PER_DIMENSION,
            jurisdictions.len(),
        )?;
        let languages: Vec<&LanguageTag> = languages.into_keys().collect();
        // `None` (global) sorts first.
        let jurisdictions: Vec<Option<&JurisdictionCode>> = jurisdictions.into_keys().collect();

        let mut cases: Vec<CaseInfo<'a>> = Vec::with_capacity(body.cases.len());
        let mut occurrences: Vec<OccInfo> = Vec::new();
        let mut variants: BTreeMap<&'a str, VariantInfo<'a>> = BTreeMap::new();
        let mut variant_total = 0u64;
        let mut previous: Option<&str> = None;
        for (ci, case) in body.cases.iter().enumerate() {
            if previous.is_some_and(|p| p >= case.case_id.as_str()) {
                return Err(AccountError::InvalidSnapshot(SnapshotDefect::CaseOrder));
            }
            previous = Some(case.case_id.as_str());
            if case.variants.is_empty() {
                return Err(AccountError::InvalidSnapshot(SnapshotDefect::EmptyGroup));
            }
            let case_occurrences_start = occurrences.len();
            let mut has_not_established = false;
            let mut classes: Vec<ContextClass> = Vec::new();
            for variant in &case.variants {
                if variant.expectations.is_empty() {
                    return Err(AccountError::InvalidSnapshot(SnapshotDefect::EmptyGroup));
                }
                if variant
                    .expectations
                    .windows(2)
                    .any(|w| w[0].occurrence_id >= w[1].occurrence_id)
                {
                    return Err(AccountError::InvalidSnapshot(
                        SnapshotDefect::OccurrenceOrder,
                    ));
                }
                let first =
                    u32::try_from(occurrences.len()).map_err(|_| AccountError::TooMany {
                        limit: Limit::Occurrences,
                        max: MAX_OUTCOMES as u64,
                        actual: occurrences.len() as u64,
                    })?;
                for e in &variant.expectations {
                    has_not_established |= matches!(
                        e.sensitivity,
                        SensitivityExpectation::NotEstablished
                            | SensitivityExpectation::ContextDependent
                    );
                    occurrences.push(OccInfo {
                        case: ci as u32,
                        expected: e.type_expectation,
                        sensitivity: e.sensitivity,
                        endpoint: e.context_class != ContextClass::Neutral,
                    });
                }
                check_limit(Limit::Occurrences, MAX_OUTCOMES, occurrences.len())?;
                // Contracts reject mixed classes (`context-class-conflict`);
                // re-checked so an unvalidated snapshot is never scored.
                if let Some(first) = variant.expectations.first() {
                    if variant
                        .expectations
                        .iter()
                        .any(|e| e.context_class != first.context_class)
                    {
                        return Err(AccountError::InvalidSnapshot(
                            SnapshotDefect::ContextClassConflict,
                        ));
                    }
                    classes.push(first.context_class);
                }
                let info = VariantInfo {
                    first,
                    expectations: &variant.expectations,
                };
                if variants.insert(variant.variant_id.as_str(), info).is_some() {
                    return Err(AccountError::InvalidSnapshot(
                        SnapshotDefect::DuplicateVariant,
                    ));
                }
            }
            if case.method == MethodId::ContextDiscrimination {
                // At least one frame per class (ADR 0008); zero in any class
                // is still an incomplete trio.
                if ![
                    ContextClass::Sensitive,
                    ContextClass::Neutral,
                    ContextClass::NonSensitive,
                ]
                .iter()
                .all(|k| classes.contains(k))
                {
                    return Err(AccountError::InvalidSnapshot(
                        SnapshotDefect::IncompleteContextTrio,
                    ));
                }
            }
            variant_total += case.variants.len() as u64;
            let language = languages
                .binary_search(&&case.language)
                .map_err(|_| AccountError::CounterOverflow)? as u16;
            let jurisdiction = jurisdictions
                .binary_search(&case.jurisdiction.as_ref())
                .map_err(|_| AccountError::CounterOverflow)? as u16;
            cases.push(CaseInfo {
                id: case.case_id.as_str(),
                method: case.method,
                language,
                jurisdiction,
                variants: case.variants.len() as u32,
                occurrences: (occurrences.len() - case_occurrences_start) as u32,
                has_not_established,
                jurisdictional: case.jurisdiction.is_some(),
            });
        }
        let counts = PopulationCounts {
            authored_cases: cases.len() as u64,
            variants: variant_total,
            occurrences: occurrences.len() as u64,
        };
        Ok(Self {
            cases,
            occurrences,
            variants,
            languages,
            jurisdictions,
            counts,
        })
    }

    /// Authored cases, variants and occurrences. Never mixed with effective N.
    pub fn counts(&self) -> PopulationCounts {
        self.counts
    }

    /// Languages present, ascending.
    pub fn languages(&self) -> &[&'a LanguageTag] {
        &self.languages
    }

    /// Jurisdictions present, ascending, with `None` (global) first.
    pub fn jurisdictions(&self) -> &[Option<&'a JurisdictionCode>] {
        &self.jurisdictions
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One outcome row as accounting reads it: identifiers by reference and the
/// four axes. Nothing here can carry text.
#[derive(Debug, Clone, Copy)]
pub struct OutcomeRef<'a> {
    /// Scanner id.
    pub scanner_id: &'a str,
    /// Authored case id.
    pub case_id: &'a str,
    /// Variant id.
    pub variant_id: &'a str,
    /// Occurrence id.
    pub occurrence_id: &'a str,
    /// Method of the case.
    pub method: MethodId,
    /// The four axes.
    pub row: OutcomeRow,
}

impl<'a> From<&'a CaseOutcome> for OutcomeRef<'a> {
    fn from(o: &'a CaseOutcome) -> Self {
        OutcomeRef {
            scanner_id: o.scanner_id.as_str(),
            case_id: o.case_id.as_str(),
            variant_id: o.variant_id.as_str(),
            occurrence_id: o.occurrence_id.as_str(),
            method: o.method,
            row: OutcomeRow {
                type_identity: o.type_identity,
                sensitivity_context: o.sensitivity_context,
                range: o.range,
                action: o.action,
            },
        }
    }
}

impl<'a> From<&'a PublicOutcome> for OutcomeRef<'a> {
    fn from(o: &'a PublicOutcome) -> Self {
        OutcomeRef {
            scanner_id: o.scanner_id.as_str(),
            case_id: o.case_id.as_str(),
            variant_id: o.variant_id.as_str(),
            occurrence_id: o.occurrence_id.as_str(),
            method: o.method,
            row: OutcomeRow {
                type_identity: o.type_identity,
                sensitivity_context: o.sensitivity_context,
                range: o.range,
                action: o.action,
            },
        }
    }
}

/// A scanner whose rows are accounted, with its run status.
#[derive(Debug, Clone, Copy)]
pub struct ScannerInput<'a> {
    /// Scanner id.
    pub id: &'a ScannerId,
    /// Run status; anything but `complete` measured nothing.
    pub status: ScannerStatus,
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/// Why eligible rows are not measured, derived from the scanner status. It
/// distinguishes an unstable scanner and an execution failure from a scanner
/// that completed but could not report an axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmeasuredCause {
    /// The scanner does not support the measured surface.
    ScannerUnsupported,
    /// The scanner could not be run.
    ScannerUnavailable,
    /// Replays disagreed: the observation is not trustworthy.
    ScannerUnstable,
    /// Execution failed (error, timeout, output limit, malformed output, cancellation).
    ExecutionFailure,
    /// The scanner completed but did not report the axis (capability not declared or unsupported).
    AxisNotReported,
}

/// The counts behind one metric's interval and what they are made of. These
/// are kept separate from effective N (`MetricAccount::effective_n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleBasis {
    /// The registry's sample unit.
    pub sample_unit: SampleUnit,
    /// Authored cases (groups) that entered the metric's population.
    pub eligible_cases: u64,
    /// Variants of those cases. Derived variants are not independent samples.
    pub eligible_variants: u64,
    /// Expected occurrences of those cases.
    pub eligible_occurrences: u64,
    /// True when at least one eligible case has more than one variant: the
    /// sample clusters correlated variants.
    pub correlated_variants: bool,
    /// True when one authored case contributes several samples (the two axis
    /// assertions of `measurable-share`).
    pub shared_case_axes: bool,
}

impl SampleBasis {
    /// How to read the interval; see [`INTERVAL_INTERPRETATION`].
    pub const fn interpretation(&self) -> &'static str {
        INTERVAL_INTERPRETATION
    }
}

/// One metric for one scanner and stratum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricAccount {
    /// Metric.
    pub metric: MetricId,
    /// Unrounded counts.
    pub counts: MetricCounts,
    /// Effective N (distinct from authored and variant counts).
    pub effective_n: u64,
    /// Accounting status derived from the counts: unresolved, not-measured and
    /// not-applicable are distinct.
    pub status: MetricStatus,
    /// The published value or the reason it is withheld.
    pub value: MetricValue,
    /// Why eligible rows were not measured, when any were not.
    pub not_measured_cause: Option<UnmeasuredCause>,
    /// Authored, variant and occurrence counts of the eligible population.
    pub basis: SampleBasis,
}

impl MetricAccount {
    /// The contract's metric result for this account.
    pub fn to_result(&self) -> MetricResult {
        MetricResult {
            metric: MetricRef::frozen(self.metric),
            status: self.status,
            counts: self.counts,
            effective_n: self.effective_n,
            value: self.value,
        }
    }
}

/// All ten metrics for one scanner and stratum, ascending by metric wire id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StratumAccounting {
    /// Authored counts of this stratum (cases, variants, occurrences).
    pub authored: PopulationCounts,
    /// The ten metrics.
    pub metrics: Vec<MetricAccount>,
}

impl StratumAccounting {
    /// The account of `metric`.
    pub fn metric(&self, metric: MetricId) -> Option<&MetricAccount> {
        self.metrics.iter().find(|m| m.metric == metric)
    }

    /// The contract metric results, in artifact order.
    pub fn results(&self) -> Vec<MetricResult> {
        self.metrics.iter().map(MetricAccount::to_result).collect()
    }
}

/// Accounting of one scanner: the overall population and its strata. Strata
/// partition the cases, so their counts add up to the overall counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerAccounting {
    /// Scanner.
    pub scanner_id: ScannerId,
    /// Run status.
    pub status: ScannerStatus,
    /// The whole population.
    pub overall: StratumAccounting,
    /// By case language, ascending.
    pub by_language: Vec<(LanguageTag, StratumAccounting)>,
    /// By case jurisdiction, ascending, `None` (global) first.
    pub by_jurisdiction: Vec<(Option<JurisdictionCode>, StratumAccounting)>,
    /// By method, ascending by wire id, only methods that have cases.
    pub by_method: Vec<(MethodId, StratumAccounting)>,
}

/// Deterministic work and state-size counters of one accounting pass, for
/// complexity checks. Memory is an element-count model (`state_bytes`), not an
/// RSS measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUse {
    /// Outcome rows read (each exactly once).
    pub rows_visited: u64,
    /// (scanner, case) groups classified (each exactly once).
    pub group_visits: u64,
    /// Bytes of per-run state allocated by the pass: group flag words, the
    /// duplicate bitset, tallies. Excludes the input and the output.
    pub state_bytes: u64,
}

/// The accounting of one run: one [`ScannerAccounting`] per scanner. Scanners
/// are never pooled and the population is never merged with another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accounting {
    /// Authored counts of the population.
    pub authored: PopulationCounts,
    /// Mechanics the values were computed with.
    pub mechanics: Mechanics,
    /// Scanners, ascending by id.
    pub scanners: Vec<ScannerAccounting>,
    /// Work counters.
    pub resources: ResourceUse,
}

// ---------------------------------------------------------------------------
// Group flags
// ---------------------------------------------------------------------------

// Facts about one (scanner, case) group, OR-accumulated over its rows. The
// `VT_*` / `RV_*` bits only consider occurrences authored as valid-type.
const VT_ANY: u32 = 1 << 0; // a valid-type occurrence exists
const VT_NM: u32 = 1 << 1; // ... with type not-measured
const VT_MISS: u32 = 1 << 2;
const VT_WF: u32 = 1 << 3; // wrong-family
const VT_WJ: u32 = 1 << 4; // wrong-jurisdiction
const RV_NONMISS: u32 = 1 << 5; // a valid-type occurrence whose range is not a miss
const RV_NA: u32 = 1 << 6; // ... whose range is not-applicable
const RV_COLL: u32 = 1 << 7; // ... overbroad or partial
const S_ANY: u32 = 1 << 8; // an authored-sensitive occurrence exists
const S_REV: u32 = 1 << 9;
const S_NM: u32 = 1 << 10;
const S_MISS: u32 = 1 << 11;
const N_ANY: u32 = 1 << 12; // an authored-non-sensitive occurrence exists
const N_REV: u32 = 1 << 13;
const N_NM: u32 = 1 << 14;
const N_FP: u32 = 1 << 15; // false-positive
const A_SREV: u32 = 1 << 16; // any row: sensitivity review-required
const A_SNM: u32 = 1 << 17; // any row: sensitivity not-measured
const A_SFAIL: u32 = 1 << 18; // any row: sensitivity fail (A8: "all rows pass" = no fail)
const A_TNM: u32 = 1 << 19; // any row: type not-measured
const A_TFAIL: u32 = 1 << 20; // any row: type fail (A8)
const E_REV: u32 = 1 << 21; // context endpoint: sensitivity review-required
const E_NM: u32 = 1 << 22; // context endpoint: not-measured
const E_FAIL: u32 = 1 << 23; // context endpoint: fail
const A_TREV: u32 = 1 << 24; // any row: type unresolved (authored not-established, ADR 0017)

fn row_flags(occ: &OccInfo, row: &OutcomeRow) -> u32 {
    let mut f = 0;
    let type_status = row.type_identity.status();
    let sens_status = row.sensitivity_context.status();
    if occ.expected == ExpectedType::Valid {
        f |= VT_ANY;
        match row.type_identity {
            TypeState::NotMeasured => f |= VT_NM,
            TypeState::Miss => f |= VT_MISS,
            TypeState::WrongFamily => f |= VT_WF,
            TypeState::WrongJurisdiction => f |= VT_WJ,
            TypeState::Correct
            | TypeState::InvalidCorrect
            | TypeState::InvalidAccepted
            | TypeState::Unresolved => {}
        }
        match row.range {
            RangeState::Miss => {}
            // `unresolved` needs a not-established range, and that needs a
            // not-established type (ADR 0018): unreachable for a valid type,
            // kept total and conservative (not a miss, not applicable).
            RangeState::NotApplicable | RangeState::Unresolved => f |= RV_NONMISS | RV_NA,
            RangeState::Exact => f |= RV_NONMISS,
            RangeState::Overbroad | RangeState::Partial => f |= RV_NONMISS | RV_COLL,
        }
    }
    match occ.sensitivity {
        SensitivityExpectation::Sensitive => {
            f |= S_ANY;
            match sens_status {
                AxisStatus::ReviewRequired => f |= S_REV,
                AxisStatus::NotMeasured => f |= S_NM,
                AxisStatus::Pass | AxisStatus::Fail => {}
            }
            if row.sensitivity_context == SensitivityState::Miss {
                f |= S_MISS;
            }
        }
        SensitivityExpectation::NonSensitive => {
            f |= N_ANY;
            match sens_status {
                AxisStatus::ReviewRequired => f |= N_REV,
                AxisStatus::NotMeasured => f |= N_NM,
                AxisStatus::Pass | AxisStatus::Fail => {}
            }
            if row.sensitivity_context == SensitivityState::FalsePositive {
                f |= N_FP;
            }
        }
        SensitivityExpectation::NotEstablished | SensitivityExpectation::ContextDependent => {}
    }
    match sens_status {
        AxisStatus::ReviewRequired => f |= A_SREV,
        AxisStatus::NotMeasured => f |= A_SNM,
        AxisStatus::Fail => f |= A_SFAIL,
        AxisStatus::Pass => {}
    }
    match type_status {
        AxisStatus::NotMeasured => f |= A_TNM,
        AxisStatus::Fail => f |= A_TFAIL,
        AxisStatus::ReviewRequired => f |= A_TREV,
        AxisStatus::Pass => {}
    }
    if occ.endpoint {
        match sens_status {
            AxisStatus::ReviewRequired => f |= E_REV,
            AxisStatus::NotMeasured => f |= E_NM,
            AxisStatus::Fail => f |= E_FAIL,
            AxisStatus::Pass => {}
        }
    }
    f
}

// ---------------------------------------------------------------------------
// Buckets and tallies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Numerator,
    Other,
    Unresolved,
    NotMeasured,
    NotApplicable,
}

/// The oracle's `groupBucket`: review-required, then not-measured, then the
/// event, else other.
fn resolve(review: bool, not_measured: bool, event: bool) -> Bucket {
    if review {
        Bucket::Unresolved
    } else if not_measured {
        Bucket::NotMeasured
    } else if event {
        Bucket::Numerator
    } else {
        Bucket::Other
    }
}

/// A group's buckets for one metric: none (outside the population, not even
/// counted as not-applicable), one, or two (`measurable-share`).
struct Buckets {
    items: [Bucket; 2],
    len: usize,
}

impl Buckets {
    const NONE: Buckets = Buckets {
        items: [Bucket::NotApplicable; 2],
        len: 0,
    };
    fn one(b: Bucket) -> Buckets {
        Buckets {
            items: [b, Bucket::NotApplicable],
            len: 1,
        }
    }
}

fn group_buckets(metric: MetricId, f: u32, case: &CaseInfo<'_>) -> Buckets {
    let has = |bit: u32| f & bit != 0;
    // Valid-type metrics judge only valid-type occurrences: an authored
    // `not-established` identity (ADR 0017) is outside their population, so it
    // changes no numerator, denominator or effective N of the type metrics.
    let valid_type = |event: u32| {
        if has(VT_ANY) {
            resolve(false, has(VT_NM), has(event))
        } else {
            Bucket::NotApplicable
        }
    };
    match metric {
        MetricId::TypeMissRate => Buckets::one(valid_type(VT_MISS)),
        MetricId::WrongFamilyRate => Buckets::one(valid_type(VT_WF)),
        MetricId::WrongJurisdictionRate => Buckets::one(if case.jurisdictional {
            valid_type(VT_WJ)
        } else {
            Bucket::NotApplicable
        }),
        MetricId::SensitiveMissRate => Buckets::one(if has(S_ANY) {
            resolve(has(S_REV), has(S_NM), has(S_MISS))
        } else {
            Bucket::NotApplicable
        }),
        MetricId::NonSensitiveFlagRate => Buckets::one(if has(N_ANY) {
            resolve(has(N_REV), has(N_NM), has(N_FP))
        } else {
            Bucket::NotApplicable
        }),
        // Only complete context trios enter the population; other methods'
        // cases are outside it (the oracle's `total` is the number of trios).
        MetricId::ContextDiscriminationRate => {
            if case.method == MethodId::ContextDiscrimination {
                Buckets::one(resolve(has(E_REV), has(E_NM), !has(E_FAIL)))
            } else {
                Buckets::NONE
            }
        }
        // A8 (ADR 0008): a case is suppressed (or its collision resolved) only
        // when ALL of its rows pass. After review-required and not-measured
        // have been handled by `resolve`, every remaining row is a pass or a
        // fail, so "all pass" is "no fail". The oracle counted a case when ANY
        // row passed; that rule stays in the compatibility tests only.
        MetricId::BenignSuppressionRate => Buckets::one(if case.method == MethodId::PiiBenign {
            resolve(has(A_SREV), has(A_SNM), !has(A_SFAIL))
        } else {
            Bucket::NotApplicable
        }),
        MetricId::JurisdictionCollisionRate => {
            Buckets::one(if case.method == MethodId::JurisdictionCollision {
                resolve(has(A_TREV), has(A_TNM), !has(A_TFAIL))
            } else {
                Bucket::NotApplicable
            })
        }
        MetricId::RangeCollateralRate => Buckets::one(if !has(VT_ANY) || !has(RV_NONMISS) {
            Bucket::NotApplicable
        } else if has(RV_NA) {
            Bucket::NotMeasured
        } else if has(RV_COLL) {
            Bucket::Numerator
        } else {
            Bucket::Other
        }),
        MetricId::MeasurableShare => {
            let type_axis = resolve(has(A_TREV), has(A_TNM), true);
            let sensitivity_axis = if case.has_not_established {
                Bucket::Unresolved
            } else {
                resolve(has(A_SREV), has(A_SNM), true)
            };
            Buckets {
                items: [type_axis, sensitivity_axis],
                len: 2,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    numerator: u64,
    other: u64,
    unresolved: u64,
    not_measured: u64,
    not_applicable: u64,
    cases: u64,
    variants: u64,
    occurrences: u64,
}

fn bump(counter: &mut u64, by: u64) -> Result<(), AccountError> {
    *counter = counter
        .checked_add(by)
        .ok_or(AccountError::CounterOverflow)?;
    Ok(())
}

impl Tally {
    fn add(&mut self, buckets: &Buckets, case: &CaseInfo<'_>) -> Result<(), AccountError> {
        let mut eligible = false;
        for b in &buckets.items[..buckets.len] {
            match b {
                Bucket::Numerator => bump(&mut self.numerator, 1)?,
                Bucket::Other => bump(&mut self.other, 1)?,
                Bucket::Unresolved => bump(&mut self.unresolved, 1)?,
                Bucket::NotMeasured => bump(&mut self.not_measured, 1)?,
                Bucket::NotApplicable => bump(&mut self.not_applicable, 1)?,
            }
            eligible |= *b != Bucket::NotApplicable;
        }
        if eligible {
            bump(&mut self.cases, 1)?;
            bump(&mut self.variants, u64::from(case.variants))?;
            bump(&mut self.occurrences, u64::from(case.occurrences))?;
        }
        Ok(())
    }
}

/// Metrics in registry (declaration) order; the tally index is the position.
const METRIC_COUNT: usize = METRICS.len();

fn metric_index(metric: MetricId) -> usize {
    METRICS
        .iter()
        .position(|m| m.id == metric)
        .unwrap_or_default()
}

/// Metric ids ascending by wire string, the artifact order.
fn metrics_in_wire_order() -> Vec<MetricId> {
    let mut ids: Vec<MetricId> = METRICS.iter().map(|m| m.id).collect();
    ids.sort_by_key(|m| m.as_str());
    ids
}

type TallySet = [Tally; METRIC_COUNT];

fn cause_for(status: ScannerStatus) -> UnmeasuredCause {
    match status {
        ScannerStatus::Complete => UnmeasuredCause::AxisNotReported,
        ScannerStatus::Unsupported => UnmeasuredCause::ScannerUnsupported,
        ScannerStatus::Unavailable => UnmeasuredCause::ScannerUnavailable,
        ScannerStatus::Unstable => UnmeasuredCause::ScannerUnstable,
        ScannerStatus::Error => UnmeasuredCause::ExecutionFailure,
    }
}

fn finish_stratum(
    authored: PopulationCounts,
    tallies: &TallySet,
    status: ScannerStatus,
    mechanics: &Mechanics,
) -> Result<StratumAccounting, AccountError> {
    let mut metrics = Vec::with_capacity(METRIC_COUNT);
    for id in metrics_in_wire_order() {
        let def = id.definition();
        let t = &tallies[metric_index(id)];
        let sum = |a: u64, b: u64| a.checked_add(b).ok_or(AccountError::CounterOverflow);
        let measured = sum(t.numerator, t.other)?;
        let eligible = sum(sum(measured, t.unresolved)?, t.not_measured)?;
        let counts = MetricCounts {
            eligible,
            measured,
            numerator: t.numerator,
            unresolved: t.unresolved,
            not_measured: t.not_measured,
            not_applicable: t.not_applicable,
            total: sum(eligible, t.not_applicable)?,
        };
        let effective_n = match def.effective_n {
            EffectiveNBasis::Measured => counts.measured,
            EffectiveNBasis::Eligible => counts.eligible,
        };
        let value = published_value(counts.numerator, effective_n, def.direction, mechanics)?;
        metrics.push(MetricAccount {
            metric: id,
            counts,
            effective_n,
            status: counts.derived_status(),
            value,
            not_measured_cause: (counts.not_measured > 0).then(|| cause_for(status)),
            basis: SampleBasis {
                sample_unit: def.sample_unit,
                eligible_cases: t.cases,
                eligible_variants: t.variants,
                eligible_occurrences: t.occurrences,
                correlated_variants: t.variants > t.cases,
                shared_case_axes: def.sample_unit == SampleUnit::AxisAssertion,
            },
        });
    }
    Ok(StratumAccounting { authored, metrics })
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

/// Account all rows of all scanners.
///
/// Cost: one pass over `rows` (each row costs two ordered-map and slice
/// lookups, logarithmic in variants and occurrences) plus one pass over the
/// (scanner, case) groups; memory is one 32-bit word per group, one bit per
/// (scanner, occurrence) and a fixed number of tallies per stratum. The result
/// does not depend on row order, scanner order or scheduling.
///
/// Every scanner must have exactly one row per authored occurrence: a missing
/// row is [`AccountError::MissingRows`], not an implicit not-measured. (A scanner
/// that did not run reports explicit not-measured rows.)
pub fn account<'r, I>(
    authored: &AuthoredIndex<'_>,
    scanners: &[ScannerInput<'_>],
    rows: I,
    mechanics: &Mechanics,
) -> Result<Accounting, AccountError>
where
    I: IntoIterator<Item = OutcomeRef<'r>>,
{
    let mut check = Collector::new();
    mechanics.validate(&Path::ROOT, &mut check);
    if !check.is_clean() {
        return Err(AccountError::InvalidMechanics);
    }
    check_limit(Limit::Scanners, MAX_SCANNERS, scanners.len())?;
    let mut order: Vec<ScannerInput<'_>> = scanners.to_vec();
    order.sort_by(|a, b| a.id.cmp(b.id));
    if order.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(AccountError::DuplicateScanner);
    }
    let scanner_count = order.len();
    let case_count = authored.cases.len();
    let occ_count = authored.occurrences.len();
    let total_rows = scanner_count
        .checked_mul(occ_count)
        .ok_or(AccountError::CounterOverflow)?;
    check_limit(Limit::Rows, MAX_OUTCOMES, total_rows)?;

    let mut flags: Vec<u32> = vec![0; scanner_count * case_count];
    let mut seen: Vec<u64> = vec![0; total_rows.div_ceil(64)];
    let mut found: Vec<u64> = vec![0; scanner_count];

    let mut rows_visited = 0u64;
    for (i, r) in rows.into_iter().enumerate() {
        let index = i as u64;
        if i >= total_rows {
            // More rows than a complete matrix holds: some row is a duplicate.
            return Err(AccountError::TooMany {
                limit: Limit::Rows,
                max: total_rows as u64,
                actual: index + 1,
            });
        }
        rows_visited += 1;
        let s = order
            .binary_search_by(|probe| probe.id.as_str().cmp(r.scanner_id))
            .map_err(|_| AccountError::UnknownScanner(index))?;
        let variant = authored
            .variants
            .get(r.variant_id)
            .ok_or(AccountError::UnknownOccurrence(index))?;
        let k = variant
            .expectations
            .binary_search_by(|e| e.occurrence_id.as_str().cmp(r.occurrence_id))
            .map_err(|_| AccountError::UnknownOccurrence(index))?;
        let occ_index = variant.first as usize + k;
        let occ = authored.occurrences[occ_index];
        let case = &authored.cases[occ.case as usize];
        if case.id != r.case_id || case.method != r.method {
            return Err(AccountError::CaseMismatch(index));
        }
        let bit = s * occ_count + occ_index;
        let (word, mask) = (bit / 64, 1u64 << (bit % 64));
        if seen[word] & mask != 0 {
            return Err(AccountError::DuplicateRow(index));
        }
        seen[word] |= mask;
        if !TypeState::reachable(occ.expected).contains(&r.row.type_identity)
            || !SensitivityState::reachable(occ.sensitivity).contains(&r.row.sensitivity_context)
            || (order[s].status != ScannerStatus::Complete && !r.row.is_unmeasured())
        {
            return Err(AccountError::OutcomeContradiction(index));
        }
        flags[s * case_count + occ.case as usize] |= row_flags(&occ, &r.row);
        found[s] += 1;
    }
    for (s, &n) in found.iter().enumerate() {
        if n != occ_count as u64 {
            return Err(AccountError::MissingRows {
                scanner: s as u64,
                expected: occ_count as u64,
                found: n,
            });
        }
    }

    // Stratum layout: [overall][languages...][jurisdictions...][methods...].
    let languages = authored.languages.len();
    let jurisdictions = authored.jurisdictions.len();
    let methods = METHODS.len();
    let strata = 1 + languages + jurisdictions + methods;
    let mut authored_by_stratum: Vec<PopulationCounts> = vec![
        PopulationCounts {
            authored_cases: 0,
            variants: 0,
            occurrences: 0,
        };
        strata
    ];
    for case in &authored.cases {
        for slot in stratum_slots(case, languages, jurisdictions) {
            let c = &mut authored_by_stratum[slot];
            bump(&mut c.authored_cases, 1)?;
            bump(&mut c.variants, u64::from(case.variants))?;
            bump(&mut c.occurrences, u64::from(case.occurrences))?;
        }
    }

    let mut group_visits = 0u64;
    let mut scanner_results = Vec::with_capacity(scanner_count);
    for (s, input) in order.iter().enumerate() {
        let mut tallies: Vec<TallySet> = vec![[Tally::default(); METRIC_COUNT]; strata];
        for (ci, case) in authored.cases.iter().enumerate() {
            group_visits += 1;
            let f = flags[s * case_count + ci];
            let slots = stratum_slots(case, languages, jurisdictions);
            for metric in METRICS.iter().map(|m| m.id) {
                let buckets = group_buckets(metric, f, case);
                let mi = metric_index(metric);
                for slot in slots {
                    tallies[slot][mi].add(&buckets, case)?;
                }
            }
        }
        let finish = |slot: usize| {
            finish_stratum(
                authored_by_stratum[slot],
                &tallies[slot],
                input.status,
                mechanics,
            )
        };
        let overall = finish(0)?;
        let mut by_language = Vec::with_capacity(languages);
        for (i, l) in authored.languages.iter().enumerate() {
            by_language.push(((*l).clone(), finish(1 + i)?));
        }
        let mut by_jurisdiction = Vec::with_capacity(jurisdictions);
        for (i, j) in authored.jurisdictions.iter().enumerate() {
            by_jurisdiction.push((j.cloned(), finish(1 + languages + i)?));
        }
        let mut by_method = Vec::new();
        let mut method_order: Vec<(usize, MethodId)> =
            METHODS.iter().map(|m| m.id).enumerate().collect();
        method_order.sort_by_key(|(_, m)| m.as_str());
        for (i, m) in method_order {
            let slot = 1 + languages + jurisdictions + i;
            if authored_by_stratum[slot].authored_cases > 0 {
                by_method.push((m, finish(slot)?));
            }
        }
        scanner_results.push(ScannerAccounting {
            scanner_id: input.id.clone(),
            status: input.status,
            overall,
            by_language,
            by_jurisdiction,
            by_method,
        });
    }

    let tally_bytes = scanner_count * strata * std::mem::size_of::<TallySet>();
    let state_bytes = flags.len() * 4 + seen.len() * 8 + found.len() * 8 + tally_bytes;
    Ok(Accounting {
        authored: authored.counts,
        mechanics: *mechanics,
        scanners: scanner_results,
        resources: ResourceUse {
            rows_visited,
            group_visits,
            state_bytes: state_bytes as u64,
        },
    })
}

/// The tally slots a case belongs to: overall, its language, its jurisdiction
/// and its method.
fn stratum_slots(case: &CaseInfo<'_>, languages: usize, jurisdictions: usize) -> [usize; 4] {
    [
        0,
        1 + usize::from(case.language),
        1 + languages + usize::from(case.jurisdiction),
        1 + languages + jurisdictions + method_slot(case.method),
    ]
}

fn method_slot(method: MethodId) -> usize {
    METHODS
        .iter()
        .position(|m| m.id == method)
        .unwrap_or_default()
}

/// Account the outcome rows of an internal artifact against its snapshot.
pub fn account_outcomes(
    authored: &AuthoredIndex<'_>,
    scanners: &[ScannerInput<'_>],
    outcomes: &[CaseOutcome],
    mechanics: &Mechanics,
) -> Result<Accounting, AccountError> {
    account(
        authored,
        scanners,
        outcomes.iter().map(OutcomeRef::from),
        mechanics,
    )
}
