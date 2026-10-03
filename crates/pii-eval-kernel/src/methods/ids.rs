//! Deterministic variant identifiers, seed derivation and the oracle's
//! `sha256-pattern` candidate generator.
//!
//! Exact algorithms, with independently computed vectors, are specified in
//! `docs/adr/0007-method-generation-and-variant-provenance.md`. Nothing here
//! reads a clock, a random source, the environment or a map iteration order:
//! every output is a pure function of the inputs named in its signature.

use pii_eval_contracts::{Id, Seed, Sha256Digest};

/// Domain tag of the variant-id hash.
pub const VARIANT_ID_DOMAIN: &str = "pii-eval.variant-id/1";
/// Domain tag of the variant-seed hash.
pub const VARIANT_SEED_DOMAIN: &str = "pii-eval.variant-seed/1";
/// Seed-derivation rule `pii-seed-v1`: a per-variant SHA-256 derivation.
pub const SEED_RULE_V1: &str = "pii-seed-v1";
/// Seed-derivation rule `legacy-case-seed`: the oracle's behaviour, where every
/// variant of a case carries the case's own seed unchanged.
pub const SEED_RULE_LEGACY: &str = "legacy-case-seed";
/// Longest slot, in bytes. With the `-` and 24 hex digits a variant id is at
/// most 73 bytes, inside the 80-byte identifier limit.
pub const MAX_SLOT_BYTES: usize = 48;
/// Hex digits of the digest kept in a variant id (96 bits).
pub const VARIANT_ID_HEX_LEN: usize = 24;

/// The role of a variant inside its authored case: the oracle's local variant
/// id (`authored`, `validated`, a context frame id, a benign accounting class,
/// ...). A slot is a lowercase slug of at most [`MAX_SLOT_BYTES`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(String);

/// A slot that is not a slug or is too long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotError;

impl Slot {
    /// Validate a slot.
    pub fn new(value: &str) -> Result<Self, SlotError> {
        if value.len() <= MAX_SLOT_BYTES && Id::new(value).is_ok() {
            Ok(Self(value.to_owned()))
        } else {
            Err(SlotError)
        }
    }

    /// The slot text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A seed-derivation rule known to this implementation. The rule id recorded
/// in a snapshot's `generation.seedDerivation` selects one; any other value is
/// unsupported and reported, never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedRule {
    /// `pii-seed-v1`.
    PiiSeedV1,
    /// `legacy-case-seed`.
    LegacyCaseSeed,
}

impl SeedRule {
    /// The rule recorded in a snapshot, or `None` when it is not known.
    pub fn from_id(id: &Seed) -> Option<Self> {
        match id.as_str() {
            SEED_RULE_V1 => Some(SeedRule::PiiSeedV1),
            SEED_RULE_LEGACY => Some(SeedRule::LegacyCaseSeed),
            _ => None,
        }
    }

    /// The rule identifier.
    pub const fn id(self) -> &'static str {
        match self {
            SeedRule::PiiSeedV1 => SEED_RULE_V1,
            SeedRule::LegacyCaseSeed => SEED_RULE_LEGACY,
        }
    }
}

/// The hash preimage of an ordered list of text fields: each field is a
/// 4-byte big-endian length followed by its UTF-8 bytes, so no field boundary
/// is ambiguous (`["ab","c"]` and `["a","bc"]` differ).
///
/// A field longer than `u32::MAX` bytes is an error, so the length prefix is
/// always exact and the encoding stays injective.
pub fn preimage(fields: &[&str]) -> Result<Vec<u8>, DerivationError> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| DerivationError)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    Ok(out)
}

/// The contract seed for one of the oracle's free-form case seeds, as the
/// `legacy-case-seed` rule needs it: every `/` becomes `.` (the contract's seed
/// alphabet is `[A-Za-z0-9._-]`, 1 to 64 bytes).
///
/// The mapping is **not injective** (`a/b` and `a.b` give the same seed), so a
/// legacy seed is not bit-identical to the oracle's; any parity comparison
/// (P9) must apply this same function to the oracle side. A seed that is still
/// invalid after the mapping is an error, never repaired.
pub fn legacy_contract_seed(oracle_seed: &str) -> Result<Seed, DerivationError> {
    Seed::new(oracle_seed.replace('/', ".")).map_err(|_| DerivationError)
}

/// The snapshot-unique identifier of the variant in `slot` of `case_id`:
/// `<slot>-<first 24 hex digits of SHA-256(preimage([VARIANT_ID_DOMAIN, case_id, slot]))>`.
///
/// A readable slot prefix would collide across cases (`a-b`+`c` against
/// `a`+`b-c`); the digest binds the pair, and the length prefix of
/// [`preimage`] makes the pair unambiguous.
pub fn variant_id(case_id: &Id, slot: &Slot) -> Result<Id, DerivationError> {
    let digest = Sha256Digest::of_bytes(&preimage(&[
        VARIANT_ID_DOMAIN,
        case_id.as_str(),
        slot.as_str(),
    ])?);
    let id = format!(
        "{}-{}",
        slot.as_str(),
        &digest.as_str()[..VARIANT_ID_HEX_LEN]
    );
    // `slot` is a slug of at most 48 bytes, so the result is a slug of at most
    // 73; the error arm is unreachable and exists so that nothing is replaced
    // silently.
    Id::new(id).map_err(|_| DerivationError)
}

/// A derived identifier failed identifier validation. Unreachable for valid
/// inputs; reported rather than replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationError;

/// The seed recorded on a derived variant.
///
/// - `pii-seed-v1`: the lowercase hex SHA-256 (64 digits) of
///   `preimage([VARIANT_SEED_DOMAIN, generator, decimal(generator_version), case_seed, case_id, slot])`.
/// - `legacy-case-seed`: `case_seed` itself.
pub fn derive_seed(
    rule: SeedRule,
    generator: &Id,
    generator_version: u32,
    case_seed: &Seed,
    case_id: &Id,
    slot: &Slot,
) -> Result<Seed, DerivationError> {
    match rule {
        SeedRule::LegacyCaseSeed => Ok(case_seed.clone()),
        SeedRule::PiiSeedV1 => {
            let version = generator_version.to_string();
            let digest = Sha256Digest::of_bytes(&preimage(&[
                VARIANT_SEED_DOMAIN,
                generator.as_str(),
                &version,
                case_seed.as_str(),
                case_id.as_str(),
                slot.as_str(),
            ])?);
            Seed::new(digest.as_str()).map_err(|_| DerivationError)
        }
    }
}

/// The oracle's `sha256-pattern` generator
/// (`materializePiiEvidenceCandidate`): every `D` in `pattern` becomes a digit
/// and every `A` an uppercase ASCII letter, chosen by the first eight hex
/// digits of `SHA-256(UTF-8 "<seed>/<n>")` read as an unsigned 32-bit number,
/// where `n` counts the substituted characters from zero. Other characters
/// pass through.
pub fn materialize_sha256_pattern(seed: &str, pattern: &str) -> String {
    let mut token = 0u64;
    pattern
        .chars()
        .map(|c| {
            if c != 'D' && c != 'A' {
                return c;
            }
            let digest = Sha256Digest::of_bytes(format!("{seed}/{token}").as_bytes());
            token += 1;
            let value = u32::from_str_radix(&digest.as_str()[..8], 16).unwrap_or(0);
            if c == 'D' {
                char::from(b'0' + (value % 10) as u8)
            } else {
                char::from(b'A' + (value % 26) as u8)
            }
        })
        .collect()
}
