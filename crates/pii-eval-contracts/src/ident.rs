//! Validated string identifiers.
//!
//! Every identifier is a newtype whose constructor and `Deserialize` enforce
//! its format, so a value of the type is a valid identifier by construction.
//! Formats are deliberately narrow (lowercase ASCII, bounded length): they are
//! compared and sorted bytewise, which makes canonical order unambiguous.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Error text used when an identifier fails validation. It names only the
/// identifier kind, never the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentError(pub &'static str);

thread_local! {
    /// Set by this crate's own identifier validators while deserializing. The
    /// parser reads it instead of inspecting serde's message text, which can
    /// echo attacker-chosen field names.
    static IDENTIFIER_FAILED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn mark_identifier_failure() {
    IDENTIFIER_FAILED.with(|f| f.set(true));
}

/// Clear the flag before a typed parse.
pub(crate) fn reset_identifier_failure() {
    IDENTIFIER_FAILED.with(|f| f.set(false));
}

/// Read and clear the flag after a typed parse.
pub(crate) fn take_identifier_failure() -> bool {
    IDENTIFIER_FAILED.with(|f| f.replace(false))
}

impl fmt::Display for IdentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}", self.0)
    }
}

impl std::error::Error for IdentError {}

fn is_lower(b: u8) -> bool {
    b.is_ascii_lowercase()
}
fn is_lower_digit(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// `^[a-z][a-z0-9-]{1,79}$`
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=80).contains(&b.len())
        && is_lower(b[0])
        && b[1..].iter().all(|&c| is_lower_digit(c) || c == b'-')
}

/// `^[a-z][a-z0-9.-]{1,79}$`
fn valid_dotted(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=80).contains(&b.len())
        && is_lower(b[0])
        && b[1..]
            .iter()
            .all(|&c| is_lower_digit(c) || c == b'.' || c == b'-')
}

/// `[a-z0-9]+(-[a-z0-9]+)*`
fn valid_kebab(s: &str) -> bool {
    !s.is_empty()
        && s.split('-')
            .all(|part| !part.is_empty() && part.bytes().all(is_lower_digit))
}

/// `^pii:(global|[a-z]{2}):<kebab>$`, with a two-letter scope that is a pinned
/// ISO 3166-1 alpha-2 code, and at most 80 bytes.
fn valid_family(s: &str) -> bool {
    if s.len() > 80 {
        return false;
    }
    let mut parts = s.splitn(3, ':');
    let (Some("pii"), Some(scope), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let scope_ok = scope == "global"
        || (scope.len() == 2
            && scope.bytes().all(|b| b.is_ascii_lowercase())
            && is_jurisdiction(&scope.to_ascii_uppercase()));
    scope_ok && valid_kebab(name)
}

/// `^[a-z]{2,8}(-[a-z0-9]{2,8})*$`, at most 35 bytes.
fn valid_language(s: &str) -> bool {
    if s.len() > 35 {
        return false;
    }
    let mut parts = s.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    (2..=8).contains(&first.len())
        && first.bytes().all(is_lower)
        && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(is_lower_digit))
}

fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^\d+\.\d+\.\d+([-+][A-Za-z0-9.-]+)?$`, at most 64 bytes.
fn valid_version(s: &str) -> bool {
    if s.len() > 64 {
        return false;
    }
    let (core, suffix) = match s.find(['-', '+']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut nums = core.split('.');
    let triple = [nums.next(), nums.next(), nums.next()];
    let numeric =
        |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    triple.iter().all(|p| numeric(*p))
        && nums.next().is_none()
        && suffix.is_none_or(|x| {
            !x.is_empty()
                && x.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
}

/// `^[a-zA-Z][a-zA-Z0-9]{0,63}$`
fn valid_config_key(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_alphabetic()
        && b[1..].iter().all(|c| c.is_ascii_alphanumeric())
}

/// `^[a-z][a-z0-9:.-]{1,79}$`
fn valid_selector(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=80).contains(&b.len())
        && is_lower(b[0])
        && b[1..]
            .iter()
            .all(|&c| is_lower_digit(c) || c == b':' || c == b'.' || c == b'-')
}

/// `^[A-Za-z0-9._-]{1,64}$`
fn valid_seed(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// `YYYY-MM-DDTHH:MM:SS(.fff)?Z`, UTC only, calendar fields range-checked.
fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let fixed = b.len() == 20 || (b.len() == 24 && b[19] == b'.');
    if !fixed || b[b.len() - 1] != b'Z' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(|c| c.is_ascii_digit());
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().unwrap_or(u32::MAX);
    let frame = b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':';
    let ok_digits = digits(0..4)
        && digits(5..7)
        && digits(8..10)
        && digits(11..13)
        && digits(14..16)
        && digits(17..19)
        && (b.len() == 20 || digits(20..23));
    frame
        && ok_digits
        && (1..=12).contains(&num(5..7))
        && (1..=31).contains(&num(8..10))
        && num(11..13) < 24
        && num(14..16) < 60
        && num(17..19) < 60
}

macro_rules! string_newtype {
    (
        $(#[$doc:meta])*
        $name:ident, kind = $kind:literal, redact = $redact:literal, valid = $valid:path,
        pattern = $pattern:literal, min = $min:literal, max = $max:literal
    ) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl fmt::Debug for $name {
            /// Identifiers flagged `redact` (case, variant and seed identifiers)
            /// print only their length, so debug logs cannot leak them.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redact {
                    write!(f, "{}(<redacted {} bytes>)", stringify!($name), self.0.len())
                } else {
                    f.debug_tuple(stringify!($name)).field(&self.0).finish()
                }
            }
        }

        impl $name {
            /// Validate and wrap a string.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentError> {
                let value = value.into();
                if $valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(IdentError($kind))
                }
            }

            /// The identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentError;
            fn try_from(value: String) -> Result<Self, IdentError> {
                // Used by `Deserialize`: record that this crate's own validator
                // failed, so the parser can report `invalid-identifier` without
                // reading any serde message text.
                Self::new(value).inspect_err(|_| mark_identifier_failure())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": $pattern,
                    "minLength": $min,
                    "maxLength": $max,
                })
            }
        }
    };
}

string_newtype!(
    /// Stable semantic identifier for cases, variants, occurrences, populations,
    /// operators and validators. Independent of scanner detector names.
    Id, kind = "id", redact = true, valid = valid_slug,
    pattern = "^[a-z][a-z0-9-]{1,79}$", min = 2, max = 80
);
string_newtype!(
    /// Scanner or adapter identifier.
    ScannerId, kind = "scanner-id", redact = false, valid = valid_dotted,
    pattern = "^[a-z][a-z0-9.-]{1,79}$", min = 2, max = 80
);
string_newtype!(
    /// Credential-neutral PII family identifier, `pii:<scope>:<name>`, where the
    /// scope is `global` or a lowercase ISO 3166-1 alpha-2 jurisdiction.
    FamilyId, kind = "family-id", redact = false, valid = valid_family,
    pattern = "^pii:(global|[a-z]{2}):[a-z0-9]+(-[a-z0-9]+)*$", min = 8, max = 80
);
string_newtype!(
    /// Language tag, a lowercase subset of BCP 47 (`ko`, `en`, `zh-hans`).
    LanguageTag, kind = "language-tag", redact = false, valid = valid_language,
    pattern = "^[a-z]{2,8}(-[a-z0-9]{2,8})*$", min = 2, max = 35
);
string_newtype!(
    /// Lowercase hexadecimal SHA-256 digest.
    Sha256Digest, kind = "sha256-digest", redact = false, valid = valid_digest,
    pattern = "^[0-9a-f]{64}$", min = 64, max = 64
);
string_newtype!(
    /// Three-part numeric version with an optional pre-release or build suffix.
    VersionString, kind = "version", redact = false, valid = valid_version,
    pattern = "^[0-9]+\\.[0-9]+\\.[0-9]+([-+][A-Za-z0-9.-]+)?$", min = 5, max = 64
);
string_newtype!(
    /// Scanner configuration parameter name.
    ConfigKey, kind = "config-key", redact = false, valid = valid_config_key,
    pattern = "^[a-zA-Z][a-zA-Z0-9]{0,63}$", min = 1, max = 64
);
string_newtype!(
    /// Activation or enable-set selector (`pii:global`, `pii-context:v2`).
    ActivationSelector, kind = "activation-selector", redact = false, valid = valid_selector,
    pattern = "^[a-z][a-z0-9:.-]{1,79}$", min = 2, max = 80
);
string_newtype!(
    /// Seed or seed-derivation label for a generated variant.
    Seed, kind = "seed", redact = true, valid = valid_seed,
    pattern = "^[A-Za-z0-9._-]{1,64}$", min = 1, max = 64
);
string_newtype!(
    /// UTC timestamp, `YYYY-MM-DDTHH:MM:SS[.mmm]Z`. Diagnostic only; never part
    /// of a semantic digest.
    TimestampUtc, kind = "timestamp", redact = false, valid = valid_timestamp,
    pattern = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{3})?Z$", min = 20, max = 24
);

impl TimestampUtc {
    /// Milliseconds since the Unix epoch. The format check guarantees the
    /// digits parse; days-from-civil is the standard proleptic Gregorian
    /// conversion, so values with different fraction lengths compare correctly.
    pub fn unix_millis(&self) -> i64 {
        let b = self.0.as_bytes();
        let n = |r: std::ops::Range<usize>| -> i64 { self.0[r].parse().unwrap_or(0) };
        let (y, m, d) = (n(0..4), n(5..7), n(8..10));
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let millis = if b.len() == 24 { n(20..23) } else { 0 };
        ((days * 24 + n(11..13)) * 60 + n(14..16)) * 60_000 + n(17..19) * 1000 + millis
    }
}

impl Sha256Digest {
    /// SHA-256 of raw bytes, as the identity of those exact bytes (for example
    /// UTF-8 variant text or scanner output). Not domain separated; semantic
    /// digests of documents use [`crate::canonical::semantic_digest`].
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(hex_lower(&Sha256::digest(bytes)))
    }

    pub(crate) fn from_raw(raw: &[u8]) -> Self {
        Self(hex_lower(raw))
    }
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Pinned ISO 3166-1 alpha-2 assignment set (ISO/TC 46 N1127, 2024-02-29),
/// ascending. Validates standards identity only; whether a jurisdiction has
/// evidence is a population decision.
pub const JURISDICTION_CODES: [&str; 249] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

/// True when `code` is an assigned ISO 3166-1 alpha-2 code in the pinned set.
pub fn is_jurisdiction(code: &str) -> bool {
    JURISDICTION_CODES.binary_search(&code).is_ok()
}

fn valid_jurisdiction(s: &str) -> bool {
    is_jurisdiction(s)
}

string_newtype!(
    /// ISO 3166-1 alpha-2 jurisdiction code (uppercase), from the pinned set.
    JurisdictionCode, kind = "jurisdiction", redact = false, valid = valid_jurisdiction,
    pattern = "^[A-Z]{2}$", min = 2, max = 2
);

/// Scope of a family: independent of any scanner's detector naming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyScope {
    /// `pii:global:*`
    Global,
    /// `pii:<xx>:*`
    Jurisdiction(JurisdictionCode),
}

impl FamilyId {
    /// The scope encoded in the identifier. The constructor guarantees the
    /// scope is `global` or an assigned jurisdiction.
    pub fn scope(&self) -> FamilyScope {
        let scope = self.0.split(':').nth(1).unwrap_or("global");
        if scope == "global" {
            FamilyScope::Global
        } else {
            // Validated at construction; fall back to Global is unreachable.
            match JurisdictionCode::new(scope.to_ascii_uppercase()) {
                Ok(code) => FamilyScope::Jurisdiction(code),
                Err(_) => FamilyScope::Global,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_accept_and_reject() {
        assert!(Id::new("email-context-sensitive").is_ok());
        for bad in ["a", "A-b", "9ab", "ab_c", "", &"a".repeat(81)] {
            assert!(Id::new(bad).is_err(), "{}", bad.len());
        }
    }

    #[test]
    fn families_require_a_known_scope() {
        assert!(FamilyId::new("pii:global:email").is_ok());
        assert!(FamilyId::new("pii:kr:national-id").is_ok());
        assert!(FamilyId::new("pii:zz:national-id").is_err());
        assert!(FamilyId::new("pii:kr:").is_err());
        assert!(FamilyId::new("pii:kr:a--b").is_err());
        assert!(FamilyId::new("cred:global:email").is_err());
        assert_eq!(
            FamilyId::new("pii:kr:national-id").unwrap().scope(),
            FamilyScope::Jurisdiction(JurisdictionCode::new("KR").unwrap())
        );
    }

    #[test]
    fn jurisdiction_set_is_sorted_and_complete() {
        assert!(JURISDICTION_CODES.windows(2).all(|w| w[0] < w[1]));
        assert!(is_jurisdiction("KR") && !is_jurisdiction("kr") && !is_jurisdiction("XX"));
    }

    #[test]
    fn digests_are_lowercase_hex_only() {
        let d = Sha256Digest::of_bytes(b"");
        assert_eq!(
            d.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(Sha256Digest::new(d.as_str().to_ascii_uppercase()).is_err());
        assert!(Sha256Digest::new("abc").is_err());
    }

    #[test]
    fn versions_languages_timestamps() {
        assert!(VersionString::new("1.2.3").is_ok());
        assert!(VersionString::new("0.1.0-beta.12").is_ok());
        assert!(VersionString::new("1.2").is_err());
        assert!(VersionString::new("1.2.3-").is_err());
        assert!(LanguageTag::new("ko").is_ok() && LanguageTag::new("zh-hans").is_ok());
        assert!(LanguageTag::new("KO").is_err() && LanguageTag::new("k").is_err());
        assert!(TimestampUtc::new("2026-10-02T12:00:00Z").is_ok());
        assert!(TimestampUtc::new("2026-10-02T12:00:00.123Z").is_ok());
        assert!(TimestampUtc::new("2026-13-02T12:00:00Z").is_err());
        assert!(TimestampUtc::new("2026-10-02T12:00:00+09:00").is_err());
    }
}
