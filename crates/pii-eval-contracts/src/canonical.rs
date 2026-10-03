//! Strict parsing, canonical serialization and the semantic digest.
//!
//! The normative description is in ADR 0003. Summary:
//!
//! * Input is parsed strictly: one JSON document, no duplicate keys, no `null`,
//!   no non-integer number, no integer outside +/-(2^53 - 1), bounded size and
//!   nesting.
//! * The canonical form of a value is compact UTF-8 JSON with object keys in
//!   ascending UTF-8 byte order, integers as plain decimal digits, strings
//!   escaped only for `"`, `\` and control characters (`\u00xx`, lowercase),
//!   and arrays in their stated order. Absent optional fields are omitted;
//!   `null` has no canonical form. Floats have no canonical form, so `NaN`,
//!   infinities and negative zero cannot occur.
//! * The semantic digest is SHA-256 over a domain prefix followed by the
//!   canonical form of the document's `semantic` body. Diagnostics such as
//!   timing live outside that body and cannot reach the digest.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::ident::Sha256Digest;
use crate::limits::{MAX_DOCUMENT_BYTES, MAX_NESTING_DEPTH, MAX_SAFE_INTEGER};
use crate::reason::{ContractError, Meta, ReasonCode};

/// Version of the digest construction. Changing the preimage layout or the
/// canonical form is a breaking change that requires a new value here.
pub const DIGEST_CONSTRUCTION: &str = "pii-eval-semantic-digest/1";

/// Bounds applied when parsing a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Largest accepted input, in bytes.
    pub max_bytes: usize,
    /// Deepest accepted nesting.
    pub max_depth: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_DOCUMENT_BYTES,
            max_depth: MAX_NESTING_DEPTH,
        }
    }
}

const TAG_DUPLICATE: &str = "pii-eval:duplicate-key";
const TAG_NULL: &str = "pii-eval:null";
const TAG_FLOAT: &str = "pii-eval:float";
const TAG_INTEGER: &str = "pii-eval:integer-range";
const TAG_DEPTH: &str = "pii-eval:depth";

struct StrictSeed {
    depth: usize,
    max_depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor {
            depth: self.depth,
            max_depth: self.max_depth,
        })
    }
}

struct StrictVisitor {
    depth: usize,
    max_depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom(TAG_INTEGER));
        }
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(E::custom(TAG_INTEGER));
        }
        Ok(Value::Number(Number::from(v)))
    }

    // Any floating-point token, including `-0`, `1.0`, `1e2` and integers too
    // large for 64 bits, reaches here.
    fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Value, E> {
        Err(E::custom(TAG_FLOAT))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Err(E::custom(TAG_NULL))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Err(E::custom(TAG_NULL))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= self.max_depth {
            return Err(serde::de::Error::custom(TAG_DEPTH));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictSeed {
            depth: self.depth + 1,
            max_depth: self.max_depth,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= self.max_depth {
            return Err(serde::de::Error::custom(TAG_DEPTH));
        }
        let mut seen = BTreeSet::new();
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(TAG_DUPLICATE));
            }
            let value = map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
                max_depth: self.max_depth,
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// Map a serde_json error (from a strict or typed parse) to a stable code.
/// Only this crate's own static tags are inspected; the error text is never
/// forwarded.
pub(crate) fn classify_parse_error(e: &serde_json::Error) -> ContractError {
    let text = e.to_string();
    let code = if text.contains(TAG_DUPLICATE) {
        ReasonCode::DuplicateKey
    } else if text.contains(TAG_NULL) {
        ReasonCode::NullNotAllowed
    } else if text.contains(TAG_FLOAT) {
        ReasonCode::FloatNotAllowed
    } else if text.contains(TAG_INTEGER) {
        ReasonCode::IntegerOutOfRange
    } else if text.contains(TAG_DEPTH) {
        ReasonCode::NestingTooDeep
    } else if text.contains(crate::ident::IDENT_ERROR_TAG) {
        ReasonCode::InvalidIdentifier
    } else {
        match e.classify() {
            serde_json::error::Category::Data => ReasonCode::SchemaViolation,
            _ => ReasonCode::MalformedJson,
        }
    };
    ContractError::root_with(code, Meta::position(e.line() as u64, e.column() as u64))
}

/// Parse one strict JSON document into a [`Value`].
///
/// Rejects: oversize input, malformed JSON or trailing data, duplicate object
/// keys, `null`, non-integer numbers (including `-0`), integers beyond
/// +/-(2^53 - 1), and nesting deeper than the limit.
pub fn parse_strict(bytes: &[u8], limits: &ParseLimits) -> Result<Value, ContractError> {
    if bytes.len() > limits.max_bytes {
        return Err(ContractError::root_with(
            ReasonCode::DocumentTooLarge,
            Meta::limit(limits.max_bytes as u64, bytes.len() as u64),
        ));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed {
        depth: 0,
        max_depth: limits.max_depth,
    }
    .deserialize(&mut de)
    .map_err(|e| classify_parse_error(&e))?;
    de.end().map_err(|e| classify_parse_error(&e))?;
    Ok(value)
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if (c as u32) < 0x20 => {
                let n = c as u32 as usize;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[n >> 4]);
                out.push(HEX[n & 0x0f]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_value(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<(), ContractError> {
    if depth > 2 * MAX_NESTING_DEPTH {
        return Err(ContractError::root(ReasonCode::NestingTooDeep));
    }
    match value {
        Value::Null => return Err(ContractError::root(ReasonCode::NullNotAllowed)),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(ContractError::root(ReasonCode::IntegerOutOfRange));
                }
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(ContractError::root(ReasonCode::IntegerOutOfRange));
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                return Err(ContractError::root(ReasonCode::FloatNotAllowed));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, depth + 1, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort explicitly: the canonical order must not depend on how the
            // JSON library orders its map. `String` ordering is bytewise.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(item, depth + 1, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Canonical bytes of a JSON value (see the module documentation).
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, ContractError> {
    let mut out = Vec::new();
    write_value(value, 0, &mut out)?;
    Ok(out)
}

/// Canonical bytes of any serializable contract value.
pub fn canonical_bytes_of<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ContractError::root(ReasonCode::SchemaViolation))?;
    canonical_bytes(&value)
}

/// `SHA-256(DIGEST_CONSTRUCTION "\n" domain "\n" canonical)`, lowercase hex.
///
/// `domain` separates digests of different things that could otherwise share
/// canonical bytes, for example `"pii-eval.corpus-snapshot/1"`.
pub fn semantic_digest(domain: &str, canonical: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_CONSTRUCTION.as_bytes());
    hasher.update(b"\n");
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);
    Sha256Digest::from_raw(hasher.finalize().as_slice())
}

/// Semantic digest of a serializable value under `domain`.
pub fn semantic_digest_of<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Sha256Digest, ContractError> {
    Ok(semantic_digest(domain, &canonical_bytes_of(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: &Value) -> String {
        String::from_utf8(canonical_bytes(v).unwrap()).unwrap()
    }

    #[test]
    fn keys_sort_bytewise_and_output_is_compact() {
        let v = json!({"b": 1, "a": [true, "x"], "A": {"z": 0, "y": -7}});
        assert_eq!(canon(&v), r#"{"A":{"y":-7,"z":0},"a":[true,"x"],"b":1}"#);
    }

    #[test]
    fn key_order_follows_utf8_bytes_not_utf16() {
        // U+FF5E (3 bytes, UTF-16 unit 0xFF5E) sorts before U+1F600 (4 bytes,
        // surrogates 0xD83D..) in UTF-8 bytes, after it in UTF-16.
        let v = json!({"\u{1F600}": 1, "\u{FF5E}": 2});
        assert_eq!(canon(&v), "{\"\u{FF5E}\":2,\"\u{1F600}\":1}");
    }

    #[test]
    fn strings_escape_only_quote_backslash_and_controls() {
        let v = json!("a\"b\\c\n\u{1}\u{7f}\u{2028}/가");
        assert_eq!(canon(&v), "\"a\\\"b\\\\c\\u000a\\u0001\u{7f}\u{2028}/가\"");
    }

    #[test]
    fn numbers_are_plain_integers_and_floats_have_no_form() {
        assert_eq!(canon(&json!(0)), "0");
        assert_eq!(canon(&json!(-5)), "-5");
        assert_eq!(canon(&json!(9007199254740991u64)), "9007199254740991");
        assert_eq!(
            canonical_bytes(&json!(9007199254740992u64))
                .unwrap_err()
                .code,
            ReasonCode::IntegerOutOfRange
        );
        assert_eq!(
            canonical_bytes(&json!(1.5)).unwrap_err().code,
            ReasonCode::FloatNotAllowed
        );
        assert_eq!(
            canonical_bytes(&json!(-0.0)).unwrap_err().code,
            ReasonCode::FloatNotAllowed
        );
        assert_eq!(
            canonical_bytes(&Value::Null).unwrap_err().code,
            ReasonCode::NullNotAllowed
        );
    }

    fn parse(text: &str) -> Result<Value, ReasonCode> {
        parse_strict(text.as_bytes(), &ParseLimits::default()).map_err(|e| e.code)
    }

    #[test]
    fn strict_parse_rejects_each_hazard_with_its_code() {
        assert_eq!(parse(r#"{"a":1,"a":2}"#), Err(ReasonCode::DuplicateKey));
        assert_eq!(
            parse(r#"{"a":{"b":1,"b":1}}"#),
            Err(ReasonCode::DuplicateKey)
        );
        assert_eq!(parse(r#"{"a":null}"#), Err(ReasonCode::NullNotAllowed));
        assert_eq!(parse(r#"{"a":1.0}"#), Err(ReasonCode::FloatNotAllowed));
        assert_eq!(parse(r#"{"a":1e2}"#), Err(ReasonCode::FloatNotAllowed));
        assert_eq!(parse(r#"{"a":-0}"#), Err(ReasonCode::FloatNotAllowed));
        assert_eq!(parse(r#"{"a":-0.0}"#), Err(ReasonCode::FloatNotAllowed));
        assert_eq!(
            parse(r#"{"a":9007199254740992}"#),
            Err(ReasonCode::IntegerOutOfRange)
        );
        assert_eq!(
            parse(r#"{"a":-9007199254740992}"#),
            Err(ReasonCode::IntegerOutOfRange)
        );
        assert_eq!(
            parse(r#"{"a":18446744073709551615}"#),
            Err(ReasonCode::IntegerOutOfRange)
        );
        assert_eq!(parse(r#"{"a":1} x"#), Err(ReasonCode::MalformedJson));
        assert_eq!(parse(r#"{"a":"#), Err(ReasonCode::MalformedJson));
        assert_eq!(parse("\u{feff}{}"), Err(ReasonCode::MalformedJson));
        assert!(parse(r#"{"a":9007199254740991,"b":-9007199254740991,"c":0}"#).is_ok());
    }

    #[test]
    fn invalid_utf8_is_malformed() {
        let bytes = b"{\"a\":\"\xff\"}";
        assert_eq!(
            parse_strict(bytes, &ParseLimits::default())
                .unwrap_err()
                .code,
            ReasonCode::MalformedJson
        );
    }

    #[test]
    fn size_and_depth_are_bounded() {
        let limits = ParseLimits {
            max_bytes: 8,
            max_depth: 3,
        };
        assert_eq!(
            parse_strict(b"{\"a\":\"123456\"}", &limits)
                .unwrap_err()
                .code,
            ReasonCode::DocumentTooLarge
        );
        let limits = ParseLimits {
            max_bytes: 1024,
            max_depth: 3,
        };
        assert!(parse_strict(b"[[[1]]]", &limits).is_ok());
        assert_eq!(
            parse_strict(b"[[[[1]]]]", &limits).unwrap_err().code,
            ReasonCode::NestingTooDeep
        );
        let deep = "[".repeat(10_000);
        assert_eq!(
            parse_strict(deep.as_bytes(), &ParseLimits::default())
                .unwrap_err()
                .code,
            ReasonCode::NestingTooDeep
        );
    }

    #[test]
    fn errors_never_echo_input() {
        let secret = "SECRETVALUE-123";
        let text = format!("{{\"{secret}\":1,\"{secret}\":2}}");
        let e = parse_strict(text.as_bytes(), &ParseLimits::default()).unwrap_err();
        assert!(!format!("{e} {e:?}").contains(secret));
    }

    #[test]
    fn digest_is_domain_separated_and_matches_independent_vector() {
        let a = semantic_digest("d1", b"{}");
        let b = semantic_digest("d2", b"{}");
        assert_ne!(a, b);
        // Independent vector: printf 'pii-eval-semantic-digest/1\nd1\n{}' | shasum -a 256
        assert_eq!(
            a.as_str(),
            "8a3fd8120597c91b68fcab45727660d752861066cfbf902e066340ce16189ce7"
        );
    }
}
