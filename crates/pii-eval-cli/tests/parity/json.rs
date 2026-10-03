//! Small accessors over `serde_json::Value` for the parity data (integers and
//! strings only; the committed files contain no float and no `null` in the
//! fields read here). Test support, synthetic data only.
#![allow(dead_code)]

use serde::de::DeserializeOwned;
use serde_json::Value;

static NULL: Value = Value::Null;

pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

pub fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    get(v, key).as_str().unwrap_or("")
}

pub fn opt_text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    get(v, key).as_str()
}

pub fn uint(v: &Value, key: &str) -> u64 {
    get(v, key).as_u64().unwrap_or(u64::MAX)
}

pub fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    get(v, key).as_array().map_or(&[], Vec::as_slice)
}

/// Parse a kebab-case wire word into a contract enum.
pub fn wire<T: DeserializeOwned>(word: &str) -> T {
    serde_json::from_value(Value::String(word.to_owned()))
        .unwrap_or_else(|_| panic!("unknown wire value {word:?}"))
}

/// The wire word of a contract enum.
pub fn word<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(s)) => s,
        other => panic!("not a wire word: {other:?}"),
    }
}
