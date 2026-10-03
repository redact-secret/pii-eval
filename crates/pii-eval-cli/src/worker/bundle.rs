//! `pii-eval-bundle/1`: a deterministic, strictly parsed archive of regular
//! files (PROPOSED, engine-owned, opaque to the custodian; Q4).
//!
//! Layout, byte for byte:
//!
//! ```text
//! pii-eval-bundle/1\n
//! <header length, decimal ASCII, no leading zeros, at most 8 digits>\n
//! <header: compact JSON, keys sorted, exactly that many bytes>\n
//! <the members' bytes, concatenated in header order, nothing after them>
//! ```
//!
//! The header is `{"members":[{"executable":bool,"path":str,"sha256":hex,"size":n},...]}`
//! with members sorted by path (byte order) and unique. The parser re-renders
//! the parsed header and requires byte equality, so there is exactly one
//! encoding of a bundle: the same files always give the same bytes and digest.
//! There are no symlinks, directories, hard links, devices or permissions
//! other than the executable flag, so none can be smuggled in.
//!
//! This reader is the only extractor. Member paths follow the custodian's
//! `validate_member_path` (no absolute path, `..`, `.`, empty component,
//! backslash or control character, at most 255 bytes and 8 components) and the
//! tree digest's name rule (printable ASCII). Bounds: [`MAX_MEMBERS`],
//! [`MAX_MEMBER_BYTES`], [`MAX_TOTAL_BYTES`], [`MAX_HEADER_BYTES`]. Members are
//! written with `create_new` under a destination this module creates, so
//! nothing existing is overwritten or followed, and every directory is created
//! mode 0700, every file 0600 (0700 when executable).

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use pii_eval_contracts::{ParseLimits, Sha256Digest, parse_strict};
use serde_json::{Value, json};

use crate::worker::contract::BundleError;

/// First line of every bundle.
pub const MAGIC: &str = "pii-eval-bundle/1";
/// Most members.
pub const MAX_MEMBERS: usize = 4096;
/// Largest member, in bytes.
pub const MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
/// Largest sum of member sizes, in bytes.
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Largest header, in bytes.
pub const MAX_HEADER_BYTES: usize = 2 * 1024 * 1024;
/// Longest member path, in bytes.
pub const MAX_PATH_BYTES: usize = 255;
/// Most components of a member path.
pub const MAX_PATH_COMPONENTS: usize = 8;

/// One file of a bundle, for [`encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Relative `/`-separated path.
    pub path: String,
    /// Content.
    pub bytes: Vec<u8>,
    /// Executable flag.
    pub executable: bool,
}

/// A member path the format accepts.
pub fn path_is_safe(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_BYTES || p.starts_with('/') || p.contains('\\') {
        return false;
    }
    if !p.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return false;
    }
    let parts: Vec<&str> = p.split('/').collect();
    parts.len() <= MAX_PATH_COMPONENTS
        && parts
            .iter()
            .all(|c| !c.is_empty() && *c != "." && *c != "..")
}

fn header_value(members: &[(String, u64, Sha256Digest, bool)]) -> Value {
    json!({"members": members.iter().map(|(p, s, d, x)| {
        json!({"executable": x, "path": p, "sha256": d.as_str(), "size": s})
    }).collect::<Vec<_>>()})
}

/// Encode files into the one canonical bundle. Fails on any input the reader
/// would refuse (paths, duplicates, bounds).
pub fn encode(members: &[Member]) -> Result<Vec<u8>, BundleError> {
    let mut sorted: Vec<&Member> = members.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    if sorted.is_empty() || sorted.len() > MAX_MEMBERS {
        return Err(BundleError::Limit);
    }
    let mut rows = Vec::new();
    let mut total = 0u64;
    for m in &sorted {
        if !path_is_safe(&m.path) {
            return Err(BundleError::Path);
        }
        let size = m.bytes.len() as u64;
        total += size;
        if size > MAX_MEMBER_BYTES || total > MAX_TOTAL_BYTES {
            return Err(BundleError::Limit);
        }
        rows.push((
            m.path.clone(),
            size,
            Sha256Digest::of_bytes(&m.bytes),
            m.executable,
        ));
    }
    if rows.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(BundleError::Duplicate);
    }
    check_tree_shape(rows.iter().map(|r| r.0.as_str()))?;
    let header = header_value(&rows).to_string();
    let mut out = format!("{MAGIC}\n{}\n{header}\n", header.len()).into_bytes();
    for m in sorted {
        out.extend_from_slice(&m.bytes);
    }
    Ok(out)
}

/// No path may be both a file and a directory prefix of another path.
fn check_tree_shape<'a>(paths: impl Iterator<Item = &'a str>) -> Result<(), BundleError> {
    let mut files: BTreeSet<&str> = BTreeSet::new();
    for p in paths {
        let mut at = 0;
        while let Some(i) = p[at..].find('/') {
            at += i;
            if files.contains(&p[..at]) {
                return Err(BundleError::Duplicate);
            }
            at += 1;
        }
        files.insert(p);
    }
    Ok(())
}

fn read_line(r: &mut impl BufRead, max: usize) -> Result<String, BundleError> {
    let mut line = Vec::new();
    r.by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| BundleError::Malformed)?;
    if line.last() != Some(&b'\n') {
        return Err(BundleError::Malformed);
    }
    line.pop();
    if line.len() > max {
        return Err(BundleError::Malformed);
    }
    String::from_utf8(line).map_err(|_| BundleError::Malformed)
}

struct Row {
    path: String,
    size: u64,
    sha256: Sha256Digest,
    executable: bool,
}

fn parse_header(bytes: &[u8]) -> Result<Vec<Row>, BundleError> {
    let value = parse_strict(
        bytes,
        &ParseLimits {
            max_bytes: MAX_HEADER_BYTES,
            max_depth: 4,
        },
    )
    .map_err(|_| BundleError::Malformed)?;
    let top = value.as_object().ok_or(BundleError::Malformed)?;
    if top.len() != 1 {
        return Err(BundleError::Malformed);
    }
    let list = top
        .get("members")
        .and_then(Value::as_array)
        .ok_or(BundleError::Malformed)?;
    if list.is_empty() || list.len() > MAX_MEMBERS {
        return Err(BundleError::Limit);
    }
    let mut rows = Vec::with_capacity(list.len());
    let mut total = 0u64;
    for item in list {
        let m = item.as_object().ok_or(BundleError::Malformed)?;
        if m.len() != 4 {
            return Err(BundleError::Malformed);
        }
        let path = m
            .get("path")
            .and_then(Value::as_str)
            .ok_or(BundleError::Malformed)?;
        if !path_is_safe(path) {
            return Err(BundleError::Path);
        }
        let size = m
            .get("size")
            .and_then(Value::as_u64)
            .ok_or(BundleError::Malformed)?;
        total = total.checked_add(size).ok_or(BundleError::Limit)?;
        if size > MAX_MEMBER_BYTES || total > MAX_TOTAL_BYTES {
            return Err(BundleError::Limit);
        }
        let sha256 = m
            .get("sha256")
            .and_then(Value::as_str)
            .and_then(|s| Sha256Digest::new(s).ok())
            .ok_or(BundleError::Malformed)?;
        let executable = m
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or(BundleError::Malformed)?;
        rows.push(Row {
            path: path.to_owned(),
            size,
            sha256,
            executable,
        });
    }
    // Sorted and unique, and re-rendering must reproduce the bytes.
    if rows
        .windows(2)
        .any(|w| w[0].path.as_bytes() > w[1].path.as_bytes())
    {
        return Err(BundleError::Malformed);
    }
    if rows.windows(2).any(|w| w[0].path == w[1].path) {
        return Err(BundleError::Duplicate);
    }
    check_tree_shape(rows.iter().map(|r| r.path.as_str()))?;
    let again = header_value(
        &rows
            .iter()
            .map(|r| (r.path.clone(), r.size, r.sha256.clone(), r.executable))
            .collect::<Vec<_>>(),
    )
    .to_string();
    if again.as_bytes() != bytes {
        return Err(BundleError::Malformed);
    }
    Ok(rows)
}

fn create_private_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(path)
}

/// Extract `archive` into the NEW directory `dest`. On any error the partial
/// destination is removed. Reads the archive once, in order.
pub fn extract(archive: &Path, dest: &Path) -> Result<(), BundleError> {
    let file = std::fs::File::open(archive).map_err(|_| BundleError::Malformed)?;
    let mut r = BufReader::new(file);
    if read_line(&mut r, MAGIC.len())? != MAGIC {
        return Err(BundleError::Malformed);
    }
    let len_text = read_line(&mut r, 8)?;
    if len_text.is_empty()
        || !len_text.bytes().all(|b| b.is_ascii_digit())
        || (len_text.len() > 1 && len_text.starts_with('0'))
    {
        return Err(BundleError::Malformed);
    }
    let header_len: usize = len_text.parse().map_err(|_| BundleError::Malformed)?;
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(BundleError::Limit);
    }
    let mut header = vec![0u8; header_len];
    r.read_exact(&mut header)
        .map_err(|_| BundleError::Malformed)?;
    let mut nl = [0u8; 1];
    r.read_exact(&mut nl).map_err(|_| BundleError::Malformed)?;
    if nl[0] != b'\n' {
        return Err(BundleError::Malformed);
    }
    let rows = parse_header(&header)?;
    drop(header);

    create_private_dir(dest, false).map_err(|_| BundleError::Extract)?;
    let result = write_members(&mut r, &rows, dest);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(dest);
    }
    result
}

fn write_members(r: &mut impl Read, rows: &[Row], dest: &Path) -> Result<(), BundleError> {
    for row in rows {
        let mut bytes = Vec::new();
        r.by_ref()
            .take(row.size)
            .read_to_end(&mut bytes)
            .map_err(|_| BundleError::Malformed)?;
        if bytes.len() as u64 != row.size {
            return Err(BundleError::Malformed);
        }
        if Sha256Digest::of_bytes(&bytes) != row.sha256 {
            return Err(BundleError::MemberDigest);
        }
        let target = dest.join(&row.path);
        if !target.starts_with(dest) {
            return Err(BundleError::Path);
        }
        if let Some(parent) = target.parent() {
            if parent != dest {
                create_private_dir(parent, true).map_err(|_| BundleError::Extract)?;
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(
            &mut options,
            if row.executable { 0o700 } else { 0o600 },
        );
        let mut out = options.open(&target).map_err(|_| BundleError::Extract)?;
        out.write_all(&bytes).map_err(|_| BundleError::Extract)?;
        out.sync_all().map_err(|_| BundleError::Extract)?;
    }
    let mut extra = [0u8; 1];
    match r.read(&mut extra) {
        Ok(0) => Ok(()),
        _ => Err(BundleError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(path: &str, bytes: &[u8]) -> Member {
        Member {
            path: path.to_owned(),
            bytes: bytes.to_vec(),
            executable: false,
        }
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("pii-eval-bundle-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn encoding_is_deterministic_and_order_independent() {
        let a = encode(&[m("b/c.js", b"2"), m("a.js", b"1")]).unwrap();
        let b = encode(&[m("a.js", b"1"), m("b/c.js", b"2")]).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with(b"pii-eval-bundle/1\n"));
    }

    #[test]
    fn a_bundle_round_trips_into_a_new_directory() {
        let dir = scratch("rt");
        let bytes = encode(&[
            m("lib/index.js", b"export {}"),
            Member {
                path: "run.sh".into(),
                bytes: b"#!/bin/sh".to_vec(),
                executable: true,
            },
        ])
        .unwrap();
        let archive = dir.join("a.bundle");
        std::fs::write(&archive, &bytes).unwrap();
        let dest = dir.join("out");
        extract(&archive, &dest).unwrap();
        assert_eq!(
            std::fs::read(dest.join("lib/index.js")).unwrap(),
            b"export {}"
        );
        // The destination must be new: an existing directory is refused.
        assert_eq!(extract(&archive, &dest), Err(BundleError::Extract));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsafe_paths_duplicates_and_shape_conflicts_are_refused_by_the_encoder() {
        for bad in [
            "",
            "/etc/x",
            "../x",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            "a\nb",
            "./a",
            "é",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert_eq!(encode(&[m(bad, b"x")]), Err(BundleError::Path), "{bad:?}");
        }
        assert_eq!(
            encode(&[m("a", b"1"), m("a", b"2")]),
            Err(BundleError::Duplicate)
        );
        assert_eq!(
            encode(&[m("a", b"1"), m("a/b", b"2")]),
            Err(BundleError::Duplicate)
        );
        assert_eq!(encode(&[]), Err(BundleError::Limit));
    }

    /// A hand-built header, so the reader is tested against bytes the encoder
    /// would never produce.
    fn raw(header: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!("{MAGIC}\n{}\n{header}\n", header.len()).into_bytes();
        v.extend_from_slice(body);
        v
    }

    fn row(path: &str, body: &[u8]) -> String {
        format!(
            r#"{{"executable":false,"path":"{path}","sha256":"{}","size":{}}}"#,
            Sha256Digest::of_bytes(body).as_str(),
            body.len()
        )
    }

    fn try_extract(label: &str, bytes: &[u8]) -> (Result<(), BundleError>, std::path::PathBuf) {
        let dir = scratch(label);
        let archive = dir.join("a.bundle");
        std::fs::write(&archive, bytes).unwrap();
        let r = extract(&archive, &dir.join("out"));
        (r, dir)
    }

    #[test]
    fn the_reader_refuses_hostile_archives_and_leaves_nothing_behind() {
        let good = row("a", b"1");
        let wrap = |rows: &str| format!(r#"{{"members":[{rows}]}}"#);
        let cases: Vec<(&str, Vec<u8>, BundleError)> = vec![
            ("empty", Vec::new(), BundleError::Malformed),
            (
                "magic",
                b"pii-eval-bundle/2\n1\nx\n".to_vec(),
                BundleError::Malformed,
            ),
            (
                "zipslip",
                raw(&wrap(&row("../x", b"1")), b"1"),
                BundleError::Path,
            ),
            (
                "absolute",
                raw(&wrap(&row("/x", b"1")), b"1"),
                BundleError::Path,
            ),
            (
                "backslash",
                raw(&wrap(&row("a\\\\b", b"1")), b"1"),
                BundleError::Path,
            ),
            (
                "control",
                raw(&wrap(&row("a\\u0001b", b"1")), b"1"),
                BundleError::Path,
            ),
            (
                "duplicate",
                raw(&wrap(&format!("{good},{good}")), b"11"),
                BundleError::Duplicate,
            ),
            (
                "unsorted",
                raw(&wrap(&format!("{},{good}", row("b", b"1"))), b"11"),
                BundleError::Malformed,
            ),
            (
                "shape",
                raw(
                    &wrap(&format!("{},{}", row("a", b"1"), row("a/b", b"1"))),
                    b"11",
                ),
                BundleError::Duplicate,
            ),
            (
                "whitespace",
                raw(&format!(" {}", wrap(&good)), b"1"),
                BundleError::Malformed,
            ),
            (
                "extra-key",
                raw(&wrap(&good.replace('}', ",\"mode\":511}")), b"1"),
                BundleError::Malformed,
            ),
            (
                "oversize-member",
                raw(
                    &wrap(&good.replace("\"size\":1", "\"size\":33554433")),
                    b"1",
                ),
                BundleError::Limit,
            ),
            ("digest", raw(&wrap(&good), b"2"), BundleError::MemberDigest),
            ("short", raw(&wrap(&good), b""), BundleError::Malformed),
            ("trailing", raw(&wrap(&good), b"1x"), BundleError::Malformed),
        ];
        for (label, bytes, expected) in cases {
            let (r, dir) = try_extract(label, &bytes);
            assert_eq!(r, Err(expected), "{label}");
            assert!(!dir.join("out").exists(), "{label}: nothing is left behind");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn the_total_size_bound_is_enforced_from_the_header_alone() {
        let one = row("a", b"1").replace("\"size\":1", &format!("\"size\":{MAX_MEMBER_BYTES}"));
        let many: Vec<String> = (0..9)
            .map(|i| one.replace("\"a\"", &format!("\"f{i}\"")))
            .collect();
        let header = format!(r#"{{"members":[{}]}}"#, many.join(","));
        let (r, dir) = try_extract("total", &raw(&header, b""));
        assert_eq!(r, Err(BundleError::Limit));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn too_many_members_are_refused() {
        let members: Vec<Member> = (0..=MAX_MEMBERS)
            .map(|i| m(&format!("f{i:05}"), b""))
            .collect();
        assert_eq!(encode(&members), Err(BundleError::Limit));
    }
}
