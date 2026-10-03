//! HMAC-SHA256 (RFC 2104) over the reviewed `sha2` hash, and a constant-time
//! comparison. Hand-written because it is fifteen lines and a dedicated crate
//! would add a dependency edge to a security-relevant path (ADR 0011, D4); the
//! implementation is pinned by the RFC 4231 test vectors and GitHub's
//! documented webhook example.

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

/// HMAC-SHA256 of `message` under `key` (any key length).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(Sha256::digest(key).as_slice());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = k;
    let mut opad = k;
    for b in &mut ipad {
        *b ^= 0x36;
    }
    for b in &mut opad {
        *b ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash.as_slice());
    let mut out = [0u8; 32];
    out.copy_from_slice(outer.finalize().as_slice());
    for b in k.iter_mut().chain(ipad.iter_mut()).chain(opad.iter_mut()) {
        *b = 0;
    }
    std::hint::black_box((&k, &ipad, &opad));
    out
}

/// Compare two byte strings without an early exit on the first difference.
/// The lengths are public (a MAC length), so unequal lengths return at once.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Decode exactly `N` bytes of lowercase hexadecimal; anything else is `None`.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let t = text.as_bytes();
    if t.len() != N * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in t.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4231_vectors() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn github_documented_webhook_example() {
        assert_eq!(
            hex(&hmac_sha256(
                b"It's a Secret to Everybody",
                b"Hello, World!"
            )),
            "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        );
    }

    #[test]
    fn comparison_and_hex_helpers() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert_eq!(unhex::<2>("00ff"), Some([0, 255]));
        assert_eq!(unhex::<2>("00FF"), None, "uppercase is not accepted");
        assert_eq!(unhex::<2>("00f"), None);
        assert_eq!(unhex::<2>("00fg"), None);
    }
}
