//! Secret material: the webhook secret (and, in a deployment, the App private
//! key). A [`Secret`] cannot be cloned, printed, serialized or compared; its
//! `Debug` is fixed text, it is overwritten when dropped (best effort: Rust
//! gives no guarantee against copies the allocator or the OS made), and it is
//! loaded only from a file with owner-only permissions
//! by the deployment (there is no environment-variable loader: an environment
//! is inherited by children and visible to same-user tools, a file is not). It is never part of a job specification, so a worker
//! cannot receive it.

use std::fmt;

/// Why a secret could not be loaded. Fixed text: no path, no value, no OS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// Shorter than [`Secret::MIN_LEN`].
    TooShort,
    /// Longer than [`Secret::MAX_LEN`].
    TooLong,
    /// The variable or file does not exist or cannot be read.
    Unavailable,
    /// Not a regular file, or readable or writable by group or others.
    InsecureFile,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretError::TooShort => "secret too short",
            SecretError::TooLong => "secret too long",
            SecretError::Unavailable => "secret unavailable",
            SecretError::InsecureFile => "secret file is not a private regular file",
        })
    }
}

impl std::error::Error for SecretError {}

/// Opaque secret bytes.
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    /// Minimum length (GitHub recommends a high-entropy random value).
    pub const MIN_LEN: usize = 32;
    /// Maximum length (a PEM private key fits).
    pub const MAX_LEN: usize = 8192;

    /// Wrap bytes after a length check.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(SecretError::TooShort);
        }
        if bytes.len() > Self::MAX_LEN {
            return Err(SecretError::TooLong);
        }
        Ok(Self { bytes })
    }

    /// Read a file. On Unix it must be a regular file that group and others
    /// cannot read or write (mode `0600` or stricter); a symlink is followed
    /// by the metadata check, so point at the file itself.
    pub fn from_file(path: &std::path::Path) -> Result<Self, SecretError> {
        use std::io::Read;
        let meta = std::fs::metadata(path).map_err(|_| SecretError::Unavailable)?;
        if !meta.is_file() {
            return Err(SecretError::InsecureFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(SecretError::InsecureFile);
            }
        }
        if meta.len() > (Self::MAX_LEN as u64) + 1 {
            return Err(SecretError::TooLong);
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| SecretError::Unavailable)?
            .take((Self::MAX_LEN as u64) + 2)
            .read_to_end(&mut bytes)
            .map_err(|_| SecretError::Unavailable)?;
        Self::new(strip_newline(bytes))
    }

    /// The bytes, for the HMAC and signing code only.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

fn strip_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        std::hint::black_box(&self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-webhook-secret-0123456789-abcdef";

    #[test]
    fn debug_and_errors_never_show_the_value() {
        let s = Secret::new(SENTINEL.as_bytes().to_vec()).unwrap();
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{s:#?}"), "Secret(<redacted>)");
        let e = Secret::new(b"SENTINEL-too-small".to_vec()).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("SENTINEL"));
    }

    #[test]
    fn length_bounds_are_enforced() {
        assert_eq!(
            Secret::new(vec![1; Secret::MIN_LEN - 1]).unwrap_err(),
            SecretError::TooShort
        );
        assert!(Secret::new(vec![1; Secret::MIN_LEN]).is_ok());
        assert_eq!(
            Secret::new(vec![1; Secret::MAX_LEN + 1]).unwrap_err(),
            SecretError::TooLong
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pii-eval-app-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, format!("{SENTINEL}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            Secret::from_file(&path).unwrap_err(),
            SecretError::InsecureFile
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let s = Secret::from_file(&path).unwrap();
        assert_eq!(s.expose(), SENTINEL.as_bytes());
        assert_eq!(
            Secret::from_file(&dir).unwrap_err(),
            SecretError::InsecureFile
        );
        assert_eq!(
            Secret::from_file(&dir.join("missing")).unwrap_err(),
            SecretError::Unavailable
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
