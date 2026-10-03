//! CLI surface for `pii-eval`.
//!
//! Bootstrap: the only behavior is printing identity for `--version`. The
//! intended `run`, `replay`, `validate` and `compare` workflows are not
//! implemented and have no promised syntax.

pub mod assemble;
pub mod exec;
pub mod run;
pub mod write;

use pii_eval_contracts::{CrateIdentity, ENGINE_NAME, ENGINE_VERSION, Role, WORKSPACE_STAGE};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity =
    CrateIdentity::new(Role::Cli, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

/// The single line printed for `--version`.
pub fn version_line() -> String {
    format!("{ENGINE_NAME} {ENGINE_VERSION} ({WORKSPACE_STAGE})")
}

/// Result of interpreting the command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Print this text to stdout and exit successfully.
    Print(String),
    /// Print this text to stderr and exit with failure status.
    Usage(String),
}

/// Interpret arguments (excluding the program name). Only `--version` is
/// recognized; every other input is a usage error.
pub fn interpret<I, S>(args: I) -> Outcome
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (Some(flag), None) if flag.as_ref() == "--version" => Outcome::Print(version_line()),
        _ => Outcome::Usage(format!(
            "usage: {ENGINE_NAME} --version\nno other command is implemented"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flag_prints_identity() {
        assert_eq!(interpret(["--version"]), Outcome::Print(version_line()));
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        assert!(matches!(interpret(Vec::<&str>::new()), Outcome::Usage(_)));
        assert!(matches!(interpret(["run"]), Outcome::Usage(_)));
        assert!(matches!(interpret(["--version", "x"]), Outcome::Usage(_)));
    }
}
