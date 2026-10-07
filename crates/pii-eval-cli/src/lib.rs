//! CLI surface for `pii-eval`: `run`, `replay`, `validate` and `compare`.
//!
//! The contract (syntax, configuration, exit codes, stdout and stderr) is
//! `docs/cli.md`; the decisions are `docs/adr/0010-standalone-cli-workflows.md`.
//! The crate's Rust API is internal; consumers use the binary and the versioned
//! JSON it reads and writes.
//!
//! Stdout carries one JSON summary line (`pii-eval-summary/1`) and nothing
//! else; stderr carries one fixed-vocabulary diagnostic line on failure. No
//! command prints raw input, a matched value, a finding or scanner output.

pub mod args;
pub mod assemble;
pub mod cmd_compare;
pub mod cmd_replay;
pub mod cmd_run;
pub mod cmd_validate;
pub mod cmd_worker;
pub mod config;
pub mod evidence;
pub mod exec;
pub mod files;
pub mod projection;
pub mod replay;
pub mod run;
pub mod scanners;
pub mod signals;
pub mod status;
pub mod summary;
pub mod worker;
pub mod write;

use pii_eval_contracts::{CrateIdentity, ENGINE_NAME, ENGINE_VERSION, Role, WORKSPACE_STAGE};

use crate::args::{Command, USAGE};
use crate::exec::CancelToken;
use crate::status::{Exit, Failure};
use crate::summary::{Rendered, render};

/// Identity of this crate.
pub const IDENTITY: CrateIdentity =
    CrateIdentity::new(Role::Cli, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

/// The single line printed for `--version`.
pub fn version_line() -> String {
    #[cfg(feature = "worker-test-adapters")]
    {
        // A build that can run the worker test adapters says so (docs/worker-job.md).
        format!(
            "{ENGINE_NAME} {ENGINE_VERSION} ({WORKSPACE_STAGE}; {})",
            worker::test_adapters::feature_name()
        )
    }
    #[cfg(not(feature = "worker-test-adapters"))]
    {
        format!("{ENGINE_NAME} {ENGINE_VERSION} ({WORKSPACE_STAGE})")
    }
}

/// Run one invocation. `cancel` is called only for `run`, so the signal
/// handlers are installed only when scanners can be launched (a Ctrl-C during
/// `validate` keeps its default behavior).
pub fn execute(args: &[String], cancel: impl FnOnce() -> Result<CancelToken, Failure>) -> Rendered {
    let command = match args::parse(args) {
        Ok(c) => c,
        Err(failure) => {
            let mut rendered = render(None, Err(failure));
            rendered.stderr.push_str(USAGE);
            rendered.stderr.push('\n');
            return rendered;
        }
    };
    match command {
        Command::Version => Rendered {
            exit: Exit::Success,
            stdout: format!("{}\n", version_line()),
            stderr: String::new(),
        },
        Command::Help => Rendered {
            exit: Exit::Success,
            stdout: format!("{USAGE}\n"),
            stderr: String::new(),
        },
        Command::Run(a) => render(
            Some("run"),
            cancel().and_then(|token| cmd_run::run(&a, &token)),
        ),
        Command::WorkerJob(a) => render_worker_result(cmd_worker::worker_job(&a, cancel)),
        Command::Replay(a) => render(Some("replay"), cmd_replay::replay(&a)),
        Command::Validate(a) => render(Some("validate"), cmd_validate::validate(&a)),
        Command::Compare(a) => render(Some("compare"), cmd_compare::compare(&a)),
    }
}

/// The rendering of a worker-job outcome: the result document alone on stdout
/// (no newline), or, for a refusal, NOTHING on stdout and one
/// fixed-vocabulary line on stderr.
pub fn render_worker_result(result: Result<worker::launch::WorkerOutput, Failure>) -> Rendered {
    match result {
        Ok(out) => Rendered {
            exit: Exit::Success,
            stdout: out.result,
            stderr: String::new(),
        },
        Err(failure) => Rendered {
            exit: failure.exit,
            stdout: String::new(),
            stderr: format!("{}\n", failure.human()),
        },
    }
}

/// [`execute`] for raw operating-system arguments: an argument that is not UTF-8
/// is a usage error (exit 2) with the usual summary, never a panic.
pub fn execute_os(
    args: Vec<std::ffi::OsString>,
    cancel: impl FnOnce() -> Result<CancelToken, Failure>,
) -> Rendered {
    let mut text = Vec::with_capacity(args.len());
    for arg in args {
        match arg.into_string() {
            Ok(a) => text.push(a),
            Err(_) => {
                let mut rendered = render(
                    None,
                    Err(Failure::usage(
                        status::reason::INVALID_OPTION_VALUE,
                        "argument (not UTF-8)",
                    )),
                );
                rendered.stderr.push_str(USAGE);
                rendered.stderr.push('\n');
                return rendered;
            }
        }
    }
    execute(&text, cancel)
}

/// The rendering of a panic: a fixed internal-error summary. The panic message
/// is never printed (it could contain input-derived text).
pub fn internal_error() -> Rendered {
    render(
        None,
        Err(Failure::new(Exit::Internal, status::reason::INTERNAL)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_reported_as_a_fixed_internal_error_with_no_text() {
        let r = internal_error();
        assert_eq!(r.exit, Exit::Internal);
        assert!(r.stdout.contains("\"reason\":\"internal-error\""));
        assert!(r.stdout.contains("\"code\":1"));
        assert_eq!(r.stderr.lines().count(), 1);
    }

    #[test]
    fn version_is_plain_text_and_failures_are_summaries() {
        let v = execute(&["--version".to_owned()], || Ok(CancelToken::new()));
        assert_eq!(v.stdout, format!("{}\n", version_line()));
        let bad = execute(&["bogus".to_owned()], || Ok(CancelToken::new()));
        assert_eq!(bad.exit, Exit::Usage);
        assert!(bad.stdout.starts_with('{'));
    }
}
