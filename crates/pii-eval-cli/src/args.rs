//! Command-line syntax (docs/cli.md). Hand-written: four commands and a few
//! `--name value` options do not justify an argument-parsing dependency
//! (ADR 0010). Every option is long-form, takes exactly one value (`--name value`
//! or `--name=value`), and may appear once unless it is declared repeatable.
//! Errors name the option, never the value.

use std::collections::BTreeMap;

use crate::status::{Failure, reason};

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `--version`.
    Version,
    /// `--help`, `-h` or `help`.
    Help,
    /// `run`.
    Run(RunArgs),
    /// `replay`.
    Replay(ReplayArgs),
    /// `validate`.
    Validate(ValidateArgs),
    /// `compare`.
    Compare(CompareArgs),
}

/// `pii-eval run --config FILE [--out DIR] [--node PATH] [--job-context FILE]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    /// Run configuration file.
    pub config: String,
    /// Output directory (overrides `output.dir` of the configuration).
    pub out: Option<String>,
    /// Absolute path of `node` (overrides the configuration).
    pub node: Option<String>,
    /// Custodian job context file (protected runs).
    pub job_context: Option<String>,
}

/// `pii-eval replay --snapshot FILE --manifest FILE --observation FILE... --out DIR ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayArgs {
    /// Corpus snapshot.
    pub snapshot: String,
    /// Run manifest.
    pub manifest: String,
    /// Observation sets, in any order.
    pub observations: Vec<String>,
    /// The original run artifact (optional; see docs/cli.md).
    pub original: Option<String>,
    /// Expected snapshot digest.
    pub expect_snapshot_digest: Option<String>,
    /// Expected manifest digest.
    pub expect_manifest_digest: Option<String>,
    /// Output directory.
    pub out: String,
    /// Overwrite policy (`refuse` or `replace`).
    pub overwrite: Option<String>,
}

/// `pii-eval validate FILE [--kind KIND] [--snapshot FILE] [--manifest FILE]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateArgs {
    /// The document to validate.
    pub file: String,
    /// Required document kind.
    pub kind: Option<String>,
    /// Snapshot to bind to.
    pub snapshot: Option<String>,
    /// Manifest to bind to.
    pub manifest: Option<String>,
}

/// `pii-eval compare --base FILE --other FILE`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareArgs {
    /// The base artifact.
    pub base: String,
    /// The other artifact.
    pub other: String,
}

struct Opts {
    values: BTreeMap<&'static str, Vec<String>>,
    positional: Vec<String>,
}

impl Opts {
    fn one(&mut self, name: &'static str) -> Option<String> {
        self.values.remove(name).and_then(|mut v| v.pop())
    }

    fn required(&mut self, name: &'static str) -> Result<String, Failure> {
        self.one(name)
            .ok_or_else(|| Failure::usage(reason::MISSING_REQUIRED_OPTION, name))
    }
}

/// `(name, repeatable)`.
type Spec = (&'static str, bool);

fn parse_opts(args: &[String], specs: &[Spec], max_positional: usize) -> Result<Opts, Failure> {
    let mut opts = Opts {
        values: BTreeMap::new(),
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        let Some(flag) = arg.strip_prefix("--") else {
            if arg.starts_with('-') && arg.len() > 1 {
                return Err(Failure::usage(reason::UNKNOWN_OPTION, "short-option"));
            }
            if opts.positional.len() >= max_positional {
                return Err(Failure::usage(reason::UNEXPECTED_ARGUMENT, "positional"));
            }
            opts.positional.push(arg.clone());
            continue;
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (flag, None),
        };
        let Some(&(spec_name, repeat)) = specs.iter().find(|(n, _)| *n == name) else {
            return Err(Failure::usage(reason::UNKNOWN_OPTION, "option"));
        };
        let value = match inline {
            Some(v) => v,
            None => {
                let v = args
                    .get(i)
                    .ok_or_else(|| Failure::usage(reason::MISSING_VALUE, spec_name))?;
                i += 1;
                v.clone()
            }
        };
        let slot = opts.values.entry(spec_name).or_default();
        if !repeat && !slot.is_empty() {
            return Err(Failure::usage(reason::DUPLICATE_OPTION, spec_name));
        }
        slot.push(value);
    }
    Ok(opts)
}

/// Interpret the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Command, Failure> {
    let Some(first) = args.first() else {
        return Err(Failure::usage(reason::MISSING_COMMAND, "command"));
    };
    let rest = &args[1..];
    match first.as_str() {
        "--version" if rest.is_empty() => Ok(Command::Version),
        "--help" | "-h" | "help" if rest.is_empty() => Ok(Command::Help),
        "--version" | "--help" | "-h" | "help" => {
            Err(Failure::usage(reason::UNEXPECTED_ARGUMENT, "positional"))
        }
        "run" => {
            let mut o = parse_opts(
                rest,
                &[
                    ("config", false),
                    ("out", false),
                    ("node", false),
                    ("job-context", false),
                ],
                0,
            )?;
            Ok(Command::Run(RunArgs {
                config: o.required("config")?,
                out: o.one("out"),
                node: o.one("node"),
                job_context: o.one("job-context"),
            }))
        }
        "replay" => {
            let mut o = parse_opts(
                rest,
                &[
                    ("snapshot", false),
                    ("manifest", false),
                    ("observation", true),
                    ("original", false),
                    ("expect-snapshot-digest", false),
                    ("expect-manifest-digest", false),
                    ("out", false),
                    ("overwrite", false),
                ],
                0,
            )?;
            let observations = o.values.remove("observation").unwrap_or_default();
            if observations.is_empty() {
                return Err(Failure::usage(
                    reason::MISSING_REQUIRED_OPTION,
                    "observation",
                ));
            }
            Ok(Command::Replay(ReplayArgs {
                snapshot: o.required("snapshot")?,
                manifest: o.required("manifest")?,
                observations,
                original: o.one("original"),
                expect_snapshot_digest: o.one("expect-snapshot-digest"),
                expect_manifest_digest: o.one("expect-manifest-digest"),
                out: o.required("out")?,
                overwrite: o.one("overwrite"),
            }))
        }
        "validate" => {
            let mut o = parse_opts(
                rest,
                &[("kind", false), ("snapshot", false), ("manifest", false)],
                1,
            )?;
            let file = o
                .positional
                .pop()
                .ok_or_else(|| Failure::usage(reason::MISSING_REQUIRED_OPTION, "file"))?;
            Ok(Command::Validate(ValidateArgs {
                file,
                kind: o.one("kind"),
                snapshot: o.one("snapshot"),
                manifest: o.one("manifest"),
            }))
        }
        "compare" => {
            let mut o = parse_opts(rest, &[("base", false), ("other", false)], 0)?;
            Ok(Command::Compare(CompareArgs {
                base: o.required("base")?,
                other: o.required("other")?,
            }))
        }
        _ => Err(Failure::usage(reason::UNKNOWN_COMMAND, "command")),
    }
}

/// The usage text (stdout for `--help`, stderr for a usage error).
pub const USAGE: &str = "\
usage:
  pii-eval run      --config FILE [--out DIR] [--node PATH] [--job-context FILE]
  pii-eval replay   --snapshot FILE --manifest FILE --observation FILE [--observation FILE]...
                    --out DIR [--original FILE] [--expect-snapshot-digest SHA256]
                    [--expect-manifest-digest SHA256] [--overwrite refuse|replace]
  pii-eval validate FILE [--kind KIND] [--snapshot FILE] [--manifest FILE]
  pii-eval compare  --base FILE --other FILE
  pii-eval --version | --help
stdout: one JSON summary line (pii-eval-summary/1); stderr: diagnostics.
exit codes and syntax: docs/cli.md";

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_each_command() {
        assert_eq!(parse(&a(&["--version"])), Ok(Command::Version));
        let Ok(Command::Run(r)) = parse(&a(&["run", "--config=c.json", "--out", "o"])) else {
            panic!("run")
        };
        assert_eq!((r.config.as_str(), r.out.as_deref()), ("c.json", Some("o")));
        let Ok(Command::Validate(v)) = parse(&a(&["validate", "f.json", "--kind", "manifest"]))
        else {
            panic!("validate")
        };
        assert_eq!(
            (v.file.as_str(), v.kind.as_deref()),
            ("f.json", Some("manifest"))
        );
        let Ok(Command::Replay(p)) = parse(&a(&[
            "replay",
            "--snapshot",
            "s",
            "--manifest",
            "m",
            "--observation",
            "o1",
            "--observation",
            "o2",
            "--out",
            "d",
        ])) else {
            panic!("replay")
        };
        assert_eq!(p.observations, ["o1", "o2"]);
    }

    #[test]
    fn usage_errors_name_the_option_and_never_the_value() {
        let cases: [(&[&str], &str); 8] = [
            (&[], reason::MISSING_COMMAND),
            (&["frobnicate"], reason::UNKNOWN_COMMAND),
            (&["run"], reason::MISSING_REQUIRED_OPTION),
            (&["run", "--config"], reason::MISSING_VALUE),
            (
                &["run", "--config", "a", "--config", "b"],
                reason::DUPLICATE_OPTION,
            ),
            (
                &["run", "--config", "a", "--bogus-secret-value", "x"],
                reason::UNKNOWN_OPTION,
            ),
            (
                &["run", "--config", "a", "extra"],
                reason::UNEXPECTED_ARGUMENT,
            ),
            (&["compare", "--base", "a"], reason::MISSING_REQUIRED_OPTION),
        ];
        for (args, expected) in cases {
            let err = parse(&a(args)).unwrap_err();
            assert_eq!(err.reason, expected, "{args:?}");
            assert_eq!(err.exit, crate::status::Exit::Usage);
            let human = err.human();
            assert!(!human.contains("bogus-secret-value"), "{human}");
        }
    }
}
