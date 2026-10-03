use std::io::Write;
use std::process::ExitCode;

use pii_eval_cli::{execute, internal_error, signals};

fn main() -> ExitCode {
    // A panic message could contain input-derived text: suppress it and report a
    // fixed internal error instead.
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rendered = std::panic::catch_unwind(|| execute(&args, signals::install))
        .unwrap_or_else(|_| internal_error());
    // A closed pipe is not an error of the measurement: ignore write failures.
    let _ = std::io::stdout().write_all(rendered.stdout.as_bytes());
    let _ = std::io::stderr().write_all(rendered.stderr.as_bytes());
    ExitCode::from(rendered.exit.code())
}
