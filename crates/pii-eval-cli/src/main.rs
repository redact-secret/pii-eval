use std::io::Write;
use std::process::ExitCode;

use pii_eval_cli::status::Exit;
use pii_eval_cli::{execute_os, internal_error, signals};

fn main() -> ExitCode {
    // A panic message could contain input-derived text: suppress it and report a
    // fixed internal error instead. Arguments are collected as raw OS strings
    // inside the guarded call, so no argument can panic the process.
    std::panic::set_hook(Box::new(|_| {}));
    let rendered = std::panic::catch_unwind(|| {
        execute_os(std::env::args_os().skip(1).collect(), signals::install)
    })
    .unwrap_or_else(|_| internal_error());
    let exit = rendered.exit;
    // A closed pipe (the reader went away) is not a failure of the command;
    // any other error writing the summary is an output failure.
    let mut out = std::io::stdout();
    let written = out
        .write_all(rendered.stdout.as_bytes())
        .and_then(|()| out.flush());
    if let Err(e) = written {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            let _ = std::io::stderr()
                .write_all(b"pii-eval: output-write-failed (output-failure, exit 7): stdout\n");
            return ExitCode::from(Exit::Output.code());
        }
    }
    let _ = std::io::stderr().write_all(rendered.stderr.as_bytes());
    ExitCode::from(exit.code())
}
