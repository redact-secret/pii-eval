use std::io::Write;
use std::process::ExitCode;

use pii_eval_cli::evidence::cmd::execute;
use pii_eval_cli::status::Exit;

fn main() -> ExitCode {
    // A panic message could contain input-derived text: suppress it.
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let rendered = std::panic::catch_unwind(|| execute(&args));
    let Ok(rendered) = rendered else {
        let _ = std::io::stderr().write_all(b"pii-eval-evidence: internal-error\n");
        return ExitCode::from(Exit::Internal.code());
    };
    let mut out = std::io::stdout();
    let _ = out
        .write_all(rendered.stdout.as_bytes())
        .and_then(|()| out.flush());
    let _ = std::io::stderr().write_all(rendered.stderr.as_bytes());
    ExitCode::from(rendered.exit.code())
}
