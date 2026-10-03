use std::process::ExitCode;

use pii_eval_cli::{Outcome, interpret};

fn main() -> ExitCode {
    match interpret(std::env::args().skip(1)) {
        Outcome::Print(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Outcome::Usage(text) => {
            eprintln!("{text}");
            ExitCode::from(2)
        }
    }
}
