//! Usage: selfhosted-guard REPO_ROOT     selfhosted-guard --self-test
//!
//! As a WASI component: `wasmtime run --dir . selfhosted-guard.wasm .`

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.as_slice() {
        [flag] if flag == "--self-test" => Ok(selfhosted_guard::self_test()),
        [root] => selfhosted_guard::read_workflows(std::path::Path::new(root))
            .and_then(|f| selfhosted_guard::run(&f)),
        _ => {
            eprintln!("usage: selfhosted-guard REPO_ROOT | --self-test");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(o) => {
            print!("{}", o.stdout);
            ExitCode::from(u8::try_from(o.code).unwrap_or(1))
        }
        Err(selfhosted_guard::Crash(msg)) => {
            eprintln!("selfhosted-guard: {msg}");
            ExitCode::from(1)
        }
    }
}
