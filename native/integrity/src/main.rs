use lvault_integrity::sha256_file;
use std::ffi::OsString;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

const MAX_PATHS: usize = 256;
const USAGE: &str = "usage: lvault-integrity hash-v1 <path> [<path> ...] (1 to 256 paths)";

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .as_deref()
        != Some("hash-v1")
    {
        return usage_error();
    }

    let paths: Vec<OsString> = args.take(MAX_PATHS + 1).collect();
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return usage_error();
    }

    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut failed = false;

    for (index, path) in paths.iter().enumerate() {
        match sha256_file(Path::new(path)) {
            Ok(digest) => {
                if writeln!(output, "v1\t{index}\tok\t{digest}").is_err() {
                    return output_error();
                }
            }
            Err(error) => {
                failed = true;
                let status = if error.kind() == io::ErrorKind::NotFound {
                    "missing"
                } else {
                    "io"
                };
                let raw_code = error
                    .raw_os_error()
                    .map_or_else(|| "-".to_owned(), |code| code.to_string());
                if writeln!(output, "v1\t{index}\t{status}\t{raw_code}").is_err() {
                    return output_error();
                }
            }
        }
    }

    if output.flush().is_err() {
        return output_error();
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(64)
}

fn output_error() -> ExitCode {
    eprintln!("lvault-integrity: unable to write protocol output");
    ExitCode::from(1)
}
