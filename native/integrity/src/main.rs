use lvault_integrity::sha256_file;
use std::ffi::OsString;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::process::ExitCode;

const MAX_PATHS: usize = 256;
const MAX_SESSION_PATH_BYTES: u32 = 65_536;
const SESSION_FRAME_VERSION: u8 = 2;
const USAGE: &str = "usage: lvault-integrity hash-v1 <path> [<path> ...] (1 to 256 paths)";
const SESSION_USAGE: &str =
    "usage: lvault-integrity hash-session-v2 (read framed paths from stdin)";

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .as_deref()
    {
        Some("hash-v1") => run_hash_v1(args),
        Some("hash-session-v2") => {
            if args.next().is_some() {
                eprintln!("{SESSION_USAGE}");
                ExitCode::from(64)
            } else {
                run_session_v2()
            }
        }
        _ => usage_error(),
    }
}

fn run_hash_v1(args: impl Iterator<Item = OsString>) -> ExitCode {
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

fn run_session_v2() -> ExitCode {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    let mut failed = false;
    let mut index = 0usize;

    loop {
        let mut version = [0u8; 1];
        let has_version = loop {
            match input.read(&mut version) {
                Ok(0) => break false,
                Ok(_) => break true,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return session_stdin_error(error),
            }
        };
        if !has_version {
            break;
        }
        if version[0] != SESSION_FRAME_VERSION {
            return session_protocol_error("unsupported frame version");
        }

        let mut length_bytes = [0u8; 4];
        if let Err(error) = input.read_exact(&mut length_bytes) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return session_protocol_error("truncated frame");
            }
            return session_stdin_error(error);
        }
        let length = u32::from_be_bytes(length_bytes);
        if length == 0 {
            return session_protocol_error("empty path");
        }
        if length > MAX_SESSION_PATH_BYTES {
            return session_protocol_error("frame too large");
        }

        let mut path_bytes = vec![0u8; length as usize];
        if let Err(error) = input.read_exact(&mut path_bytes) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return session_protocol_error("truncated frame");
            }
            return session_stdin_error(error);
        }
        let path = match String::from_utf8(path_bytes) {
            Ok(path) => path,
            Err(_) => return session_protocol_error("path is not valid UTF-8"),
        };

        match sha256_file(Path::new(&path)) {
            Ok(digest) => {
                if writeln!(output, "v2\t{index}\tok\t{digest}").is_err() {
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
                if writeln!(output, "v2\t{index}\t{status}\t{raw_code}").is_err() {
                    return output_error();
                }
            }
        }

        if output.flush().is_err() {
            return output_error();
        }
        let Some(next_index) = index.checked_add(1) else {
            return session_protocol_error("request index exhausted");
        };
        index = next_index;
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn session_protocol_error(reason: &str) -> ExitCode {
    eprintln!("lvault-integrity: session-v2: {reason}");
    ExitCode::from(64)
}

fn session_stdin_error(error: io::Error) -> ExitCode {
    let raw_code = error
        .raw_os_error()
        .map_or_else(|| "-".to_owned(), |code| code.to_string());
    eprintln!("lvault-integrity: session-v2: stdin-io\t{raw_code}");
    ExitCode::from(1)
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(64)
}

fn output_error() -> ExitCode {
    eprintln!("lvault-integrity: unable to write protocol output");
    ExitCode::from(1)
}
