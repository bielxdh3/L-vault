use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const FRAME_VERSION: u8 = 2;
const MAX_PATH_BYTES: usize = 65_536;
static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lvault-integrity-session-{}-{}",
            std::process::id(),
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create synthetic fixture directory");
        Self(path)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write synthetic fixture file");
        path
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spawn_session() -> Child {
    Command::new(env!("CARGO_BIN_EXE_lvault-integrity"))
        .arg("hash-session-v2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start lvault-integrity session process")
}

fn write_frame(input: &mut impl Write, path: &[u8]) {
    let length = u32::try_from(path.len()).expect("path length fits the frame header");
    input
        .write_all(&[FRAME_VERSION])
        .expect("write frame version");
    input
        .write_all(&length.to_be_bytes())
        .expect("write frame length");
    input.write_all(path).expect("write path payload");
    input.flush().expect("flush request frame");
}

fn read_reply(output: &mut impl BufRead) -> String {
    let mut line = String::new();
    let bytes = output.read_line(&mut line).expect("read one session reply");
    assert_ne!(
        bytes, 0,
        "session should reply before reading another frame"
    );
    line
}

fn finish(mut child: Child) -> (ExitStatus, String) {
    let status = child.wait().expect("wait for session process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("session stderr is piped")
        .read_to_string(&mut stderr)
        .expect("read session stderr");
    (status, stderr)
}

fn run_with_input(input: &[u8]) -> Output {
    let mut child = spawn_session();
    let _write_result = child
        .stdin
        .take()
        .expect("session stdin is piped")
        .write_all(input);
    child.wait_with_output().expect("collect session output")
}

fn error_code(error: &io::Error) -> String {
    error
        .raw_os_error()
        .map_or_else(|| "-".to_owned(), |code| code.to_string())
}

fn path_bytes(path: &Path) -> &[u8] {
    path.to_str()
        .expect("synthetic fixture path is valid UTF-8")
        .as_bytes()
}

#[test]
fn session_v2_replies_in_lockstep_and_hashes_space_and_unicode_paths() {
    let fixtures = FixtureDir::new();
    let first = fixtures.file("synthetic ' Ω.bin", b"abc");
    let second = fixtures.file("second path.txt", b"hello");
    let mut child = spawn_session();
    let mut input = child.stdin.take().expect("session stdin is piped");
    let mut output = BufReader::new(child.stdout.take().expect("session stdout is piped"));

    write_frame(&mut input, path_bytes(&first));
    assert_eq!(
        read_reply(&mut output),
        "v2\t0\tok\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );

    write_frame(&mut input, path_bytes(&second));
    assert_eq!(
        read_reply(&mut output),
        "v2\t1\tok\t2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
    );

    drop(input);
    let mut trailing = String::new();
    output
        .read_to_string(&mut trailing)
        .expect("read to clean EOF");
    assert!(trailing.is_empty());
    let (status, stderr) = finish(child);
    assert_eq!(status.code(), Some(0));
    assert!(stderr.is_empty());
}

#[test]
fn session_v2_accepts_clean_eof_after_one_request() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("early stop Ω.bin", b"abc");
    let mut child = spawn_session();
    let mut input = child.stdin.take().expect("session stdin is piped");
    let mut output = BufReader::new(child.stdout.take().expect("session stdout is piped"));

    write_frame(&mut input, path_bytes(&path));
    assert_eq!(
        read_reply(&mut output),
        "v2\t0\tok\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );

    drop(input);
    let mut trailing = String::new();
    output
        .read_to_string(&mut trailing)
        .expect("read to clean EOF after one request");
    assert!(trailing.is_empty());
    let (status, stderr) = finish(child);
    assert_eq!(status.code(), Some(0));
    assert!(stderr.is_empty());
}

#[test]
fn session_v2_preserves_native_io_errors_and_continues_with_later_paths() {
    let fixtures = FixtureDir::new();
    let missing = fixtures.0.join("missing.bin");
    let missing_error = File::open(&missing).expect_err("missing synthetic path");
    let directory = fixtures.0.join("directory.bin");
    fs::create_dir(&directory).expect("create synthetic directory fixture");
    let directory_error = lvault_integrity::sha256_file(&directory)
        .expect_err("reading a directory produces a native I/O error");
    assert_ne!(directory_error.kind(), io::ErrorKind::NotFound);
    let good = fixtures.file("after errors.txt", b"abc");

    let mut child = spawn_session();
    let mut input = child.stdin.take().expect("session stdin is piped");
    let mut output = BufReader::new(child.stdout.take().expect("session stdout is piped"));

    write_frame(&mut input, path_bytes(&missing));
    assert_eq!(
        read_reply(&mut output),
        format!("v2\t0\tmissing\t{}\n", error_code(&missing_error))
    );
    write_frame(&mut input, path_bytes(&directory));
    assert_eq!(
        read_reply(&mut output),
        format!("v2\t1\tio\t{}\n", error_code(&directory_error))
    );
    write_frame(&mut input, path_bytes(&good));
    assert_eq!(
        read_reply(&mut output),
        "v2\t2\tok\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );

    drop(input);
    let mut trailing = String::new();
    output
        .read_to_string(&mut trailing)
        .expect("read to clean EOF after I/O errors");
    assert!(trailing.is_empty());
    let (status, stderr) = finish(child);
    assert_eq!(status.code(), Some(1));
    assert!(stderr.is_empty());
}

#[test]
fn session_v2_accepts_maximum_frame_length() {
    let fixtures = FixtureDir::new();
    let prefix = format!("{}{}", fixtures.0.display(), std::path::MAIN_SEPARATOR);
    let path = format!("{prefix}{}", "x".repeat(MAX_PATH_BYTES - prefix.len()));
    assert_eq!(path.len(), MAX_PATH_BYTES);
    let native_error = lvault_integrity::sha256_file(Path::new(&path))
        .expect_err("the maximum-length synthetic path cannot name a fixture file");
    let mut input = Vec::with_capacity(MAX_PATH_BYTES + 5);
    write_frame(&mut input, path.as_bytes());

    let output = run_with_input(&input);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        output.stdout,
        format!("v2\t0\tio\t{}\n", error_code(&native_error)).as_bytes()
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn session_v2_rejects_malformed_and_oversized_frames_deterministically() {
    let oversized = [FRAME_VERSION]
        .into_iter()
        .chain(((MAX_PATH_BYTES as u32) + 1).to_be_bytes())
        .collect::<Vec<_>>();
    let truncated_header = [FRAME_VERSION, 0, 0];
    let truncated_payload = [FRAME_VERSION, 0, 0, 0, 3, b'a'];
    let empty_path = [FRAME_VERSION, 0, 0, 0, 0];
    let invalid_utf8 = [FRAME_VERSION, 0, 0, 0, 1, 0xff];
    let cases: [(&str, &[u8], &str); 6] = [
        (
            "unsupported version",
            &[3],
            "lvault-integrity: session-v2: unsupported frame version\n",
        ),
        (
            "oversized path",
            &oversized,
            "lvault-integrity: session-v2: frame too large\n",
        ),
        (
            "truncated header",
            &truncated_header,
            "lvault-integrity: session-v2: truncated frame\n",
        ),
        (
            "truncated payload",
            &truncated_payload,
            "lvault-integrity: session-v2: truncated frame\n",
        ),
        (
            "empty path",
            &empty_path,
            "lvault-integrity: session-v2: empty path\n",
        ),
        (
            "invalid UTF-8",
            &invalid_utf8,
            "lvault-integrity: session-v2: path is not valid UTF-8\n",
        ),
    ];

    for (name, input, expected_stderr) in cases {
        let output = run_with_input(input);
        assert_eq!(output.status.code(), Some(64), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert_eq!(output.stderr, expected_stderr.as_bytes(), "{name}");
    }
}
