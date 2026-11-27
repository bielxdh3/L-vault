use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lvault-integrity-cli-{}-{}",
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

    fn entries(&self) -> Vec<OsString> {
        let mut entries = fs::read_dir(&self.0)
            .expect("read synthetic fixture directory")
            .map(|entry| entry.expect("read fixture entry").file_name())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Output {
    let executable = std::env::var_os("CARGO_BIN_EXE_lvault-integrity");
    assert!(
        executable.is_some(),
        "Cargo must provide the lvault-integrity executable for this contract test"
    );

    Command::new(executable.expect("checked executable path"))
        .args(args)
        .output()
        .expect("run lvault-integrity directly without a shell")
}

fn hash_v1_args(paths: &[PathBuf]) -> Vec<OsString> {
    std::iter::once(OsString::from("hash-v1"))
        .chain(paths.iter().map(|path| path.as_os_str().to_owned()))
        .collect()
}

#[test]
fn hash_v1_emits_sha256_for_space_and_unicode_path_without_writes() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("synthetic ' Ω.bin", b"abc");
    let before_bytes = fs::read(&path).expect("read fixture before hashing");
    let before_entries = fixtures.entries();

    let output = run(hash_v1_args(std::slice::from_ref(&path)));

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"v1\t0\tok\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        fs::read(&path).expect("read fixture after hashing"),
        before_bytes
    );
    assert_eq!(fixtures.entries(), before_entries);
}

#[test]
fn hash_v1_reports_missing_path_and_continues_batch_with_raw_os_code() {
    let fixtures = FixtureDir::new();
    let first = fixtures.file("first.bin", b"abc");
    let missing = fixtures.0.join("missing.bin");
    let last = fixtures.file("last.bin", b"hello");
    let missing_error = File::open(&missing).expect_err("missing fixture stays absent");
    let raw_code = missing_error
        .raw_os_error()
        .map_or_else(|| "-".to_owned(), |code| code.to_string());

    let output = run(hash_v1_args(&[first, missing, last]));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout).expect("protocol output is UTF-8"),
        format!(
            "v1\t0\tok\tba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n\
             v1\t1\tmissing\t{raw_code}\n\
             v1\t2\tok\t2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
        )
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn hash_v1_reports_non_missing_io_failure_with_raw_os_code() {
    let fixtures = FixtureDir::new();
    let directory = fixtures.0.join("directory.bin");
    fs::create_dir(&directory).expect("create synthetic directory fixture");
    let expected_error = File::open(&directory).and_then(|mut file| {
        let mut byte = [0; 1];
        file.read(&mut byte)
    });
    let expected_error = expected_error.expect_err("reading a directory fails on this platform");
    assert_ne!(expected_error.kind(), std::io::ErrorKind::NotFound);
    let raw_code = expected_error
        .raw_os_error()
        .map_or_else(|| "-".to_owned(), |code| code.to_string());

    let output = run(hash_v1_args(std::slice::from_ref(&directory)));

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout).expect("protocol output is UTF-8"),
        format!("v1\t0\tio\t{raw_code}\n")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn hash_v1_rejects_batches_over_the_documented_bound() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("payload.bin", b"unchanged");
    let paths = vec![path; 257];

    let output = run(hash_v1_args(&paths));

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
