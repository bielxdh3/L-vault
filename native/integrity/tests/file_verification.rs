use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lvault_integrity::{sha256_file, verify_file};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lvault-integrity-{}-{}",
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

    fn entries(&self) -> Vec<String> {
        let mut entries = fs::read_dir(&self.0)
            .expect("read synthetic fixture directory")
            .map(|entry| {
                entry
                    .expect("read fixture entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
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

#[test]
fn hashes_empty_and_abc_as_lowercase_sha256() {
    let fixtures = FixtureDir::new();
    let empty = fixtures.file("empty.bin", b"");
    let abc = fixtures.file("abc.bin", b"abc");

    let empty_digest = sha256_file(&empty).expect("hash empty file");
    let abc_digest = sha256_file(&abc).expect("hash abc file");

    assert_eq!(
        empty_digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        abc_digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(
        abc_digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    );
}

#[test]
fn hashes_multichunk_fixture_to_python_hashlib_vector() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("large.bin", &vec![b'a'; 2 * 1024 * 1024 + 17]);
    let expected = "c2273a45bd6d19d2714b8279b1fd1123bb746e7f7f6331085fb6ecaa30164546";

    assert_eq!(sha256_file(&path).expect("hash large file"), expected);
    assert!(verify_file(&path, expected).expect("verify large file"));
}

#[test]
fn verify_file_returns_mismatch_without_error() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("abc.bin", b"abc");

    assert!(!verify_file(&path, &"0".repeat(64)).expect("digest mismatch is not an I/O error"));
    assert!(
        !verify_file(
            &path,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        )
        .expect("uppercase digest does not match lowercase output")
    );
    assert!(!verify_file(&path, "not-a-sha256").expect("malformed digest does not match"));
}

#[test]
fn verify_file_returns_not_found() {
    let fixtures = FixtureDir::new();
    let missing = fixtures.0.join("missing.bin");

    let error = verify_file(&missing, &"0".repeat(64)).expect_err("missing file must fail closed");

    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn verify_file_leaves_fixture_unchanged() {
    let fixtures = FixtureDir::new();
    let path = fixtures.file("payload.bin", b"hello world");
    let before_bytes = fs::read(&path).expect("read fixture before verification");
    let before_entries = fixtures.entries();

    assert!(
        verify_file(
            &path,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
        .expect("verify fixture")
    );

    assert_eq!(
        fs::read(&path).expect("read fixture after verification"),
        before_bytes
    );
    assert_eq!(fixtures.entries(), before_entries);
}
