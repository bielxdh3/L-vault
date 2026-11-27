use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const CHUNK_SIZE: usize = 1024 * 1024;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// One already ordered catalog row needed for hash verification.
#[derive(Debug, Clone, Copy)]
pub struct CatalogRecord<'a> {
    pub path: &'a Path,
    pub expected_sha256: &'a str,
}

/// Why a catalog row did not match its expected digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogFailureKind {
    Missing,
    DigestMismatch,
}

/// A failed catalog row, borrowing its original path.
#[derive(Debug, PartialEq, Eq)]
pub struct CatalogFailure<'a> {
    pub path: &'a Path,
    pub kind: CatalogFailureKind,
}

/// Match and failure projection over the rows visited.
#[derive(Debug, PartialEq, Eq)]
pub struct CatalogProjection<'a> {
    pub matches: usize,
    pub failures: Vec<CatalogFailure<'a>>,
}

/// Hash a file using lowercase SHA-256 hex and read-only streaming I/O.
pub fn sha256_file(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(lowercase_hex(&hasher.finalize()))
}

/// Compare a file's SHA-256 digest with the expected lowercase hex string.
pub fn verify_file(path: impl AsRef<Path>, expected_sha256: &str) -> io::Result<bool> {
    Ok(sha256_file(path)? == expected_sha256)
}

/// Verify an ordered stream of catalog rows without a database or report formatting.
///
/// Only matching rows consume `sample_limit`; `None` and `Some(0)` are unlimited.
/// Missing paths are reported from the existence check. Later I/O errors propagate
/// unchanged, including their raw OS code when available.
///
/// This preserves Python's missing-file and read/open error behavior while leaving
/// report wording and persistence to its existing caller.
pub fn verify_catalog_records<'a>(
    records: impl IntoIterator<Item = CatalogRecord<'a>>,
    sample_limit: Option<usize>,
) -> io::Result<CatalogProjection<'a>> {
    verify_catalog_records_with(
        records,
        sample_limit,
        |path| path.try_exists(),
        |path, expected_sha256| verify_file(path, expected_sha256),
    )
}

fn verify_catalog_records_with<'a>(
    records: impl IntoIterator<Item = CatalogRecord<'a>>,
    sample_limit: Option<usize>,
    mut path_exists: impl FnMut(&Path) -> io::Result<bool>,
    mut verify: impl FnMut(&Path, &str) -> io::Result<bool>,
) -> io::Result<CatalogProjection<'a>> {
    let mut projection = CatalogProjection {
        matches: 0,
        failures: Vec::new(),
    };

    for record in records {
        if !path_exists(record.path)? {
            projection.failures.push(CatalogFailure {
                path: record.path,
                kind: CatalogFailureKind::Missing,
            });
        } else if verify(record.path, record.expected_sha256)? {
            projection.matches += 1;
        } else {
            projection.failures.push(CatalogFailure {
                path: record.path,
                kind: CatalogFailureKind::DigestMismatch,
            });
        }

        if sample_limit.is_some_and(|limit| limit > 0 && projection.matches >= limit) {
            break;
        }
    }

    Ok(projection)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_not_found_if_file_disappears_after_existence_check() {
        let path = Path::new("synthetic/raced-away");
        let mut existence_checks = 0;
        let mut open_attempts = 0;

        let result = verify_catalog_records_with(
            [CatalogRecord {
                path,
                expected_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            }],
            None,
            |checked_path| {
                existence_checks += 1;
                assert_eq!(checked_path, path);
                Ok(true)
            },
            |opened_path, _| {
                open_attempts += 1;
                assert_eq!(opened_path, path);
                Err(io::Error::from_raw_os_error(2))
            },
        );

        let error = result.expect_err("a failed open after existence must propagate");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.raw_os_error(), Some(2));
        assert_eq!(existence_checks, 1);
        assert_eq!(open_attempts, 1);
    }
}
