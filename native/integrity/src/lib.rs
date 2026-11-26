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
    IoError(io::ErrorKind),
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
/// `NotFound` remains distinct from a digest mismatch and other I/O errors.
///
/// Python's current verifier reports missing files and digest mismatches, but lets
/// non-missing `OSError`s from hashing propagate. This projection retains those
/// failures as `IoError` and leaves Python report wording and persistence unchanged.
pub fn verify_catalog_records<'a>(
    records: impl IntoIterator<Item = CatalogRecord<'a>>,
    sample_limit: Option<usize>,
) -> CatalogProjection<'a> {
    let mut projection = CatalogProjection {
        matches: 0,
        failures: Vec::new(),
    };

    for record in records {
        match verify_file(record.path, record.expected_sha256) {
            Ok(true) => projection.matches += 1,
            Ok(false) => projection.failures.push(CatalogFailure {
                path: record.path,
                kind: CatalogFailureKind::DigestMismatch,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                projection.failures.push(CatalogFailure {
                    path: record.path,
                    kind: CatalogFailureKind::Missing,
                });
            }
            Err(error) => projection.failures.push(CatalogFailure {
                path: record.path,
                kind: CatalogFailureKind::IoError(error.kind()),
            }),
        }

        if sample_limit.is_some_and(|limit| limit > 0 && projection.matches >= limit) {
            break;
        }
    }

    projection
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
