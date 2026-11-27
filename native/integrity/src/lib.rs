use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const CHUNK_SIZE: usize = 1024 * 1024;
const HEX: &[u8; 16] = b"0123456789abcdef";

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

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
