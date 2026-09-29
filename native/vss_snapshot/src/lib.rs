use std::collections::HashSet;
use std::fmt;

const MAX_VOLUMES: usize = 64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let inner = value
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(value);
        if inner.len() != 36 {
            return Err(InputError("GUID must use the 8-4-4-4-12 form"));
        }
        for (i, b) in inner.bytes().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if b != b'-' {
                    return Err(InputError("GUID has invalid separators"));
                }
            } else if !b.is_ascii_hexdigit() {
                return Err(InputError("GUID contains a non-hexadecimal character"));
            }
        }

        let digits: Vec<u8> = inner.bytes().filter(|b| *b != b'-').collect();
        let mut bytes = [0u8; 16];
        for (i, pair) in digits.chunks_exact(2).enumerate() {
            bytes[i] = (hex(pair[0])? << 4) | hex(pair[1])?;
        }
        Ok(Self(bytes))
    }

    pub fn as_vss_guid(&self) -> windows_core::GUID {
        let b = &self.0;
        windows_core::GUID {
            data1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_be_bytes([b[4], b[5]]),
            data3: u16::from_be_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeGuidPath(String);

impl VolumeGuidPath {
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let Some(rest) = value.strip_prefix(r"\\?\Volume{") else {
            return Err(InputError(
                "volume must be a canonical \\\\?\\Volume{GUID}\\ path",
            ));
        };
        let Some(guid_text) = rest.strip_suffix(r"}\") else {
            return Err(InputError("volume GUID path must end with a backslash"));
        };
        Guid::parse(guid_text)?;
        Ok(Self(format!(r"\\?\Volume{{{guid_text}}}\")))
    }

    fn as_wide_z(&self) -> Vec<u16> {
        self.0.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputError(&'static str);

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InputError {}

pub fn validate_volumes(values: &[String]) -> Result<Vec<VolumeGuidPath>, InputError> {
    if values.is_empty() {
        return Err(InputError("at least one volume GUID is required"));
    }
    if values.len() > MAX_VOLUMES {
        return Err(InputError("too many volumes (maximum is 64)"));
    }

    let mut seen = HashSet::new();
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let path = VolumeGuidPath::parse(value)?;
        if !seen.insert(path.as_str().to_ascii_lowercase()) {
            return Err(InputError("duplicate volume GUID"));
        }
        paths.push(path);
    }
    Ok(paths)
}

fn hex(value: u8) -> Result<u8, InputError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(InputError("GUID contains a non-hexadecimal character")),
    }
}

#[cfg(windows)]
mod requester;

mod journal;

pub use journal::{JournalPath, SnapshotJournal, serialize_snapshot_ids};

#[cfg(windows)]
pub use requester::{SnapshotInfo, cleanup_snapshot, create_snapshots};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_guid() {
        let guid = Guid::parse("{01234567-89ab-cdef-0123-456789abcdef}").unwrap();
        assert_eq!(guid.to_string(), "{01234567-89ab-cdef-0123-456789abcdef}");
    }

    #[test]
    fn rejects_malformed_guid() {
        for value in ["", "not-a-guid", "0123456789ab-cdef-0123-456789abcdef"] {
            assert!(Guid::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn accepts_only_canonical_volume_guid_paths() {
        let path =
            VolumeGuidPath::parse(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\").unwrap();
        assert_eq!(
            path.as_str(),
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
        );
        for value in [
            r"C:\",
            r"\Device\HarddiskVolume1\",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\subdir\",
        ] {
            assert!(VolumeGuidPath::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rejects_duplicate_volume_paths_case_insensitively() {
        let values = vec![
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_string(),
            r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\".to_string(),
        ];
        assert!(validate_volumes(&values).is_err());
    }

    #[test]
    fn requires_a_bounded_nonempty_volume_list() {
        assert!(validate_volumes(&[]).is_err());
        let values = (0..65)
            .map(|i| format!(r"\\?\Volume{{00000000-0000-0000-0000-{i:012x}}}\"))
            .collect::<Vec<_>>();
        assert!(validate_volumes(&values).is_err());
    }
}
