use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Guid;

const JOURNAL_FILENAME: &str = "vss_snapshot_journal.json";
const MAX_SNAPSHOT_IDS: usize = 64;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalPath(PathBuf);

impl JournalPath {
    pub fn validate(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid_input("journal path must be absolute"));
        }
        if path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }) {
            return Err(invalid_input(
                "journal path cannot contain . or .. components",
            ));
        }
        if path.file_name().and_then(|name| name.to_str()) != Some(JOURNAL_FILENAME) {
            return Err(invalid_input(
                "journal file must be named vss_snapshot_journal.json",
            ));
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| invalid_input("journal parent directory is required"))?;
        validate_parent_directory_chain(parent)?;

        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !is_regular_non_reparse_file(&metadata) {
                    return Err(invalid_input(
                        "journal target must be a regular non-reparse file",
                    ));
                }
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "journal target already exists",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self(path.to_owned())),
            Err(error) => Err(error),
        }
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

pub struct SnapshotJournal {
    path: JournalPath,
    snapshot_ids: Vec<String>,
}

impl SnapshotJournal {
    /// Exclusively creates a new, initially empty per-job journal.
    pub fn create(path: JournalPath) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.as_path())?;
        verify_open_regular_file(&file)?;
        file.write_all(&serialize_snapshot_ids(&[])?)?;
        file.sync_all()?;
        Ok(Self {
            path,
            snapshot_ids: Vec::new(),
        })
    }

    /// Persists a returned AddToSnapshotSet identifier before another VSS step runs.
    pub fn record_snapshot_id(&mut self, snapshot_id: &str) -> io::Result<()> {
        let canonical_id = canonical_guid(snapshot_id)?;
        if self.snapshot_ids.len() >= MAX_SNAPSHOT_IDS {
            return Err(invalid_input("journal contains too many snapshot IDs"));
        }
        if self.snapshot_ids.iter().any(|known| known == &canonical_id) {
            return Err(invalid_input("duplicate snapshot ID in journal"));
        }

        let mut updated = self.snapshot_ids.clone();
        updated.push(canonical_id);
        replace_journal_atomically(self.path.as_path(), &updated)?;
        self.snapshot_ids = updated;
        Ok(())
    }

    /// Clears IDs only after the caller has successfully removed those exact snapshots.
    pub fn clear_snapshot_ids(&mut self) -> io::Result<()> {
        replace_journal_atomically(self.path.as_path(), &[])?;
        self.snapshot_ids.clear();
        Ok(())
    }

    pub fn snapshot_ids(&self) -> &[String] {
        &self.snapshot_ids
    }
}

pub fn serialize_snapshot_ids(snapshot_ids: &[String]) -> io::Result<Vec<u8>> {
    if snapshot_ids.len() > MAX_SNAPSHOT_IDS {
        return Err(invalid_input("journal contains too many snapshot IDs"));
    }
    let mut canonical_ids = Vec::with_capacity(snapshot_ids.len());
    for snapshot_id in snapshot_ids {
        let canonical_id = canonical_guid(snapshot_id)?;
        if canonical_ids.iter().any(|known| known == &canonical_id) {
            return Err(invalid_input("duplicate snapshot ID in journal"));
        }
        canonical_ids.push(canonical_id);
    }

    let body = canonical_ids
        .iter()
        .map(|snapshot_id| format!("\"{snapshot_id}\""))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!("{{\"snapshot_ids\":[{body}]}}\n").into_bytes())
}

fn canonical_guid(snapshot_id: &str) -> io::Result<String> {
    Guid::parse(snapshot_id)
        .map(|guid| guid.to_string())
        .map_err(|_| invalid_input("snapshot ID must be a GUID"))
}

fn replace_journal_atomically(path: &Path, snapshot_ids: &[String]) -> io::Result<()> {
    validate_parent_for_replace(path)?;
    let bytes = serialize_snapshot_ids(snapshot_ids)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid_input("journal parent directory is required"))?;

    let (temporary_path, mut temporary_file) = create_unique_temporary_file(parent)?;
    let write_result = (|| {
        verify_open_regular_file(&temporary_file)?;
        temporary_file.write_all(&bytes)?;
        temporary_file.sync_all()
    })();
    drop(temporary_file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    Ok(())
}

fn validate_parent_for_replace(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid_input("journal parent directory is required"))?;
    validate_parent_directory_chain(parent)?;
    let target_metadata = fs::symlink_metadata(path)?;
    if !is_regular_non_reparse_file(&target_metadata) {
        return Err(invalid_input(
            "journal target must remain a regular non-reparse file",
        ));
    }
    Ok(())
}

fn validate_parent_directory_chain(parent: &Path) -> io::Result<()> {
    for ancestor in parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || has_reparse_attribute(&metadata) {
            return Err(invalid_input(
                "journal parent path must contain only existing non-reparse directories",
            ));
        }
    }
    Ok(())
}

fn create_unique_temporary_file(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let filename = format!(
            ".{JOURNAL_FILENAME}.{}.{}.tmp",
            std::process::id(),
            sequence
        );
        let path = parent.join(filename);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique journal update file",
    ))
}

fn verify_open_regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if is_regular_non_reparse_file(&metadata) {
        Ok(())
    } else {
        Err(invalid_input(
            "journal handle is not a regular non-reparse file",
        ))
    }
}

fn is_regular_non_reparse_file(metadata: &Metadata) -> bool {
    metadata.is_file() && !has_reparse_attribute(metadata)
}

#[cfg(windows)]
fn has_reparse_attribute(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn has_reparse_attribute(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_directory() -> PathBuf {
        for _ in 0..100 {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lvault-vss-journal-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
        panic!("could not allocate test directory")
    }

    #[test]
    fn journal_schema_serializes_only_canonical_exact_ids() {
        assert_eq!(
            serialize_snapshot_ids(&[]).unwrap(),
            b"{\"snapshot_ids\":[]}\n"
        );
        assert_eq!(
            serialize_snapshot_ids(&[
                "{01234567-89AB-CDEF-0123-456789ABCDEF}".to_owned(),
                "{fedcba98-7654-3210-fedc-ba9876543210}".to_owned(),
            ])
            .unwrap(),
            b"{\"snapshot_ids\":[\"{01234567-89ab-cdef-0123-456789abcdef}\",\"{fedcba98-7654-3210-fedc-ba9876543210}\"]}\n"
        );
    }

    #[test]
    fn journal_serialization_rejects_invalid_or_duplicate_ids() {
        assert!(serialize_snapshot_ids(&["not-a-guid".to_owned()]).is_err());
        assert!(
            serialize_snapshot_ids(&[
                "{01234567-89ab-cdef-0123-456789abcdef}".to_owned(),
                "01234567-89AB-CDEF-0123-456789ABCDEF".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn validates_new_journal_path_and_rejects_wrong_or_existing_targets() {
        let directory = test_directory();
        let journal_path = directory.join(JOURNAL_FILENAME);
        assert_eq!(
            JournalPath::validate(&journal_path).unwrap().as_path(),
            journal_path
        );
        assert!(JournalPath::validate(Path::new("relative/vss_snapshot_journal.json")).is_err());
        assert!(JournalPath::validate(&directory.join("other.json")).is_err());
        assert!(JournalPath::validate(&directory.join("missing").join(JOURNAL_FILENAME)).is_err());

        fs::write(&journal_path, b"existing").unwrap();
        assert_eq!(
            JournalPath::validate(&journal_path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn create_new_and_atomic_updates_keep_exact_json_schema() {
        let directory = test_directory();
        let path = directory.join(JOURNAL_FILENAME);
        let validated = JournalPath::validate(&path).unwrap();
        let stale_validated = validated.clone();
        let mut journal = SnapshotJournal::create(validated).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"snapshot_ids\":[]}\n");
        assert!(SnapshotJournal::create(stale_validated).is_err());
        journal
            .record_snapshot_id("{01234567-89AB-CDEF-0123-456789ABCDEF}")
            .unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{\"snapshot_ids\":[\"{01234567-89ab-cdef-0123-456789abcdef}\"]}\n"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
