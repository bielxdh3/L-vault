use std::path::Path;
use std::process::ExitCode;

use lvault_vss_snapshot::{
    JournalPath, SnapshotJournal, cleanup_snapshot, create_snapshots, validate_volumes,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{{\"error\":{}}}", json_string(&message));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("snapshot") => {
            let (journal_path, volume_values) = parse_snapshot_args(args)?;
            let volumes = validate_volumes(&volume_values).map_err(|e| e.to_string())?;
            let journal_path = JournalPath::validate(Path::new(&journal_path))
                .map_err(|error| error.to_string())?;
            let mut journal = SnapshotJournal::create(journal_path)
                .map_err(|error| error.to_string())?;
            let snapshots = create_snapshots(&volumes, &mut journal).map_err(|e| e.to_string())?;
            print!("{{\"snapshots\":[");
            for (index, snapshot) in snapshots.iter().enumerate() {
                if index != 0 {
                    print!(",");
                }
                print!(
                    "{{\"snapshot_id\":{},\"snapshot_set_id\":{},\"original_volume\":{},\"device_object\":{}}}",
                    json_string(&snapshot.snapshot_id),
                    json_string(&snapshot.snapshot_set_id),
                    json_string(&snapshot.original_volume),
                    json_string(&snapshot.device_object),
                );
            }
            println!("]}}");
            Ok(())
        }
        Some("cleanup") => {
            let snapshot_id = parse_one_id(args)?;
            cleanup_snapshot(&snapshot_id).map_err(|e| e.to_string())?;
            println!("{{\"deleted_snapshot_id\":{}}}", json_string(&snapshot_id));
            Ok(())
        }
        _ => Err(r"usage: LVaultVssSnapshot snapshot --journal <protected-job-dir>\vss_snapshot_journal.json --volume '\\?\Volume{GUID}\'... | cleanup --snapshot-id <GUID>".into()),
    }
}

fn parse_snapshot_args<I>(args: I) -> Result<(String, Vec<String>), String>
where
    I: Iterator<Item = String>,
{
    let mut args = args;
    let mut journal = None;
    let mut volumes = Vec::new();
    while let Some(option) = args.next() {
        match option.as_str() {
            "--journal" => {
                if journal.is_some() {
                    return Err("--journal may be specified only once".into());
                }
                journal = Some(args.next().ok_or("--journal requires a value")?);
            }
            "--volume" => volumes.push(args.next().ok_or("--volume requires a value")?),
            _ => return Err(format!("unknown snapshot option: {option}")),
        }
    }
    let journal = journal.ok_or("snapshot requires --journal <path>")?;
    Ok((journal, volumes))
}

fn parse_one_id<I>(mut args: I) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    if args.next().as_deref() != Some("--snapshot-id") {
        return Err("expected --snapshot-id".into());
    }
    let id = args.next().ok_or("--snapshot-id requires a value")?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    lvault_vss_snapshot::Guid::parse(&id).map_err(|e| e.to_string())?;
    Ok(id)
}

fn json_string(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c <= '\u{1f}' => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> std::vec::IntoIter<String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn snapshot_arguments_require_journal_path() {
        assert_eq!(
            parse_snapshot_args(args(&[
                "--volume",
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
            ])),
            Err("snapshot requires --journal <path>".into())
        );
    }

    #[test]
    fn snapshot_arguments_collect_journal_and_volumes() {
        assert_eq!(
            parse_snapshot_args(args(&[
                "--journal",
                r"C:\ProgramData\L-vault\clone-jobs\job-1\vss_snapshot_journal.json",
                "--volume",
                r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\",
                "--volume",
                r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}\",
            ])),
            Ok((
                r"C:\ProgramData\L-vault\clone-jobs\job-1\vss_snapshot_journal.json".into(),
                vec![
                    r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".into(),
                    r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}\".into(),
                ]
            ))
        );
    }

    #[test]
    fn snapshot_arguments_reject_duplicate_journal_and_missing_values() {
        assert!(parse_snapshot_args(args(&["--journal", "a", "--journal", "b"])).is_err());
        assert!(parse_snapshot_args(args(&["--journal"])).is_err());
        assert!(parse_snapshot_args(args(&["--journal", "a", "--volume"])).is_err());
    }
}
