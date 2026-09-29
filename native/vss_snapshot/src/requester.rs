use std::time::{Duration, Instant};

use windows_core::{BSTR, GUID, Interface, PCWSTR, PWSTR};

use crate::{Guid, SnapshotJournal, VolumeGuidPath};

mod bindings {
    // windows-bindgen emits COM ABI glue that triggers general-purpose Clippy lints.
    #![allow(clippy::all)]
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/vss_bindings.rs"));
}

use bindings::{
    CreateVssBackupComponentsInternal, IVssAsync, IVssBackupComponents, IVssBackupComponentsEx2,
    VSS_BT_COPY, VSS_CTX_ALL, VSS_CTX_APP_ROLLBACK, VSS_OBJECT_SNAPSHOT, VSS_S_ASYNC_CANCELLED,
    VSS_S_ASYNC_FINISHED, VSS_S_ASYNC_PENDING, VSS_SNAPSHOT_PROP, VSS_SS_CREATED, VSS_WS_STABLE,
    VSS_WS_WAITING_FOR_BACKUP_COMPLETE, VssFreeSnapshotPropertiesInternal,
};

const SNAPSHOT_OPERATION_TIMEOUT: Duration = Duration::from_secs(12 * 60);
const ASYNC_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotInfo {
    pub snapshot_id: String,
    pub snapshot_set_id: String,
    pub original_volume: String,
    pub device_object: String,
}

pub fn create_snapshots(
    volumes: &[VolumeGuidPath],
    journal: &mut SnapshotJournal,
) -> windows_core::Result<Vec<SnapshotInfo>> {
    // Keep all IVssAsync waits inside one deadline so the Python supervisor can
    // recover from the durable per-job journal before its outer timeout expires.
    let deadline = Instant::now() + SNAPSHOT_OPERATION_TIMEOUT;
    windows_core::init_mta()?;
    let backup = unsafe { CreateVssBackupComponentsInternal()? };
    unsafe {
        backup.InitializeForBackup(&BSTR::new()).ok()?;
        backup.SetContext(VSS_CTX_APP_ROLLBACK).ok()?;
        backup
            .SetBackupState(false, false, VSS_BT_COPY, false)
            .ok()?;
        wait(backup.GatherWriterMetadata()?, deadline)?;

        let set_id = backup.StartSnapshotSet()?;
        let mut pending = Vec::with_capacity(volumes.len());
        for volume in volumes {
            let wide = volume.as_wide_z();
            let snapshot_id = backup.AddToSnapshotSet(PCWSTR(wide.as_ptr()), GUID::default())?;
            journal
                .record_snapshot_id(&format_guid(snapshot_id))
                .map_err(|error| {
                    protocol_error(&format!(
                        "could not persist registered VSS snapshot ID {}: {error}",
                        format_guid(snapshot_id)
                    ))
                })?;
            pending.push((snapshot_id, volume.as_str().to_owned()));
        }

        let mut snapshot_may_exist = false;
        let mut writers_completed = false;
        let result = (|| {
            wait(backup.PrepareForBackup()?, deadline)?;
            gather_and_check_writer_status(&backup, WriterCheckpoint::Prepared, deadline)?;
            snapshot_may_exist = true;
            wait(backup.DoSnapshotSet()?, deadline)?;
            gather_and_check_writer_status(&backup, WriterCheckpoint::SnapshotCreated, deadline)?;
            wait(backup.BackupComplete()?, deadline)?;
            writers_completed = true;
            gather_and_check_writer_status(&backup, WriterCheckpoint::BackupComplete, deadline)?;

            let mut result = Vec::with_capacity(pending.len());
            for (snapshot_id, requested_volume) in &pending {
                let props = SnapshotProperties(get_snapshot_properties(&backup, *snapshot_id)?);
                let original_volume = pwstr_to_string(PWSTR(props.0.m_pwszOriginalVolumeName))?;
                let device_object = pwstr_to_string(PWSTR(props.0.m_pwszSnapshotDeviceObject))?;

                if !original_volume.eq_ignore_ascii_case(requested_volume) {
                    return Err(protocol_error("VSS returned a different original volume"));
                }
                if props.0.m_eStatus != VSS_SS_CREATED {
                    return Err(protocol_error("VSS snapshot is not in the created state"));
                }

                result.push(SnapshotInfo {
                    snapshot_id: format_guid(*snapshot_id),
                    snapshot_set_id: format_guid(set_id),
                    original_volume,
                    device_object,
                });
            }
            Ok(result)
        })();

        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if !writers_completed {
                    let _ = backup.AbortBackup();
                }
                let original = error.to_string();
                drop(backup);
                if snapshot_may_exist {
                    return match rollback_snapshots(&pending) {
                        Ok(()) => match journal.clear_snapshot_ids() {
                            Ok(()) => Err(protocol_error(&format!(
                                "VSS snapshot failed and its partial snapshots were deleted: {original}"
                            ))),
                            Err(journal_error) => Err(protocol_error(&format!(
                                "VSS snapshot failed and partial snapshots were deleted, but the journal could not be cleared: {original}; {journal_error}"
                            ))),
                        },
                        Err(cleanup) => Err(protocol_error(&format!(
                            "VSS snapshot failed: {original}; cleanup needs attention: {cleanup}"
                        ))),
                    };
                }
                return Err(protocol_error(&original));
            }
        };

        // VSS_CTX_APP_ROLLBACK snapshots persist; the caller must retain each exact ID.
        Ok(result)
    }
}

pub fn cleanup_snapshot(snapshot_id: &str) -> windows_core::Result<()> {
    let snapshot_id = Guid::parse(snapshot_id)
        .map_err(|_| protocol_error("invalid snapshot GUID"))?
        .as_vss_guid();
    windows_core::init_mta()?;
    cleanup_snapshot_id(snapshot_id)
}

fn cleanup_snapshot_id(snapshot_id: GUID) -> windows_core::Result<()> {
    let backup = unsafe { CreateVssBackupComponentsInternal()? };
    unsafe {
        backup.InitializeForBackup(&BSTR::new()).ok()?;
        backup.SetContext(VSS_CTX_ALL).ok()?;
        let props = SnapshotProperties(get_snapshot_properties(&backup, snapshot_id)?);
        let exposed = if props.0.m_pwszExposedName.is_null() {
            String::new()
        } else {
            pwstr_to_string(PWSTR(props.0.m_pwszExposedName))?
        };
        drop(props);

        if !exposed.is_empty() {
            let extended: IVssBackupComponentsEx2 = backup.cast()?;
            extended.UnexposeSnapshot(snapshot_id).ok()?;
        }

        let mut deleted = 0i32;
        let mut nondeleted = GUID::default();
        backup
            .DeleteSnapshots(
                snapshot_id,
                VSS_OBJECT_SNAPSHOT,
                false,
                &mut deleted as *mut i32 as *const i32,
                &mut nondeleted as *mut GUID as *const GUID,
            )
            .ok()?;
        if deleted != 1 {
            return Err(protocol_error("VSS did not delete exactly one snapshot"));
        }
        Ok(())
    }
}

fn rollback_snapshots(pending: &[(GUID, String)]) -> Result<(), String> {
    let mut failures = Vec::new();
    for (snapshot_id, _) in pending {
        if let Err(error) = cleanup_snapshot_id(*snapshot_id) {
            failures.push(format!("{}: {error}", format_guid(*snapshot_id)));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

unsafe fn get_snapshot_properties(
    backup: &IVssBackupComponents,
    snapshot_id: GUID,
) -> windows_core::Result<VSS_SNAPSHOT_PROP> {
    let mut props = VSS_SNAPSHOT_PROP::default();
    unsafe { backup.GetSnapshotProperties(snapshot_id, &mut props).ok()? };
    Ok(props)
}

struct SnapshotProperties(VSS_SNAPSHOT_PROP);

impl Drop for SnapshotProperties {
    fn drop(&mut self) {
        unsafe { VssFreeSnapshotPropertiesInternal(&self.0) };
    }
}

fn wait(async_operation: IVssAsync, deadline: Instant) -> windows_core::Result<()> {
    loop {
        let wait_millis = remaining_wait_millis(Instant::now(), deadline)
            .ok_or_else(|| protocol_error("VSS asynchronous operation exceeded its deadline"))?;
        unsafe { async_operation.Wait(wait_millis).ok()? };
        let mut status = windows_core::HRESULT(0);
        let mut reserved = 0i32;
        unsafe {
            async_operation
                .QueryStatus(&mut status, &mut reserved)
                .ok()?
        };
        if Instant::now() >= deadline {
            return Err(protocol_error(
                "VSS asynchronous operation exceeded its deadline",
            ));
        }
        if status == VSS_S_ASYNC_FINISHED {
            return Ok(());
        }
        if status == VSS_S_ASYNC_PENDING {
            if Instant::now() >= deadline {
                return Err(protocol_error(
                    "VSS asynchronous operation exceeded its deadline",
                ));
            }
            continue;
        }
        if status == VSS_S_ASYNC_CANCELLED {
            return Err(windows_core::Error::from_hresult(windows_core::HRESULT(
                0x80004004_u32 as i32,
            )));
        }
        if status.is_err() {
            return Err(windows_core::Error::from_hresult(status));
        }
        return Err(protocol_error("unexpected VSS asynchronous status"));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterCheckpoint {
    Prepared,
    SnapshotCreated,
    BackupComplete,
}

impl WriterCheckpoint {
    fn label(self) -> &'static str {
        match self {
            Self::Prepared => "PrepareForBackup",
            Self::SnapshotCreated => "DoSnapshotSet",
            Self::BackupComplete => "BackupComplete",
        }
    }

    fn state_is_expected(self, state: i32) -> bool {
        match self {
            Self::Prepared | Self::BackupComplete => state == VSS_WS_STABLE,
            // Writers normally wait for the requester's BackupComplete event
            // after the snapshot has completed. Stable is also safe for a writer
            // that did not participate in the snapshot event.
            Self::SnapshotCreated => {
                state == VSS_WS_STABLE || state == VSS_WS_WAITING_FOR_BACKUP_COMPLETE
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WriterStatus {
    writer_id: GUID,
    state: i32,
    failure: windows_core::HRESULT,
}

fn validate_writer_statuses(
    checkpoint: WriterCheckpoint,
    statuses: &[WriterStatus],
) -> Result<(), String> {
    if statuses.is_empty() {
        return Err(format!(
            "VSS returned no writer statuses after {}",
            checkpoint.label()
        ));
    }
    for status in statuses {
        if status.failure.0 != 0 || !checkpoint.state_is_expected(status.state) {
            return Err(format!(
                "VSS writer {} reported state {} and failure HRESULT 0x{:08X} after {}",
                format_guid(status.writer_id),
                status.state,
                status.failure.0 as u32,
                checkpoint.label()
            ));
        }
    }
    Ok(())
}

fn gather_and_check_writer_status(
    backup: &IVssBackupComponents,
    checkpoint: WriterCheckpoint,
    deadline: Instant,
) -> windows_core::Result<()> {
    let async_operation = unsafe { backup.GatherWriterStatus()? };
    wait(async_operation, deadline)?;

    let status_result = (|| {
        let count = unsafe { backup.GetWriterStatusCount()? };
        if count == 0 {
            return Err(protocol_error("VSS returned no writer statuses"));
        }
        let mut statuses = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut instance_id = GUID::default();
            let mut writer_id = GUID::default();
            let mut _writer_name = BSTR::new();
            let mut state = 0i32;
            let mut failure = windows_core::HRESULT(0);
            unsafe {
                backup
                    .GetWriterStatus(
                        index,
                        &mut instance_id,
                        &mut writer_id,
                        &mut _writer_name,
                        &mut state,
                        &mut failure,
                    )
                    .ok()?;
            }
            statuses.push(WriterStatus {
                writer_id,
                state,
                failure,
            });
        }
        validate_writer_statuses(checkpoint, &statuses).map_err(|message| protocol_error(&message))
    })();

    let free_result = unsafe { backup.FreeWriterStatus() }.ok();
    match (status_result, free_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn remaining_wait_millis(now: Instant, deadline: Instant) -> Option<u32> {
    let remaining = deadline.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    let remaining_millis = remaining.as_millis().min(u32::MAX as u128) as u32;
    Some(
        remaining_millis
            .max(1)
            .min(ASYNC_POLL_INTERVAL.as_millis() as u32),
    )
}

fn pwstr_to_string(value: PWSTR) -> windows_core::Result<String> {
    if value.0.is_null() {
        return Err(protocol_error("VSS returned a null string"));
    }
    unsafe {
        value
            .to_string()
            .map_err(|_| protocol_error("VSS returned invalid UTF-16"))
    }
}

fn format_guid(value: GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
}

fn protocol_error(message: &str) -> windows_core::Error {
    windows_core::Error::new(windows_core::HRESULT(0x80004005_u32 as i32), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_guid_round_trips_to_vss_guid_layout() {
        let parsed = Guid::parse("{01234567-89ab-cdef-0123-456789abcdef}").unwrap();
        assert_eq!(format_guid(parsed.as_vss_guid()), parsed.to_string());
    }

    fn writer_status(state: i32, failure: i32) -> WriterStatus {
        WriterStatus {
            writer_id: Guid::parse("{01234567-89ab-cdef-0123-456789abcdef}")
                .unwrap()
                .as_vss_guid(),
            state,
            failure: windows_core::HRESULT(failure),
        }
    }

    #[test]
    fn writer_status_requires_stable_after_prepare_and_backup_complete() {
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::Prepared,
                &[writer_status(VSS_WS_STABLE, 0)]
            )
            .is_ok()
        );
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::BackupComplete,
                &[writer_status(VSS_WS_STABLE, 0)]
            )
            .is_ok()
        );
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::Prepared,
                &[writer_status(VSS_WS_WAITING_FOR_BACKUP_COMPLETE, 0)]
            )
            .is_err()
        );
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::BackupComplete,
                &[writer_status(VSS_WS_WAITING_FOR_BACKUP_COMPLETE, 0)]
            )
            .is_err()
        );
    }

    #[test]
    fn writer_status_allows_only_expected_post_snapshot_state() {
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::SnapshotCreated,
                &[writer_status(VSS_WS_WAITING_FOR_BACKUP_COMPLETE, 0)]
            )
            .is_ok()
        );
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::SnapshotCreated,
                &[writer_status(VSS_WS_STABLE, 0)]
            )
            .is_ok()
        );
        assert!(
            validate_writer_statuses(WriterCheckpoint::SnapshotCreated, &[writer_status(0, 0)])
                .is_err()
        );
    }

    #[test]
    fn writer_failure_hresult_and_empty_status_fail_closed() {
        assert!(validate_writer_statuses(WriterCheckpoint::Prepared, &[]).is_err());
        assert!(
            validate_writer_statuses(
                WriterCheckpoint::Prepared,
                &[writer_status(VSS_WS_STABLE, 0x800423F3u32 as i32)]
            )
            .is_err()
        );
    }

    #[test]
    fn async_wait_slice_is_capped_and_expires_at_the_overall_deadline() {
        let now = Instant::now();
        assert_eq!(
            remaining_wait_millis(now, now + Duration::from_secs(5)),
            Some(1000)
        );
        assert_eq!(
            remaining_wait_millis(now, now + Duration::from_millis(25)),
            Some(25)
        );
        assert_eq!(remaining_wait_millis(now, now), None);
        assert_eq!(
            remaining_wait_millis(now, now - Duration::from_secs(1)),
            None
        );
    }
}
