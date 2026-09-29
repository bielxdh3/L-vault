use std::path::PathBuf;

fn main() {
    let bindings =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("vss_bindings.rs");

    windows_bindgen::builder()
        .output(&bindings)
        .filters([
            "CreateVssBackupComponentsInternal",
            "IVssBackupComponents",
            "IVssBackupComponentsEx2",
            "IVssAsync",
            "VSS_SNAPSHOT_PROP",
            "VSS_SNAPSHOT_CONTEXT",
            "VSS_SNAPSHOT_STATE",
            "VSS_OBJECT_TYPE",
            "VSS_BACKUP_TYPE",
            "VSS_VOLUME_SNAPSHOT_ATTRIBUTES",
            "VSS_WRITER_STATE",
            "VSS_WS_STABLE",
            "VSS_WS_WAITING_FOR_BACKUP_COMPLETE",
            "VssFreeSnapshotPropertiesInternal",
            "VSS_S_ASYNC_FINISHED",
            "VSS_S_ASYNC_PENDING",
            "VSS_S_ASYNC_CANCELLED",
        ])
        .flat()
        .write();
}
