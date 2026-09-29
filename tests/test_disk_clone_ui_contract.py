from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "localvault" / "templates" / "disk_clone.html"
BASE = ROOT / "src" / "localvault" / "templates" / "base.html"
REPLICA = ROOT / "src" / "localvault" / "templates" / "replica.html"


def test_clone_ui_is_first_party_and_binds_the_authorized_disk_roles():
    html = TEMPLATE.read_text(encoding="utf-8")
    for expected in (
        "{{ clone_mode }}",
        "source_display.model",
        "source_display.masked_serial",
        "target_display.model",
        "protected_display.model",
        "ALL DATA ON TARGET WILL BE ERASED",
        "Bootable",
        "Clone now",
        "Type <strong>CLONE</strong>",
        "Windows inbox VSS, Storage, and NTFS file-copy facilities",
    ):
        assert expected in html
    for implementation_noise in ("DiskGenius", "Clonezilla", "BIOS", "UEFI", "PowerShell", "BitLocker", "nonce", "/dev/sd", "handoff"):
        assert implementation_noise.casefold() not in html.casefold()
    assert 'action="/disk-clone/start"' in html
    assert 'action="/disk-clone/cancel"' in html
    assert 'action="/disk-clone/recover-vss"' in html
    assert 'aria-live="polite"' in html
    assert "fetch(statusUrl" in html


def test_replica_and_first_party_disk_clone_are_distinct_surfaces():
    replica = REPLICA.read_text(encoding="utf-8")
    base = BASE.read_text(encoding="utf-8")
    clone = TEMPLATE.read_text(encoding="utf-8")
    assert "Réplica de arquivos" in replica
    assert "não é um clone de dados do Windows" in replica
    assert "Clone de dados" in replica
    assert 'href="/disk-clone"' in replica
    assert "Réplica de arquivos" in base
    assert "{{ clone_mode }}" in clone


def test_clone_ui_reports_data_clone_bootability_and_explicit_exclusions():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "No · this is a data clone" in html
    assert "pagefile.sys" in html
    assert "hiberfil.sys" in html
    assert "swapfile.sys" in html
    assert "Junctions and mount-point destinations are not traversed" in html
    assert "unsupported reparse points fail closed" in html
