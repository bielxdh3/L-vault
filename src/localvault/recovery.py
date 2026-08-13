from __future__ import annotations

import email.policy
import json
import tempfile
from email.message import EmailMessage
from pathlib import Path
from zipfile import ZipFile

from . import db
from .config import ensure_directories
from .gmail_takeout import ingest_gmail_takeout
from .photos import ingest_photos_takeout
from .reports import RunReport
from .restore import execute_restore, plan_restore
from .utils import sha256_file
from .verify import verify_vault


def run_recovery_test() -> dict[str, object]:
    """Run a bounded recovery drill entirely inside an ephemeral synthetic root."""
    with tempfile.TemporaryDirectory(prefix="localvault-recovery-") as temp_root:
        root = Path(temp_root) / "fixture"
        destination = Path(temp_root) / "restore"
        p = ensure_directories(root)
        db.init_db(p.db)
        archive = _write_fixture_zip(p.google_takeout_inbox / "synthetic-takeout.zip")

        ingest_report = RunReport(source="synthetic", mode="recovery_ingest")
        ingest_photos_takeout(p, ingest_report, zip_paths=[archive])
        ingest_gmail_takeout(p, ingest_report, zip_paths=[archive])

        verify_report = RunReport(source="vault", mode="verify_full")
        verify_vault(p, verify_report)
        integrity_verified = verify_report.failed_count == 0 and verify_report.imported_count > 0

        restore_result = None
        restore_drill_passed = False
        errors: list[str] = []
        if integrity_verified:
            plan = plan_restore(p, destination, limit=1000)
            restore_result = execute_restore(p, plan)
            restore_drill_passed = restore_result.status == "completed" and _restore_matches_index(p, destination)
            if not restore_drill_passed:
                errors.append("Synthetic restore did not match the indexed file contract.")
        else:
            errors.extend(item["error"] for item in verify_report.errors[:5])

        return {
            "schema": 1,
            "status": "passed" if integrity_verified and restore_drill_passed else "failed",
            "integrity_verified": integrity_verified,
            "restore_drill_passed": restore_drill_passed,
            "integrity": {
                "status": "integrity_verified" if integrity_verified else "integrity_failed",
                "checked": verify_report.imported_count,
                "errors": verify_report.failed_count,
            },
            "restore": {
                "status": "restore_drill_passed" if restore_drill_passed else "restore_drill_failed",
                "selected": restore_result.public()["counts"]["selected"] if restore_result else 0,
                "copied": restore_result.public()["counts"]["copied"] if restore_result else 0,
                "bytes": restore_result.public()["counts"]["bytes"] if restore_result else 0,
            },
            "fixture": {"synthetic": True, "temporary": True, "bounded": True},
            "errors": errors[:5],
        }


def _write_fixture_zip(path: Path, marker: str = "synthetic") -> Path:
    message = EmailMessage(policy=email.policy.default)
    message["From"] = "synthetic@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = f"Synthetic recovery fixture {marker}"
    message["Date"] = "Tue, 13 Aug 2026 12:00:00 +0000"
    message["Message-ID"] = "<synthetic-recovery@example.test>"
    message.set_content(f"Synthetic recovery body {marker}")
    message.add_attachment(f"synthetic attachment {marker}".encode(), maintype="application", subtype="octet-stream", filename="fixture.bin")
    message.set_boundary("synthetic-recovery-boundary")
    mbox = b"From synthetic@example.test Tue Aug 13 12:00:00 2026\n" + message.as_bytes(policy=email.policy.default)
    entries = {
        "Takeout/Mail/mail.mbox": mbox,
        "Takeout/Google Photos/2026/08/synthetic-photo.jpg": f"synthetic-photo-{marker}".encode(),
        "Takeout/Google Photos/2026/08/synthetic-video.mp4": f"synthetic-video-{marker}".encode(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def _restore_matches_index(p, destination: Path) -> bool:
    with db.connect(p.db) as conn:
        rows = conn.execute("SELECT path,sha256,size FROM files ORDER BY id").fetchall()
    for row in rows:
        source = Path(row["path"])
        target = destination / source.relative_to((p.root / "vault").resolve())
        if not target.is_file() or target.stat().st_size != int(row["size"] or 0) or sha256_file(target) != row["sha256"]:
            return False
    return bool(rows)

