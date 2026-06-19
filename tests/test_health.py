from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.health import health_snapshot


def test_health_snapshot_flags_missing_index_entries(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    missing = p.gmail_messages / "missing.eml"
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256="hash", path=missing, media_type="email", size=10, source="test")

    health = health_snapshot(p)

    assert health["status"] == "attention"
    assert any(not check["ok"] and check["name"] == "Indice do cofre" for check in health["checks"])


def test_health_snapshot_reports_free_space(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)

    health = health_snapshot(p)

    assert health["free_gb"] > 0
    assert any(check["name"] == "Espaco livre" for check in health["checks"])
