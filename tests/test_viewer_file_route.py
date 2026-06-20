from pathlib import Path

from fastapi.testclient import TestClient

from localvault import db
from localvault.config import ensure_directories
from localvault.viewer import create_app


def test_file_route_only_serves_files_inside_vault(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault_file = p.root / "vault" / "sample.txt"
    vault_file.parent.mkdir(parents=True, exist_ok=True)
    vault_file.write_text("ok", encoding="utf-8")
    config_file = p.config / "token.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text("secret", encoding="utf-8")
    client = TestClient(create_app(p.root))

    allowed = client.get("/file", params={"path": str(vault_file)})
    blocked = client.get("/file", params={"path": str(config_file)})
    missing = client.get("/file", params={"path": str(p.root / "vault" / "missing.txt")})

    assert allowed.status_code == 200
    assert allowed.text == "ok"
    assert blocked.status_code == 403
    assert missing.status_code == 404
