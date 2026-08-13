from pathlib import Path

from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.viewer import create_app


def _client(tmp_path: Path) -> tuple[TestClient, object]:
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    set_password(p.root, "synthetic-password")
    client = TestClient(create_app(p.root))
    assert client.post("/login", data={"password": "synthetic-password"}, follow_redirects=False).status_code == 303
    return client, p


def test_navigation_exposes_phase_surfaces_and_accessible_status(tmp_path: Path):
    client, _p = _client(tmp_path)

    response = client.get("/")

    assert response.status_code == 200
    for href in ("/gmail", "/fotos", "/backups", "/reports", "/setup", "/restore", "/replica"):
        assert f'href="{href}"' in response.text
    assert 'aria-label="NavegaÃ§Ã£o principal"' in response.text
    assert 'lang="pt-BR"' in response.text


def test_setup_restore_and_replica_pages_are_read_only_and_secret_safe(tmp_path: Path):
    client, p = _client(tmp_path)
    before = p.db.stat().st_mtime_ns

    pages = {
        "/setup": "Configurado",
        "/restore": "DisponÃ­vel pela CLI",
        "/replica": "NÃ£o configurada",
    }
    for path, marker in pages.items():
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.text
        assert "synthetic-password" not in response.text
        assert "auth.json" not in response.text

    assert p.db.stat().st_mtime_ns == before
    assert list(p.logs.iterdir()) == []


def test_empty_states_are_explicit_and_get_does_not_start_backup(tmp_path: Path):
    client, p = _client(tmp_path)

    for path, marker in (("/gmail", "Nenhum e-mail"), ("/fotos", "Nenhuma foto"), ("/backups", "Nenhuma execuÃ§Ã£o"), ("/reports", "Nenhuma execuÃ§Ã£o")):
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.text

    assert client.get("/dashboard/backup-now", follow_redirects=False).status_code == 303
    assert list(p.logs.iterdir()) == []

