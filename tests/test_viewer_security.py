from pathlib import Path
import ssl
import pytest

from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.viewer import TLSConfigurationError, _sanitize_email_html, create_app, validate_tls_files
from localvault.cli import validate_viewer_exposure
import typer


def _app(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    set_password(p.root, "correct horse battery")
    return TestClient(create_app(p.root)), p


def _login(client: TestClient):
    assert client.post("/login", data={"password": "wrong"}, follow_redirects=False).status_code == 401
    assert client.post("/login", data={"password": "correct horse battery"}, follow_redirects=False).status_code == 303


def test_authentication_blocks_data_and_password_rotation_invalidates_session(tmp_path: Path):
    client, p = _app(tmp_path)
    secret = p.config / "auth.json"
    vault_file = p.root / "vault" / "safe.txt"; vault_file.parent.mkdir(parents=True, exist_ok=True); vault_file.write_text("safe")
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/file", params={"path": str(vault_file)}).status_code == 401
    assert client.get("/gmail", headers={"accept": "application/json"}).status_code == 401
    assert client.get("/file", params={"path": str(secret)}).status_code == 401
    assert client.post("/control/run?command=verify").status_code == 401
    _login(client)
    assert client.get("/file", params={"path": str(vault_file)}).text == "safe"
    assert client.get("/file", params={"path": str(secret)}).status_code == 403
    set_password(p.root, "new password")
    assert client.get("/", follow_redirects=False).status_code == 303


def test_csrf_is_required_and_forms_supply_it(tmp_path: Path, monkeypatch):
    client, p = _app(tmp_path)
    _login(client)
    calls = []
    monkeypatch.setattr("localvault.viewer.start_background_command", lambda *_: calls.append(True))
    page = client.get("/control")
    assert 'name="csrf_token"' in page.text
    assert client.post("/control/run?command=verify").status_code == 403
    assert client.post("/control/run?command=verify", data={"csrf_token": "bad"}).status_code == 403
    token = client.cookies.get("session")
    assert token
    import re
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/control/run?command=verify", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
    assert calls == [True]
    assert client.get("/control/run?command=verify").status_code == 405


def test_sanitizer_allows_formatting_and_removes_active_and_remote_content():
    clean = _sanitize_email_html('<p><b>ok</b><i>fine</i></p><ul><li>x</li></ul><table><tr><td>cell</td></tr></table><a href="https://safe.example">link</a><script>x</script><IMG SRC=https://evil.example/x OnErRoR=go() srcset="https://evil/x 2x"><a href=javascript:alert(1)>bad</a><div style="background:url(https://evil/x)">x</div><svg onload=go()>x</svg>')
    for dangerous in ("script", "onerror", "javascript:", "evil.example", "srcset", "background", "<svg"):
        assert dangerous not in clean.lower()
    for safe in ("<b>ok</b>", "<i>fine</i>", "<ul>", "<table>", 'href="https://safe.example"'):
        assert safe in clean


def test_network_binding_requires_loopback_or_lan_opt_in_and_authentication():
    validate_viewer_exposure("127.0.0.1", False, True)
    for host, allow_lan, configured in (("0.0.0.0", False, True), ("0.0.0.0", True, False), ("0.0.0.0", True, True), ("127.0.0.1", False, False)):
        try:
            validate_viewer_exposure(host, allow_lan, configured)
        except typer.BadParameter:
            pass
        else:
            raise AssertionError("unsafe viewer configuration was accepted")


def test_tls_files_require_regular_pair_and_validate_with_ssl_primitive(monkeypatch, tmp_path: Path):
    cert = tmp_path / "synthetic-cert.pem"
    key = tmp_path / "synthetic-key.pem"
    cert.write_text("synthetic certificate", encoding="utf-8")
    key.write_text("synthetic private key", encoding="utf-8")
    calls = []

    def load_cert_chain(_context, *, certfile, keyfile, password=None):
        calls.append((certfile, keyfile))

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load_cert_chain)
    validate_viewer_exposure("0.0.0.0", True, True, True, cert, key)
    assert calls == [(str(cert.resolve()), str(key.resolve()))]

    with pytest.raises(typer.BadParameter):
        validate_viewer_exposure("0.0.0.0", True, True, True, cert, None)


def test_tls_missing_or_invalid_material_is_rejected(tmp_path: Path):
    with pytest.raises(TLSConfigurationError):
        validate_tls_files(tmp_path / "missing-cert.pem", tmp_path / "missing-key.pem")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("invalid", encoding="utf-8")
    key.write_text("invalid", encoding="utf-8")
    with pytest.raises(TLSConfigurationError):
        validate_tls_files(cert, key)


def test_session_cookie_secure_only_when_https_and_foreign_origin_is_rejected(tmp_path: Path):
    client, p = _app(tmp_path)
    plain_login = client.post("/login", data={"password": "correct horse battery"}, follow_redirects=False)
    assert "; Secure" not in plain_login.headers["set-cookie"]

    secure_client = TestClient(create_app(p.root, https_enabled=True), base_url="https://testserver")
    secure_login = secure_client.post("/login", data={"password": "correct horse battery"}, follow_redirects=False)
    assert "; secure" in secure_login.headers["set-cookie"].lower()
    assert secure_client.post("/control/run?command=verify", headers={"origin": "http://evil.example"}).status_code == 403
