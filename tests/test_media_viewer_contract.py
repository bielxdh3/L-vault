from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "localvault" / "templates" / "fotos.html"
SCRIPT = ROOT / "src" / "localvault" / "static" / "media_viewer.js"
CSS = ROOT / "src" / "localvault" / "static" / "media_viewer.css"
BASE = ROOT / "src" / "localvault" / "templates" / "base.html"
REPLICA = ROOT / "src" / "localvault" / "templates" / "replica.html"


def test_media_viewer_is_one_top_layer_dialog_not_nested_per_tile():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert html.count('id="media-viewer"') == 1
    assert '<dialog class="media-dialog"' in html
    assert 'data-media-viewer-open' in html
    assert 'href="#preview-' not in html
    assert 'class="preview"' not in html


def test_media_viewer_has_native_escape_cleanup_and_focus_restore():
    js = SCRIPT.read_text(encoding="utf-8")
    assert "showModal" in js
    assert 'dialog.addEventListener("close"' in js
    assert "opener.focus" in js
    assert "Native <dialog> handles Escape" in js
    assert 'event.target === dialog' in js


def test_media_viewer_uses_top_layer_and_viewport_safe_media():
    css = CSS.read_text(encoding="utf-8")
    assert ".media-dialog::backdrop" in css
    assert "100dvh" in css
    assert "max-width: 100%" in css
    assert "max-height: 100%" in css
    assert "object-fit: contain" in css
    assert "prefers-reduced-motion" in css


def test_file_replica_is_not_presented_as_physical_clone():
    replica = REPLICA.read_text(encoding="utf-8")
    base = BASE.read_text(encoding="utf-8")
    assert "Réplica de arquivos" in replica
    assert "não é um clone bootável" in replica
    assert 'href="/disk-clone"' in replica
    assert "Réplica de arquivos" in base
