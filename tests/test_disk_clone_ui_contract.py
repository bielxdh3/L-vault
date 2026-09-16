from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "localvault" / "templates" / "disk_clone.html"
BASE = ROOT / "src" / "localvault" / "templates" / "base.html"
REPLICA = ROOT / "src" / "localvault" / "templates" / "replica.html"


def test_disk_clone_ui_explains_safe_actions_and_destructive_boundary():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "Clone físico do disco" in html
    assert "Verificar prontidão" in html
    assert "Simular fluxo completo" in html
    assert "não executam Clonezilla contra um disco real" in html
    assert "isso não equivale a um boot test" in html.casefold()
    assert "Quando um clone real for autorizado, este disco será sobrescrito" in html


def test_replica_and_physical_clone_are_distinct_surfaces():
    replica = REPLICA.read_text(encoding="utf-8")
    base = BASE.read_text(encoding="utf-8")
    clone = TEMPLATE.read_text(encoding="utf-8")
    assert "Réplica de arquivos" in replica
    assert "não é um clone bootável" in replica
    assert 'href="/disk-clone"' in replica
    assert "Réplica de arquivos" in base
    assert "Clone físico do disco" in clone


def test_clone_ui_never_claims_bootability_from_structural_verification():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "verificação estrutural" in html
    assert "não equivale a um boot test" in html.casefold()
