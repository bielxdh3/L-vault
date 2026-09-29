from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "localvault" / "templates" / "disk_clone.html"
BASE = ROOT / "src" / "localvault" / "templates" / "base.html"
REPLICA = ROOT / "src" / "localvault" / "templates" / "replica.html"


def test_disk_clone_ui_shows_the_assisted_diskgenius_path_and_destructive_boundary():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "DiskGenius 6.1.1" in html
    assert "System Migration" in html
    assert "Hot Migration" in html
    assert "Clone now" in html
    assert "Todos os dados do Seagate serão substituídos" in html
    assert "O progresso e o resultado aparecem no DiskGenius" in html
    assert "O DiskGenius informou que a migração foi concluída com sucesso" in html
    assert "L-vault exclui este disco do mapeamento" in html
    assert "Clonezilla" not in html
    assert "BIOS" not in html
    assert "nonce" not in html.casefold()
    assert "/dev/sd" not in html


def test_replica_and_physical_clone_are_distinct_surfaces():
    replica = REPLICA.read_text(encoding="utf-8")
    base = BASE.read_text(encoding="utf-8")
    clone = TEMPLATE.read_text(encoding="utf-8")
    assert "Réplica de arquivos" in replica
    assert "não é um clone bootável" in replica
    assert 'href="/disk-clone"' in replica
    assert "Réplica de arquivos" in base
    assert "Clone do sistema" in clone


def test_clone_ui_never_claims_a_physical_boot_test_from_structure_alone():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "não inicia o Windows clonado" in html
    assert "boot físico" in html


def test_clone_ui_explains_owner_selection_and_lvault_revalidation():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "Conferi no DiskGenius a origem Kingston e o destino Seagate" in html
    assert "Revalidar identidade do destino" in html
    assert "protected_role.model" in html
    assert "Número de disco" not in html
    assert "partição 2 (100 MiB)" in html
    assert "partições 3–5 são históricas" in html
    assert "fechei o DiskGenius" in html
