from __future__ import annotations

import logging
import os
import json
import subprocess
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path
from typing import Callable, Optional

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from . import __version__, db
from .config import DEFAULT_ROOT, ensure_config, ensure_directories, load_config, paths
from .auth import auth_path, load_auth, set_password
from .auto_takeout import auto_takeout as run_auto_takeout
from .dedupe import build_duplicate_report
from .disk_clone import (
    CloneService,
    DiskCloneBlocked,
    EnrollmentStore,
    WindowsProtectedPathResolver,
    WindowsDiskInventory,
    WindowsDiskLifecycle,
    _source_paths,
    disk_clone_dashboard_data,
    protected_path_conflicts,
    provider_for_config,
    resolved_protected_path_conflicts,
    validate_disk_clone_config,
    validated_disk_clone_config,
)
from .disk_clone_ui import native_countdown, run_native_ui
from .offline_clone import OfflineCloneBlocked, ProductionOfflineSignatureVerifier, simulate_offline_round_trip
from .clonezilla_artifacts import (
    acquire_official_bundle,
    inspect_local_attestor,
    provision_official_public_keyring,
    GpgDetachedSigner,
    TrustedClonezillaExtractor,
    build_production_extraction_manifest,
    write_official_artifact_record,
    verify_official_bundle,
)
from .offline_runtime import (
    CLONEZILLA_SIGNER_FINGERPRINT,
    CLONEZILLA_STABLE_AMD64_ISO_FILENAME,
    CLONEZILLA_STABLE_AMD64_ISO_SHA256,
    LocalExtractionAttestationVerifier,
    OfficialChecksumVerifier,
    OfflineRuntimeValidator,
    REQUIRED_RUNTIME_TOOLS,
    RUNTIME_VALIDATION_PROFILE_PRODUCTION_STATIC,
    RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST,
    simulate_virtual_offline_round_trip,
)
from .gmail_api import backup_gmail_api as run_gmail_api
from .gmail_audit import audit_gmail_duplicates, repair_stale_gmail_runs
from .gmail_maintenance import rename_existing_gmail_files
from .gmail_takeout import ingest_gmail_takeout
from .health import health_snapshot
from .locks import BackupLock
from .migrations import migrate_to_takeout_photos
from .photos import ingest_photos_takeout, scan_existing_media
from .recovery import run_recovery_test
from .replica import ReplicaValidationError, execute_replica, plan_replica
from .reports import RunReport, finish_run, mark_stale_running_runs, start_run
from .restore import RestoreValidationError, execute_restore, plan_restore
from .scheduler import generate_schedule_files, list_windows_tasks, merge_automation_config, run_powershell_script
from .source_sync import sync_sources as run_source_sync
from .utils import atomic_write_text, cleanup_stale_temp_files, free_space_bytes, utc_now
from .verify import verify_vault
from .viewer import TLSConfigurationError, create_app, validate_tls_files
from .vault_index import cleanup_missing_index_entries

app = typer.Typer(help="LocalVault Backup Manager", invoke_without_command=True)
console = Console()


def root_option() -> Path:
    return typer.Option(DEFAULT_ROOT, "--root", help="LocalVault root folder.")


def dry_option() -> bool:
    return typer.Option(False, "--dry-run", help="Preview work without copying or indexing data.")


def prepare(root: Path):
    p = ensure_directories(root)
    db.init_db(p.db)
    cleanup_stale_temp_files(p.root)
    mark_stale_running_runs(p.db)
    migrate_to_takeout_photos(p)
    configure_logging(p.logs)
    return p


def _read_signature_file(path: Optional[Path]) -> bytes | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise typer.BadParameter("signature file is missing, unsafe, or oversized")
    return path.read_bytes()


def configure_logging(logs_dir: Path) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=logs_dir / f"localvault_{utc_now().replace(':','').replace('+','Z')}.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", force=True)


def _human_size(size_bytes: int) -> str:
    size = float(max(size_bytes, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if size < 1024 or unit == "PiB":
            return f"{size:.1f} {unit}"
        size /= 1024


PROTECTED_COMMANDS = {
    "api",
    "auto_takeout",
    "daily_backup",
    "ingest_all",
    "photos_and_gmail",
    "takeout",
}


def run_with_report(root: Path, source: str, mode: str, func, dry_run: bool = False, protected: bool | None = None, *args, **kwargs) -> RunReport:
    p = prepare(root)
    report_mode = f"{mode}{'_dry_run' if dry_run else ''}"
    lock_needed = mode in PROTECTED_COMMANDS if protected is None else protected
    try:
        lock_context = BackupLock(_backup_lock_path(p)) if lock_needed and not dry_run else nullcontext()
        with lock_context:
            report = start_run(p.db, RunReport(source=source, mode=report_mode))
            try:
                func(p, report, dry_run=dry_run, *args, **kwargs)
                status = "ok" if report.failed_count == 0 else "warning"
            except Exception as exc:
                report.error(source, str(exc))
                status = "failed"
            finish_run(p.db, p.reports, report, status=status)
            return report
    except RuntimeError as exc:
        report = start_run(p.db, RunReport(source=source, mode=report_mode))
        report.error("lock", str(exc))
        finish_run(p.db, p.reports, report, status="failed")
        return report


def run_manual_report(root: Path, source: str, mode: str, dry_run: bool, protected: bool, func) -> RunReport:
    p = prepare(root)
    report_mode = f"{mode}{'_dry_run' if dry_run else ''}"
    try:
        lock_context = BackupLock(_backup_lock_path(p)) if protected and not dry_run else nullcontext()
        with lock_context:
            report = start_run(p.db, RunReport(source=source, mode=report_mode))
            try:
                func(p, report)
                status = "ok" if report.failed_count == 0 else "warning"
            except Exception as exc:
                report.error(source, str(exc))
                status = "failed"
            finish_run(p.db, p.reports, report, status=status)
            return report
    except RuntimeError as exc:
        report = start_run(p.db, RunReport(source=source, mode=report_mode))
        report.error("lock", str(exc))
        finish_run(p.db, p.reports, report, status="failed")
        return report


def _backup_lock_path(p) -> Path:
    return p.logs / "localvault_backup.lock"


def finish_cli_command(report: RunReport) -> None:
    print_summary(report)
    if report.status == "failed":
        raise typer.Exit(1)


@app.callback()
def main(version: bool = typer.Option(False, "--version", help="Show version and exit.")):
    if version:
        console.print(f"LocalVault Backup Manager {__version__}")
        raise typer.Exit()


@app.command("init")
def init(root: Path = root_option()):
    p = ensure_directories(root)
    ensure_config(root)
    db.init_db(p.db)
    console.print(f"[green]LocalVault initialized at {p.root}[/]")
    console.print(f"Free space: {free_space_bytes(p.root) / (1024**3):.1f} GB")


@app.command("setup")
def setup(
    root: Path = root_option(),
    password_stdin: bool = typer.Option(False, "--password-stdin", help="Read one hidden password line from stdin; never print it."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Do not prompt; report missing password as manual work."),
):
    """Configura a raiz local sem instalar scheduler ou autorizar Gmail."""
    root = Path(root).expanduser()
    if root.exists() and not root.is_dir():
        raise typer.BadParameter("Vault root must be a directory.", param_hint="--root")
    try:
        p = ensure_directories(root)
        config = ensure_config(root)
        db.init_db(p.db)
    except OSError as exc:
        raise typer.BadParameter(f"Vault root/configuration is not writable: {root}", param_hint="--root") from exc

    console.print("[bold]Configuracao guiada LocalVault[/]")
    print(f"Raiz: {p.root} [OK]")
    free_gb = free_space_bytes(p.root) / (1024**3)
    minimum_gb = float(config.get("safety", {}).get("minimum_free_gb", 20))
    free_status = "OK" if free_gb >= minimum_gb else "ATENCAO"
    console.print(f"Espaco livre: {free_gb:.1f} GB (minimo {minimum_gb:.1f} GB) [{free_status}]")

    auth_file = auth_path(p.root)
    auth = load_auth(p.root)
    password_required = False
    if auth:
        console.print("Senha do painel: CONFIGURADA (preservada)")
    elif auth_file.exists():
        console.print("Senha do painel: MANUAL - arquivo existente invalido; nenhum segredo foi alterado")
        password_required = True
    elif password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            console.print("Senha do painel: REQUIRED - forneca uma linha via --password-stdin")
            password_required = True
        else:
            set_password(p.root, password)
            console.print("Senha do painel: CONFIGURADA (criada; valor oculto)")
    elif non_interactive:
        console.print("Senha do painel: REQUIRED - execute novamente com --password-stdin ou modo interativo")
        password_required = True
    else:
        password = typer.prompt("Senha inicial do painel", hide_input=True, confirmation_prompt=True)
        if not password:
            raise typer.BadParameter("Password cannot be empty.")
        set_password(p.root, password)
        console.print("Senha do painel: CONFIGURADA (criada; valor oculto)")

    viewer = config.get("viewer", {})
    host = str(viewer.get("host", "127.0.0.1"))
    port = int(viewer.get("port", 8787))
    if host in ("127.0.0.1", "localhost"):
        console.print(f"Painel: CONFIGURADO - loopback {host}:{port}")
    elif viewer.get("allow_lan", False):
        console.print(f"Painel: ATENCAO - LAN {host}:{port}; HTTP sem criptografia, use apenas rede confiavel")
    else:
        console.print(f"Painel: MANUAL - host {host} exige allow_lan=true")

    gmail = config.get("gmail", {})
    if gmail.get("api_enabled", False):
        console.print("Gmail API: CONFIGURADA - autorizacao continua sendo uma etapa manual")
    else:
        console.print("Gmail API: DESATIVADA - use Takeout/manual; nenhuma autorizacao foi iniciada")
    for label, key in (("credencial", "credentials_file"), ("token", "token_file")):
        candidate = Path(str(gmail.get(key, ""))).expanduser()
        state = "encontrado" if candidate.is_file() else "ausente"
        print(f"Gmail {label}: {state} (conteudo nao lido)")

    sources = config.get("source_sync", {}).get("google_takeout_sources", [])
    console.print("Fontes Google Takeout:")
    if not sources:
        console.print("- nenhuma configurada")
    for source in sources:
        source_path = Path(str(source)).expanduser()
        state = "OK" if source_path.is_dir() else "MANUAL"
        print(f"- {source_path}: {state}")

    automation = merge_automation_config(config.get("automation", {}))
    console.print("Previa do agendador automatico (instalacao separada):")
    for key, task in automation.get("tasks", {}).items():
        if not task.get("enabled", True):
            continue
        days = ",".join(task.get("days") or []) or "todos os dias"
        console.print(f"- {task.get('name', key)}: {task.get('command', '')}, {task.get('frequency', 'daily')} {task.get('time', '03:00')}, {days}")
    console.print("Agendador: MANUAL - use `schedule-install` explicitamente; setup nao instala tarefas")

    health = health_snapshot(p)
    health_label = "OK" if health["status"] == "ok" else "ATENCAO"
    console.print(f"Validacao inicial: {health_label} - configuracao, banco e saude local verificados")
    if password_required:
        raise typer.Exit(2)


@app.command("sync-sources")
def sync_sources(root: Path = root_option(), dry_run: bool = dry_option()):
    finish_cli_command(run_with_report(root, "source_sync", "sync_sources", run_source_sync, dry_run=dry_run))


@app.command("ingest-takeout")
def ingest_takeout(root: Path = root_option(), dry_run: bool = dry_option()):
    def work(p, report):
        ingest_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
    report = run_manual_report(root, "google_takeout", "photos_and_gmail", dry_run, True, work)
    finish_cli_command(report)


@app.command("ingest-all")
def ingest_all(root: Path = root_option(), dry_run: bool = dry_option(), skip_sync: bool = typer.Option(False, "--skip-sync")):
    def work(p, report):
        if not skip_sync:
            run_source_sync(p, report, dry_run=dry_run)
        ingest_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
        build_duplicate_report(p, report, dry_run=dry_run)
    report = run_manual_report(root, "all_sources", "ingest_all", dry_run, True, work)
    finish_cli_command(report)


@app.command("backup-gmail-api")
def backup_gmail_api(root: Path = root_option(), dry_run: bool = dry_option(), max_messages: Optional[int] = typer.Option(None, "--max-messages")):
    finish_cli_command(run_with_report(root, "gmail", "api", run_gmail_api, dry_run=dry_run, max_messages=max_messages))


@app.command("daily-backup")
def daily_backup(root: Path = root_option(), dry_run: bool = dry_option()):
    def work(p, report):
        removed = cleanup_missing_index_entries(p)
        if removed:
            report.warn(f"Cleaned {removed} missing index entries before backup.")
        run_gmail_api(p, report, dry_run=dry_run)
        run_source_sync(p, report, dry_run=dry_run)
        ingest_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
        build_duplicate_report(p, report, dry_run=dry_run)
        verify_vault(p, report, dry_run=False, sample_limit=None)
    report = run_manual_report(root, "localvault", "daily_backup", dry_run, True, work)
    finish_cli_command(report)


@app.command("rename-gmail-files")
def rename_gmail_files(root: Path = root_option(), dry_run: bool = dry_option()):
    """Rename already imported Gmail .eml files with readable Windows-safe names."""
    finish_cli_command(run_with_report(root, "gmail", "rename_files", rename_existing_gmail_files, dry_run=dry_run))


@app.command("gmail-dedupe-audit")
def gmail_dedupe_audit(root: Path = root_option(), dry_run: bool = dry_option()):
    """Generate a Gmail duplicate/orphan audit report without deleting anything."""
    finish_cli_command(run_with_report(root, "gmail", "dedupe_audit", audit_gmail_duplicates, dry_run=dry_run))


@app.command("gmail-repair-runs")
def gmail_repair_runs(root: Path = root_option(), dry_run: bool = dry_option(), older_than_hours: int = typer.Option(6, "--older-than-hours")):
    """Mark old stuck Gmail runs as warning so the dashboard is not misleading."""
    finish_cli_command(run_with_report(root, "gmail", "repair_runs", repair_stale_gmail_runs, dry_run=dry_run, older_than_hours=older_than_hours))


@app.command("photos-ingest-takeout")
def photos_ingest_takeout(root: Path = root_option(), dry_run: bool = dry_option()):
    """Import photos and videos from Google Takeout ZIPs in the inbox."""
    finish_cli_command(run_with_report(root, "photos_takeout", "takeout", ingest_photos_takeout, dry_run=dry_run))


@app.command("auto-takeout")
def auto_takeout(root: Path = root_option(), dry_run: bool = dry_option()):
    """Move valid Google Takeout ZIPs from configured source folders and import them once."""
    finish_cli_command(run_with_report(root, "google_takeout", "auto_takeout", run_auto_takeout, dry_run=dry_run))


@app.command("write-gmail-oauth")
def write_gmail_oauth(
    root: Path = root_option(),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="Google OAuth desktop client id."),
    client_secret: Optional[str] = typer.Option(None, "--client-secret", help="Google OAuth client secret. Prefer pasting at the prompt instead of command history."),
    project_id: str = typer.Option("", "--project-id", help="Google Cloud project id, optional."),
):
    """Write the Gmail OAuth desktop-client JSON expected by LocalVault."""
    p = prepare(root)
    if not client_id:
        client_id = typer.prompt("Client ID")
    if not client_secret:
        console.print("[yellow]Cole o Client Secret completo aqui. Ele normalmente comeÃ§a com GOCSPX-.[/]")
        client_secret = typer.prompt("Client Secret")
    client_id = client_id.strip()
    client_secret = client_secret.strip()
    project_id = project_id.strip()
    if not client_id.endswith(".apps.googleusercontent.com"):
        raise typer.BadParameter("Client ID parece incorreto. Ele deve terminar com .apps.googleusercontent.com")
    if len(client_secret) < 20 or not client_secret.startswith("GOCSPX-"):
        raise typer.BadParameter("Client Secret parece incorreto. Copie o valor completo que comeÃ§a com GOCSPX-, nÃ£o o texto mascarado.")
    payload = {
        "installed": {
            "client_id": client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": ["http://localhost"],
        }
    }
    target = p.config / "google_oauth_client_secret.json"
    atomic_write_text(target, json.dumps(payload, indent=2), encoding="utf-8")
    cfg_path = p.config / "config.yaml"
    cfg_text = cfg_path.read_text(encoding="utf-8")
    cfg_text = cfg_text.replace("api_enabled: false", "api_enabled: true")
    atomic_write_text(cfg_path, cfg_text, encoding="utf-8")
    console.print(f"[green]OAuth file written:[/] {target}")
    console.print("Next: python -m localvault backup-gmail-api --root E:\\LocalVault --max-messages 1")


@app.command("sources-status")
def sources_status(root: Path = root_option()):
    p = prepare(root); cfg = load_config(root).get("source_sync", {})
    console.print("[bold]Automatic Source Sync[/]")
    console.print(f"Enabled: {cfg.get('enabled', True)}")
    for name, values in [("Google Takeout", cfg.get("google_takeout_sources", []))]:
        console.print(f"{name}:")
        for value in values:
            console.print(f"- {value}")
    console.print(f"Takeout ZIPs in inbox: {len(list(p.google_takeout_inbox.glob('*.zip')))}")


@app.command("open-inboxes")
def open_inboxes(root: Path = root_option()):
    p = prepare(root)
    for folder in (p.google_takeout_inbox, p.manual_imports_inbox):
        if os.name == "nt":
            os.startfile(folder)  # type: ignore[attr-defined]
        else:
            console.print(folder)


@app.command("scan-media")
def scan_media(root: Path = root_option(), dry_run: bool = dry_option()):
    finish_cli_command(run_with_report(root, "vault", "scan_media", scan_existing_media, dry_run=dry_run))


@app.command("dedupe")
def dedupe(root: Path = root_option(), dry_run: bool = dry_option()):
    report = run_with_report(root, "vault", "dedupe", build_duplicate_report, dry_run=dry_run)
    finish_cli_command(report)


@app.command("verify")
def verify(root: Path = root_option(), sample_limit: Optional[int] = typer.Option(None, "--sample-limit")):
    mode = "verify_full" if sample_limit is None else "verify_sample"
    finish_cli_command(run_with_report(root, "vault", mode, verify_vault, dry_run=False, sample_limit=sample_limit))


@app.command("repair-index")
def repair_index(root: Path = root_option()):
    p = prepare(root)
    removed = cleanup_missing_index_entries(p)
    console.print(f"Removed missing index entries: {removed}")


@app.command("health-check")
def health_check(root: Path = root_option(), as_json: bool = typer.Option(False, "--json", help="Emit bounded machine-readable health JSON.")):
    p = prepare(root)
    health = health_snapshot(p)
    if as_json:
        print(json.dumps(health, ensure_ascii=False, separators=(",", ":"), default=str))
        return
    console.print(f"Status: {health['status']}")
    for item in health["checks"]:
        marker = "OK" if item["ok"] else "ATENCAO"
        console.print(f"{marker} - {item['name']}: {item['detail']}")


def _restore_destination_option() -> Path:
    return typer.Option(..., "--destination", help="Separate restore destination folder.")


def _restore_media_option() -> str:
    return typer.Option("all", "--media-type", help="all, email, gmail_attachment, photo, or video.")


def _restore_conflict_option() -> str:
    return typer.Option("skip", "--conflict", help="skip, rename, or overwrite.")


@app.command("restore-plan")
def restore_plan_command(
    root: Path = root_option(),
    destination: Path = _restore_destination_option(),
    media_type: str = _restore_media_option(),
    limit: Optional[int] = typer.Option(None, "--limit", help="Bound the number of indexed files."),
    conflict: str = _restore_conflict_option(),
):
    try:
        plan = plan_restore(paths(root), destination, media_type=media_type, limit=limit, conflict=conflict)
    except RestoreValidationError as exc:
        print(json.dumps({"schema": 1, "status": "rejected", "errors": [str(exc)[:240]]}, ensure_ascii=False))
        raise typer.Exit(2)
    print(json.dumps(plan.public(), ensure_ascii=False, separators=(",", ":")))


@app.command("restore")
def restore_command(
    root: Path = root_option(),
    destination: Path = _restore_destination_option(),
    media_type: str = _restore_media_option(),
    limit: Optional[int] = typer.Option(None, "--limit", help="Bound the number of indexed files."),
    conflict: str = _restore_conflict_option(),
    dry_run: bool = dry_option(),
):
    try:
        plan = plan_restore(paths(root), destination, media_type=media_type, limit=limit, conflict=conflict)
        result = execute_restore(paths(root), plan, dry_run=dry_run)
    except RestoreValidationError as exc:
        print(json.dumps({"schema": 1, "status": "rejected", "errors": [str(exc)[:240]]}, ensure_ascii=False))
        raise typer.Exit(2)
    print(json.dumps(result.public(), ensure_ascii=False, separators=(",", ":")))
    if result.status == "partial":
        raise typer.Exit(1)


@app.command("recovery-test")
def recovery_test_command():
    """Run a bounded synthetic integrity and restore drill in temporary storage."""
    result = run_recovery_test()
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    if result["status"] != "passed":
        raise typer.Exit(1)


def _replica_destination_option() -> Optional[Path]:
    return typer.Option(None, "--destination", help="Explicit separate replica destination folder.")


@app.command("replica-plan")
def replica_plan_command(root: Path = root_option(), destination: Optional[Path] = _replica_destination_option()):
    try:
        result = plan_replica(paths(root), destination)
    except (OSError, ReplicaValidationError) as exc:
        print(json.dumps({"schema": 1, "status": "rejected", "errors": [str(exc)[:240]]}, ensure_ascii=False))
        raise typer.Exit(2)
    print(json.dumps(result.public(), ensure_ascii=False, separators=(",", ":")))


@app.command("replica")
def replica_command(root: Path = root_option(), destination: Optional[Path] = _replica_destination_option(), dry_run: bool = dry_option()):
    p = paths(root)
    try:
        plan = plan_replica(p, destination)
        if dry_run:
            result = execute_replica(p, plan, dry_run=True)
        else:
            with BackupLock(_backup_lock_path(p)):
                result = execute_replica(p, plan)
    except RuntimeError as exc:
        print(json.dumps({"schema": 1, "status": "lock_conflict", "errors": [str(exc)[:240]]}, ensure_ascii=False))
        raise typer.Exit(1)
    except (OSError, ReplicaValidationError) as exc:
        print(json.dumps({"schema": 1, "status": "rejected", "errors": [str(exc)[:240]]}, ensure_ascii=False))
        raise typer.Exit(2)
    print(json.dumps(result.public(), ensure_ascii=False, separators=(",", ":")))
    if result.status not in {"completed", "stale", "dry_run"}:
        raise typer.Exit(1)


@app.command("disk-clone-status")
def disk_clone_status(root: Path = root_option()):
    """Show safe provider, enrollment, due-date, and run state information."""
    p = prepare(root)
    status = disk_clone_dashboard_data(p)
    status["offline_runtime"] = OfflineRuntimeValidator().validate().payload()
    console.print_json(json.dumps(status, ensure_ascii=False, default=str))


@app.command("disk-clone-check")
def disk_clone_check(root: Path = root_option()):
    """Run non-destructive clone preflight; never launches a provider."""
    p = prepare(root)
    try:
        result = CloneService(p).preflight(perform_activity=False, require_enabled=False)
    except DiskCloneBlocked as exc:
        console.print(f"State: {exc.state}\nReason: {exc.reason}")
        raise typer.Exit(1)
    console.print(f"State: {result.state}\nReason: {result.reason}")
    if result.details:
        console.print_json(json.dumps(result.details, ensure_ascii=False, default=str))
    if not result.ok:
        raise typer.Exit(1)


@app.command("disk-clone-simulate")
def disk_clone_simulate(root: Path = root_option()):
    """Exercise the fake offline Clonezilla round trip without touching host disks."""
    with tempfile.TemporaryDirectory(prefix="localvault-clone-sim-") as temp_root:
        result = simulate_offline_round_trip(Path(temp_root))
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if result.get("state") != "offline_simulation_completed":
        raise typer.Exit(1)


@app.command("disk-clone-virtual-roundtrip")
def disk_clone_virtual_roundtrip(root: Path = root_option()):
    """Exercise the durable virtual return channel with synthetic devices only."""
    prepare(root)
    with tempfile.TemporaryDirectory(prefix="localvault-clone-virtual-") as temp_root:
        result = simulate_virtual_offline_round_trip(Path(temp_root))
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if result.get("state") != "consumed":
        raise typer.Exit(1)


@app.command("disk-clone-runtime-validate")
def disk_clone_runtime_validate(
    root: Path = root_option(),
    iso: Optional[Path] = typer.Option(None, "--iso", help="Existing official Clonezilla ISO; never downloaded."),
    extracted_tree: Optional[Path] = typer.Option(None, "--extracted-tree", help="Existing extracted ISO tree; never modified."),
    checksums: Optional[Path] = typer.Option(None, "--checksums", help="Signed official checksum manifest; never downloaded."),
    checksums_signature: Optional[Path] = typer.Option(None, "--checksums-signature", help="Detached signature for --checksums."),
    extraction_manifest: Optional[Path] = typer.Option(None, "--extraction-manifest", help="Canonical signed extraction manifest for --extracted-tree."),
    extraction_signature: Optional[Path] = typer.Option(None, "--extraction-signature", help="Detached signature for --extraction-manifest."),
    official_verifier_binary: Optional[Path] = typer.Option(None, "--official-verifier-binary", help="Explicit read-only gpgv-compatible verifier for official Clonezilla checksums; never discovered."),
    official_public_keyring: Optional[Path] = typer.Option(None, "--official-public-keyring", help="Pinned read-only DRBL/Clonezilla public keyring."),
    local_attestation_verifier_binary: Optional[Path] = typer.Option(None, "--local-attestation-verifier-binary", help="Explicit read-only verifier for L-vault extraction attestations; never discovered."),
    local_attestation_public_keyring: Optional[Path] = typer.Option(None, "--local-attestation-public-keyring", help="Pinned read-only L-vault extraction-attestation public keyring."),
    profile: str = typer.Option(RUNTIME_VALIDATION_PROFILE_PRODUCTION_STATIC, "--profile", help="Validation profile: production_static (default) or synthetic_test."),
):
    """Inspect supplied Clonezilla artifacts and their signed tree binding without booting or touching storage."""
    prepare(root)
    if profile not in {RUNTIME_VALIDATION_PROFILE_PRODUCTION_STATIC, RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST}:
        raise typer.BadParameter("profile must be production_static or synthetic_test", param_hint="--profile")
    config = load_config(root).get("disk_clone", {})
    official_verifier = None
    local_attestation_verifier = None
    if official_verifier_binary is not None and official_public_keyring is not None:
        official_verifier = OfficialChecksumVerifier(ProductionOfflineSignatureVerifier(official_verifier_binary, official_public_keyring, CLONEZILLA_SIGNER_FINGERPRINT))
    local_fingerprint = str(config.get("local_attestation_fingerprint", ""))
    if local_attestation_verifier_binary is not None and local_attestation_public_keyring is not None and local_fingerprint:
        local_attestation_verifier = LocalExtractionAttestationVerifier(ProductionOfflineSignatureVerifier(local_attestation_verifier_binary, local_attestation_public_keyring, local_fingerprint))
    validator = OfflineRuntimeValidator() if profile == RUNTIME_VALIDATION_PROFILE_PRODUCTION_STATIC else OfflineRuntimeValidator.synthetic_test(CLONEZILLA_STABLE_AMD64_ISO_SHA256)
    report = validator.validate(
        iso_path=iso,
        extracted_tree=extracted_tree,
        checksums_path=checksums,
        checksums_signature=_read_signature_file(checksums_signature),
        official_verifier=official_verifier,
        local_attestation_verifier=local_attestation_verifier,
        extraction_manifest_path=extraction_manifest,
        extraction_manifest_signature=_read_signature_file(extraction_signature),
    )
    console.print_json(json.dumps(report.payload(), ensure_ascii=False, default=str))
    if report.state == "offline_runtime_blocked":
        raise typer.Exit(1)


def _artifact_cache_option() -> Path:
    return typer.Option(Path.home() / ".localvault" / "clonezilla-artifacts", "--cache", help="Private cache outside the repository; output never prints this path.")


@app.command("disk-clone-artifacts-verify")
def disk_clone_artifacts_verify(
    cache: Path = _artifact_cache_option(),
    offline: bool = typer.Option(False, "--offline", help="Revalidate only already-cached artifacts; do not use the network."),
    gpg: Path = typer.Option(..., "--gpg", help="Absolute host GPG executable used only for isolated public-key provisioning."),
    gpgv: Path = typer.Option(..., "--gpgv", help="Absolute host gpgv executable used for the official detached signature."),
):
    """Acquire or revalidate the pinned public Clonezilla artifacts only."""
    repository = Path(__file__).resolve().parents[2]
    try:
        bundle = acquire_official_bundle(cache, repository=repository, offline=offline)
        keyring = bundle.public_key.parent / "drbl-clonezilla-public.gpg"
        fingerprint, keyring_sha256 = provision_official_public_keyring(armored_key=bundle.public_key, destination=keyring, gpg_binary=gpg, repository=repository)
        verified = verify_official_bundle(bundle, gpgv_binary=gpgv, public_keyring=keyring)
        write_official_artifact_record(bundle, verified, keyring_sha256=keyring_sha256)
    except OfflineCloneBlocked as exc:
        console.print_json(json.dumps({"state": exc.state, "reason": exc.reason}, ensure_ascii=False))
        raise typer.Exit(1)
    console.print_json(json.dumps({
        "state": "official_artifacts_verified",
        "source_hosts": sorted({record.source_host for record in bundle.records}),
        "retrieval_date": max(record.retrieval_date for record in bundle.records),
        "artifacts": [record.payload() for record in bundle.records],
        "iso_filename": bundle.iso.name,
        "iso_sha256": verified.iso_sha256,
        "checksum_manifest_sha256": verified.checksum_manifest_sha256,
        "official_signer_fingerprint": fingerprint,
        "official_keyring_sha256": keyring_sha256,
        "offline": offline,
    }, ensure_ascii=False))


@app.command("disk-clone-artifact-status")
def disk_clone_artifact_status(cache: Path = _artifact_cache_option()):
    """Report read-only presence and size state for the pinned artifact cache."""
    names = (CLONEZILLA_STABLE_AMD64_ISO_FILENAME, "CHECKSUMS.TXT", "CHECKSUMS.TXT.gpg", "drbl-clonezilla-public.asc", "drbl-clonezilla-public.gpg")
    result = []
    for name in names:
        path = Path(cache) / name
        safe = path.is_file() and not path.is_symlink()
        result.append({"filename": name, "present": safe, "size": path.stat().st_size if safe else 0})
    console.print_json(json.dumps({"state": "artifact_cache_status", "artifacts": result}, ensure_ascii=False))


@app.command("disk-clone-attestor-status")
def disk_clone_attestor_status(
    gpg: Path = typer.Option(..., "--gpg", help="Absolute host GPG executable."),
    gnupg_home: Path = typer.Option(..., "--gnupg-home", help="Private local attestor home; never printed."),
    public_keyring: Optional[Path] = typer.Option(None, "--public-keyring", help="Read-only public verification keyring."),
):
    """Inspect local extraction-attestor readiness without printing secret locations or key material."""
    try:
        result = inspect_local_attestor(gpg_binary=gpg, gnupg_home=gnupg_home, public_keyring=public_keyring)
    except OfflineCloneBlocked as exc:
        console.print_json(json.dumps({"state": exc.state, "reason": exc.reason}, ensure_ascii=False))
        raise typer.Exit(1)
    result["state"] = "local_attestor_ready" if result["private_key_present"] and result["public_keyring_present"] else "local_attestation_provisioning_blocked"
    console.print_json(json.dumps(result, ensure_ascii=False))
    if result["state"] != "local_attestor_ready":
        raise typer.Exit(1)


@app.command("disk-clone-runtime-extract")
def disk_clone_runtime_extract(
    cache: Path = _artifact_cache_option(),
    stage: Path = typer.Option(..., "--stage", help="Private empty extraction staging directory outside the repository."),
    gpg: Path = typer.Option(..., "--gpg", help="Absolute host GPG executable."),
    gpgv: Path = typer.Option(..., "--gpgv", help="Absolute host gpgv executable."),
    iso_extractor: Path = typer.Option(..., "--iso-extractor", help="Absolute installed ISO extractor executable."),
    iso_product: str = typer.Option(..., "--iso-product"),
    iso_version: str = typer.Option(..., "--iso-version"),
    rootfs_extractor: Path = typer.Option(..., "--rootfs-extractor", help="Absolute installed SquashFS extractor executable."),
    rootfs_product: str = typer.Option(..., "--rootfs-product"),
    rootfs_version: str = typer.Option(..., "--rootfs-version"),
    local_gpg: Path = typer.Option(..., "--local-gpg", help="Absolute host GPG executable for the separate local attestor."),
    local_gnupg_home: Path = typer.Option(..., "--local-gnupg-home", help="Private local attestor home; never printed."),
    local_fingerprint: str = typer.Option(..., "--local-fingerprint", help="Full local public attestor fingerprint."),
):
    """Extract verified regular-file artifacts, attest the tree, and never execute extracted content."""
    repository = Path(__file__).resolve().parents[2]
    try:
        bundle = acquire_official_bundle(cache, repository=repository, offline=True)
        keyring = bundle.public_key.parent / "drbl-clonezilla-public.gpg"
        provision_official_public_keyring(armored_key=bundle.public_key, destination=keyring, gpg_binary=gpg, repository=repository)
        verified = verify_official_bundle(bundle, gpgv_binary=gpgv, public_keyring=keyring)
        ensure_private_cache(stage, repository=repository)
        products = TrustedClonezillaExtractor(iso_executable=iso_extractor, rootfs_executable=rootfs_extractor, iso_product=iso_product, iso_version=iso_version, rootfs_product=rootfs_product, rootfs_version=rootfs_version).extract(bundle.iso, stage)
        attestation = build_production_extraction_manifest(iso_filename=bundle.iso.name, iso_sha256=verified.iso_sha256, checksum_manifest_sha256=verified.checksum_manifest_sha256, official_evidence=verified.evidence, extracted_root=stage / "root-tree", products=products)
        signer = GpgDetachedSigner(gpg_binary=local_gpg, gnupg_home=local_gnupg_home, key_fingerprint=local_fingerprint)
        manifest_path = stage / "extraction-manifest.json"
        signature_path = stage / "extraction-manifest.sig"
        from .utils import atomic_write_bytes
        atomic_write_bytes(manifest_path, attestation.canonical_bytes())
        atomic_write_bytes(signature_path, signer.sign(attestation.canonical_bytes()))
    except OfflineCloneBlocked as exc:
        console.print_json(json.dumps({"state": exc.state, "reason": exc.reason}, ensure_ascii=False))
        raise typer.Exit(1)
    console.print_json(json.dumps({"state": "production_extraction_attested", "iso_filename": bundle.iso.name, "iso_sha256": verified.iso_sha256, "rootfs_relative_path": products.rootfs_relative_path, "rootfs_sha256": products.rootfs_sha256, "inventory_schema": attestation.schema, "entry_count": attestation.entry_count, "total_regular_file_bytes": attestation.total_regular_file_bytes, "inventory_sha256": attestation.inventory_sha256, "required_tools": list(REQUIRED_RUNTIME_TOOLS)}, ensure_ascii=False))


@app.command("disk-clone-run")
def disk_clone_run(root: Path = root_option()):
    """Report the deferred offline handoff; never starts a Windows clone."""
    config = validated_disk_clone_config(root)
    if not config["enabled"]:
        console.print_json(json.dumps({"state": "blocked_configuration", "reason": "A clonagem esta desativada por configuracao."}, ensure_ascii=False))
        raise typer.Exit(1)
    prepare(root)
    result = {
        "state": "offline_boot_not_configured",
        "reason": "Clonezilla Live boot handoff is not configured; no reboot or storage mutation is permitted in this phase.",
        "boot_tested": False,
    }
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if result.get("state") not in {"success", "skipped_not_due", "skipped_outside_window", "skipped_window_expired_before_start", "skipped_no_interactive_session", "skipped_target_missing", "skipped_high_source_activity"}:
        raise typer.Exit(1)


@app.command("disk-clone-show")
def disk_clone_show(root: Path = root_option()):
    """Signal the existing native clone window to restore; never starts a clone."""
    from .disk_clone import active_clone_run_id, create_control_request, latest_clone_run_id

    p = prepare(root)
    request_id = create_control_request(p.db, "show", run_id=active_clone_run_id(p.db) or latest_clone_run_id(p.db), actor="local-command")
    console.print(f"Restore request: {request_id}")


@app.command("disk-clone-ui")
def disk_clone_ui(root: Path = root_option(), countdown_seconds: int = typer.Option(300, "--countdown-seconds"), monitor: bool = typer.Option(False, "--monitor"), run_id: str | None = typer.Option(None, "--run-id")):
    """Run the native warning or durable progress/error window."""
    config = validated_disk_clone_config(root)
    if not config["enabled"]:
        raise typer.BadParameter("A clonagem esta desativada por configuracao.")
    p = prepare(root)
    run_native_ui(p.root, countdown_seconds, monitor=monitor, run_id=run_id)


@app.command("disk-clone-retry-worker")
def disk_clone_retry_worker(root: Path = root_option(), request_id: str = typer.Option(..., "--request-id")):
    """Consume one durable retry request through the guarded workflow."""
    p = prepare(root)
    result = CloneService(p).consume_retry_request(request_id=request_id, countdown=lambda seconds: native_countdown(p.root, seconds))
    console.print_json(json.dumps(result, ensure_ascii=False, default=str))
    if result.get("state") not in {"retry_accepted", "retry_rejected", "retry_not_claimed"}:
        raise typer.Exit(1)


@app.command("disk-clone-enroll")
def disk_clone_enroll(root: Path = root_option()):
    """Interactively enroll a distinct physical target by stable identity."""
    if not validated_disk_clone_config(root)["enabled"]:
        raise typer.BadParameter("A clonagem esta desativada por configuracao.")
    if os.name != "nt":
        raise typer.BadParameter("A inscricao de clone exige Windows e privilegios administrativos.")
    p = prepare(root)
    cfg = load_config(root)
    provider = provider_for_config(cfg.get("disk_clone", {}))
    _enroll_disk_clone(
        p,
        provider,
        inventory=WindowsDiskInventory(),
        resolver=WindowsProtectedPathResolver(),
        lifecycle=WindowsDiskLifecycle(),
        store=EnrollmentStore(root),
        prompt=typer.prompt,
    )


def _enroll_disk_clone(
    p,
    provider,
    *,
    inventory,
    resolver,
    lifecycle,
    store,
    prompt: Callable[..., object],
) -> None:
    """Run enrollment with injectable read-only fakes for regression tests."""
    full_config = load_config(p.root)
    cfg = validate_disk_clone_config(full_config.get("disk_clone", {}))
    if not cfg["enabled"]:
        raise typer.BadParameter("A clonagem esta desativada por configuracao.")
    discovery = provider.discover()
    capabilities = provider.validate_capabilities()
    if not capabilities.supported:
        raise typer.BadParameter(f"Inscricao bloqueada para {discovery.name}: {capabilities.blocker or discovery.detail}")

    disks = inventory.list_disks()
    sources = [disk for disk in disks if disk.is_system or disk.is_boot]
    if len(sources) != 1:
        raise typer.BadParameter("Nao foi possivel identificar o disco de sistema atual.")
    source = sources[0]
    protected_paths = _source_paths(p, full_config)
    table = Table(title="Candidatos; numero efemero, nunca identidade")
    for column in ("Nº efemero", "Modelo", "Capacidade", "Barramento", "Particao", "Estado", "Somente leitura", "Volumes montados", "Caminhos protegidos", "Serial", "Forca", "Sistema/boot/pagefile/crash", "Aviso"):
        table.add_column(column)
    for disk in disks:
        conflicts = protected_path_conflicts(disk, protected_paths, resolver=resolver)
        mounted = any(part.mount_point for part in disk.partitions)
        critical = any((disk.is_system, disk.is_boot, disk.is_pagefile, disk.is_crash_dump))
        similar = any(
            other.number != disk.number
            and (
                other.model.casefold() == disk.model.casefold()
                or (disk.size_bytes and abs(other.size_bytes - disk.size_bytes) <= max(disk.size_bytes // 100, 1))
            )
            for other in disks
        )
        warnings = []
        if critical:
            warnings.append("NAO USAR: sistema/boot/pagefile/crash")
        if similar:
            warnings.append("outro disco tem modelo/capacidade aproximados")
        table.add_row(
            str(disk.number),
            disk.model or "(sem modelo)",
            f"{disk.size_bytes:,} bytes ({_human_size(disk.size_bytes)})",
            disk.bus_type or "desconhecido",
            disk.partition_style or "desconhecido",
            "online" if disk.online else "offline",
            "sim" if disk.read_only else "nao",
            "sim" if mounted else "nao",
            "sim" if conflicts else "nao",
            disk.masked_serial,
            disk.identity_strength(),
            "/".join("sim" if flag else "nao" for flag in (disk.is_system, disk.is_boot, disk.is_pagefile, disk.is_crash_dump)),
            "; ".join(warnings) or "-",
        )
    console.print(table)
    console.print("Nao pre-selecione por capacidade, modelo, letra ou numero; confirme a identidade persistente abaixo.")
    target_number = prompt("Numero momentaneo do HD de destino", type=int)
    target = next((disk for disk in disks if disk.number == target_number), None)
    if not target or target.number == source.number or any((target.is_system, target.is_boot, target.is_pagefile, target.is_crash_dump)):
        raise typer.BadParameter("O destino deve ser outro disco fisico.")

    def refresh_matches(reference_source=source, reference_target=target):
        refreshed = inventory.list_disks()
        target_matches = [disk for disk in refreshed if disk.matches(reference_target, require_strong=True)]
        source_matches = [disk for disk in refreshed if disk.matches(reference_source, require_strong=True) and (disk.is_system or disk.is_boot)]
        return refreshed, source_matches, target_matches

    refreshed, source_matches, target_matches = refresh_matches()
    if len(target_matches) != 1 or len(source_matches) != 1:
        raise typer.BadParameter("A identidade fisica mudou ou ficou ambigua; inscricao bloqueada.")
    target, source = target_matches[0], source_matches[0]
    if target.matches(source, require_strong=False) or any((target.is_system, target.is_boot, target.is_pagefile, target.is_crash_dump)):
        raise typer.BadParameter("O destino atualizado e invalido ou e um disco critico.")
    try:
        conflicts, _ = resolved_protected_path_conflicts(target, _source_paths(p, load_config(p.root)), resolver, inventory=refreshed)
    except Exception as exc:
        raise typer.BadParameter("Inscricao bloqueada: dados protegidos do L-vault nao puderam ser resolvidos com seguranca.") from exc
    if conflicts:
        raise typer.BadParameter("Inscricao bloqueada: o disco selecionado contem ou mapeia de forma ambigua dados protegidos do L-vault.")
    phrase = target.confirmation_phrase()
    ack = prompt(f"Digite exatamente {phrase}")
    if ack != phrase:
        raise typer.BadParameter("Confirmacao destrutiva incorreta.")

    # Rebuild every authorization input after the user confirmation pause.
    final_inventory, final_source_matches, final_target_matches = refresh_matches()
    if len(final_target_matches) != 1 or len(final_source_matches) != 1:
        raise typer.BadParameter("A identidade fisica mudou, desapareceu ou ficou ambigua antes da operacao; inscricao bloqueada.")
    final_target, final_source = final_target_matches[0], final_source_matches[0]
    if final_target.matches(final_source, require_strong=False) or any((final_target.is_system, final_target.is_boot, final_target.is_pagefile, final_target.is_crash_dump)):
        raise typer.BadParameter("O destino final e invalido ou se tornou um disco critico; inscricao bloqueada.")
    if final_target.confirmation_phrase() != phrase:
        raise typer.BadParameter("A identidade confirmada mudou antes da operacao; inscricao bloqueada.")
    try:
        conflicts, _ = resolved_protected_path_conflicts(final_target, _source_paths(p, load_config(p.root)), resolver, inventory=final_inventory)
    except Exception as exc:
        raise typer.BadParameter("Inscricao bloqueada: dados protegidos do L-vault nao puderam ser resolvidos com seguranca.") from exc
    if conflicts:
        raise typer.BadParameter("Inscricao bloqueada: o disco selecionado contem ou mapeia de forma ambigua dados protegidos do L-vault.")
    lifecycle.set_offline(final_target)

    # Re-authorize after the state-changing transition and immediately before persistence.
    post_inventory, post_source_matches, post_target_matches = refresh_matches(final_source, final_target)
    if len(post_target_matches) != 1 or len(post_source_matches) != 1:
        raise typer.BadParameter("A identidade fisica mudou, desapareceu ou ficou ambigua apos a transicao; inscricao bloqueada.")
    post_source, post_target = post_source_matches[0], post_target_matches[0]
    if post_target.matches(post_source, require_strong=False) or any((post_target.is_system, post_target.is_boot, post_target.is_pagefile, post_target.is_crash_dump)):
        raise typer.BadParameter("O destino apos a transicao e invalido ou se tornou um disco critico; inscricao bloqueada.")
    if post_target.confirmation_phrase() != phrase:
        raise typer.BadParameter("A identidade confirmada mudou apos a transicao; inscricao bloqueada.")
    try:
        conflicts, _ = resolved_protected_path_conflicts(post_target, _source_paths(p, load_config(p.root)), resolver, inventory=post_inventory)
    except Exception as exc:
        raise typer.BadParameter("Inscricao bloqueada: dados protegidos do L-vault nao puderam ser resolvidos com seguranca apos a transicao.") from exc
    if conflicts:
        raise typer.BadParameter("Inscricao bloqueada: os dados protegidos do L-vault mudaram ou ficaram ambiguos apos a transicao.")
    store.save(post_source, post_target, discovery.name, "disk_intelligent")
    console.print("Inscricao criada. O provedor nunca e executado durante a inscricao.")


@app.command("serve")
def serve(
    root: Path = root_option(),
    host: Optional[str] = typer.Option(None, "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
    tls_certfile: Optional[Path] = typer.Option(None, "--tls-certfile", help="TLS certificate PEM path."),
    tls_keyfile: Optional[Path] = typer.Option(None, "--tls-keyfile", help="TLS private key PEM path."),
):
    p = prepare(root); cfg = load_config(root)["viewer"]
    selected_host, selected_port = host or cfg.get("host", "127.0.0.1"), int(port or cfg.get("port", 8787))
    selected_cert = tls_certfile or cfg.get("tls_certfile")
    selected_key = tls_keyfile or cfg.get("tls_keyfile")
    tls_enabled = bool(cfg.get("tls_enabled", False) or tls_certfile or tls_keyfile)
    validate_viewer_exposure(selected_host, bool(cfg.get("allow_lan", False)), bool(load_auth(p.root)), tls_enabled, selected_cert, selected_key)
    tls_options = {}
    if tls_enabled:
        cert, key = validate_tls_files(selected_cert, selected_key)
        tls_options = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
    uvicorn.run(create_app(p.root, https_enabled=tls_enabled), host=selected_host, port=selected_port, **tls_options)


def validate_viewer_exposure(host: str, allow_lan: bool, authentication_configured: bool, tls_enabled: bool = False, tls_certfile: Path | str | None = None, tls_keyfile: Path | str | None = None) -> None:
    if host not in ("127.0.0.1", "localhost") and not allow_lan:
        raise typer.BadParameter("LAN exposure is disabled.")
    if not authentication_configured:
        raise typer.BadParameter("Viewer authentication is not configured. Run: python -m localvault auth-set-password --root <vault-root>")
    if host not in ("127.0.0.1", "localhost"):
        if not tls_enabled:
            raise typer.BadParameter("Non-loopback exposure requires TLS; configure tls_enabled and certificate/key paths.")
        try:
            validate_tls_files(tls_certfile, tls_keyfile)
        except TLSConfigurationError as exc:
            raise typer.BadParameter(str(exc)) from exc
    elif tls_enabled:
        try:
            validate_tls_files(tls_certfile, tls_keyfile)
        except TLSConfigurationError as exc:
            raise typer.BadParameter(str(exc)) from exc


@app.command("auth-set-password")
def auth_set_password(root: Path = root_option()):
    """Set or rotate the single-user viewer password."""
    p = ensure_directories(root)
    password = typer.prompt("Viewer password", hide_input=True, confirmation_prompt=True)
    if not password:
        raise typer.BadParameter("Password cannot be empty.")
    set_password(p.root, password)
    console.print("[green]Viewer password set. Existing viewer sessions were invalidated.[/]")


@app.command("viewer-shortcut")
def viewer_shortcut(root: Path = root_option()):
    p = prepare(root)
    script = p.root / "create_desktop_shortcut.ps1"
    if not script.exists():
        raise typer.BadParameter(f"Shortcut script not found: {script}")
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)], text=True, capture_output=True, check=False)
    console.print(result.stdout or result.stderr)
    if result.returncode:
        raise typer.Exit(result.returncode)


@app.command("schedule")
def schedule(root: Path = root_option()):
    """Gera scripts de prévia; não instala tarefas do Windows."""
    files = generate_schedule_files(prepare(root))
    console.print(f"Generated: {files.install}, {files.remove}, {files.list_tasks}, {files.runner}")


@app.command("schedule-install")
def schedule_install(root: Path = root_option()):
    result = run_powershell_script(generate_schedule_files(prepare(root)).install)
    if result.returncode:
        raise typer.Exit(result.returncode)


@app.command("schedule-remove")
def schedule_remove(root: Path = root_option()):
    result = run_powershell_script(generate_schedule_files(prepare(root)).remove)
    if result.returncode:
        raise typer.Exit(result.returncode)


@app.command("schedule-list")
def schedule_list(root: Path = root_option()):
    prefix = load_config(root).get("automation", {}).get("task_prefix", "LocalVault")
    result = list_windows_tasks(prefix)
    console.print(result.stdout or result.stderr)


@app.command("report")
def report(root: Path = root_option()):
    p = prepare(root)
    with db.connect(p.db) as conn:
        rows = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 10").fetchall()
    for row in rows:
        console.print(f"#{row['id']} {row['source']} {row['mode']} {row['status']} imported={row['imported_count']} failed={row['failed_count']}")
    if not rows:
        console.print("No runs recorded yet.")


def print_summary(report: RunReport) -> None:
    console.print(f"Status: {report.status}")
    console.print(f"Imported/indexed: {report.imported_count}")
    console.print(f"Skipped duplicates: {report.skipped_duplicates}")
    console.print(f"Failed: {report.failed_count}")
    console.print(f"Storage added/indexed: {report.storage_added / (1024**2):.2f} MB")
    if report.report_path:
        console.print(f"Report: {report.report_path}")

