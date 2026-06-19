from __future__ import annotations

import logging
import os
import json
import subprocess
from pathlib import Path
from typing import Optional

import typer
import uvicorn
from rich.console import Console

from . import __version__, db
from .config import DEFAULT_ROOT, ensure_config, ensure_directories, load_config, paths
from .dedupe import build_duplicate_report
from .gmail_api import backup_gmail_api as run_gmail_api
from .gmail_maintenance import rename_existing_gmail_files
from .gmail_takeout import ingest_gmail_takeout
from .health import health_snapshot
from .photos import ingest_google_photos_local_sources, ingest_google_photos_takeout, scan_existing_media
from .reports import RunReport, finish_run, start_run
from .scheduler import generate_schedule_files, list_windows_tasks, run_powershell_script
from .source_sync import sync_sources as run_source_sync
from .utils import free_space_bytes, utc_now
from .verify import verify_vault
from .viewer import create_app
from .vault_index import cleanup_missing_index_entries
from .whatsapp import copy_whatsapp_media_folder, ingest_whatsapp_exports

app = typer.Typer(help="LocalVault Backup Manager", invoke_without_command=True)
console = Console()


def root_option() -> Path:
    return typer.Option(DEFAULT_ROOT, "--root", help="LocalVault root folder.")


def dry_option() -> bool:
    return typer.Option(False, "--dry-run", help="Preview work without copying or indexing data.")


def prepare(root: Path):
    p = ensure_directories(root)
    db.init_db(p.db)
    configure_logging(p.logs)
    return p


def configure_logging(logs_dir: Path) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=logs_dir / f"localvault_{utc_now().replace(':','').replace('+','Z')}.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", force=True)


def run_with_report(root: Path, source: str, mode: str, func, dry_run: bool = False, *args, **kwargs) -> RunReport:
    p = prepare(root)
    report = start_run(p.db, RunReport(source=source, mode=f"{mode}{'_dry_run' if dry_run else ''}"))
    try:
        func(p, report, dry_run=dry_run, *args, **kwargs)
        status = "ok" if report.failed_count == 0 else "warning"
    except Exception as exc:
        report.error(source, str(exc))
        status = "failed"
    finish_run(p.db, p.reports, report, status=status)
    return report


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


@app.command("sync-sources")
def sync_sources(root: Path = root_option(), dry_run: bool = dry_option()):
    print_summary(run_with_report(root, "source_sync", "sync_sources", run_source_sync, dry_run=dry_run))


@app.command("ingest-takeout")
def ingest_takeout(root: Path = root_option(), dry_run: bool = dry_option()):
    p = prepare(root)
    report = start_run(p.db, RunReport(source="google_takeout", mode="photos_and_gmail_dry_run" if dry_run else "photos_and_gmail"))
    try:
        ingest_google_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
        status = "ok" if report.failed_count == 0 else "warning"
    except Exception as exc:
        report.error("google_takeout", str(exc)); status = "failed"
    finish_run(p.db, p.reports, report, status=status)
    print_summary(report)


@app.command("ingest-whatsapp")
def ingest_whatsapp(root: Path = root_option(), dry_run: bool = dry_option(), media_folder: Optional[Path] = typer.Option(None, "--media-folder")):
    p = prepare(root)
    report = start_run(p.db, RunReport(source="whatsapp", mode="exports_dry_run" if dry_run else "exports"))
    try:
        ingest_whatsapp_exports(p, report, dry_run=dry_run)
        if media_folder:
            copy_whatsapp_media_folder(p, media_folder, report, dry_run=dry_run)
        status = "ok" if report.failed_count == 0 else "warning"
    except Exception as exc:
        report.error("whatsapp", str(exc)); status = "failed"
    finish_run(p.db, p.reports, report, status=status)
    print_summary(report)


@app.command("ingest-all")
def ingest_all(root: Path = root_option(), dry_run: bool = dry_option(), skip_sync: bool = typer.Option(False, "--skip-sync")):
    p = prepare(root)
    report = start_run(p.db, RunReport(source="all_sources", mode="ingest_all_dry_run" if dry_run else "ingest_all"))
    try:
        if not skip_sync:
            run_source_sync(p, report, dry_run=dry_run)
        ingest_google_photos_local_sources(p, report, dry_run=dry_run)
        ingest_google_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
        ingest_whatsapp_exports(p, report, dry_run=dry_run)
        build_duplicate_report(p, report, dry_run=dry_run)
        status = "ok" if report.failed_count == 0 else "warning"
    except Exception as exc:
        report.error("all_sources", str(exc)); status = "failed"
    finish_run(p.db, p.reports, report, status=status)
    print_summary(report)


@app.command("backup-gmail-api")
def backup_gmail_api(root: Path = root_option(), dry_run: bool = dry_option(), max_messages: Optional[int] = typer.Option(None, "--max-messages")):
    print_summary(run_with_report(root, "gmail", "api", run_gmail_api, dry_run=dry_run, max_messages=max_messages))


@app.command("daily-backup")
def daily_backup(root: Path = root_option(), dry_run: bool = dry_option()):
    p = prepare(root)
    report = start_run(p.db, RunReport(source="localvault", mode="daily_backup_dry_run" if dry_run else "daily_backup"))
    try:
        removed = cleanup_missing_index_entries(p)
        if removed:
            report.warn(f"Cleaned {removed} missing index entries before backup.")
        run_gmail_api(p, report, dry_run=dry_run)
        run_source_sync(p, report, dry_run=dry_run)
        ingest_google_photos_local_sources(p, report, dry_run=dry_run)
        ingest_google_photos_takeout(p, report, dry_run=dry_run)
        ingest_gmail_takeout(p, report, dry_run=dry_run)
        ingest_whatsapp_exports(p, report, dry_run=dry_run)
        build_duplicate_report(p, report, dry_run=dry_run)
        verify_vault(p, report, dry_run=False, sample_limit=100)
        status = "ok" if report.failed_count == 0 else "warning"
    except Exception as exc:
        report.error("daily_backup", str(exc)); status = "failed"
    finish_run(p.db, p.reports, report, status=status)
    print_summary(report)


@app.command("rename-gmail-files")
def rename_gmail_files(root: Path = root_option(), dry_run: bool = dry_option()):
    """Rename already imported Gmail .eml files with readable Windows-safe names."""
    print_summary(run_with_report(root, "gmail", "rename_files", rename_existing_gmail_files, dry_run=dry_run))


@app.command("photos-sync-local")
def photos_sync_local(root: Path = root_option(), dry_run: bool = dry_option()):
    """Import photos/videos from configured local Google Photos folders."""
    print_summary(run_with_report(root, "google_photos", "local_sources", ingest_google_photos_local_sources, dry_run=dry_run))


@app.command("photos-add-source")
def photos_add_source(folder: Path, root: Path = root_option()):
    """Add a local folder that LocalVault should monitor for photos/videos."""
    import yaml
    p = prepare(root)
    folder = folder.expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    cfg_path = p.config / "config.yaml"
    cfg = load_config(root)
    sources = list(cfg.setdefault("google_photos", {}).get("local_media_sources", []))
    text_folder = str(folder)
    if text_folder not in sources:
        sources.append(text_folder)
    cfg["google_photos"]["local_media_sources"] = sources
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Google Photos local source added:[/] {folder}")


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
        console.print("[yellow]Cole o Client Secret completo aqui. Ele normalmente começa com GOCSPX-.[/]")
        client_secret = typer.prompt("Client Secret")
    client_id = client_id.strip()
    client_secret = client_secret.strip()
    project_id = project_id.strip()
    if not client_id.endswith(".apps.googleusercontent.com"):
        raise typer.BadParameter("Client ID parece incorreto. Ele deve terminar com .apps.googleusercontent.com")
    if len(client_secret) < 20 or not client_secret.startswith("GOCSPX-"):
        raise typer.BadParameter("Client Secret parece incorreto. Copie o valor completo que começa com GOCSPX-, não o texto mascarado.")
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
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    cfg_path = p.config / "config.yaml"
    cfg_text = cfg_path.read_text(encoding="utf-8")
    cfg_text = cfg_text.replace("api_enabled: false", "api_enabled: true")
    cfg_path.write_text(cfg_text, encoding="utf-8")
    console.print(f"[green]OAuth file written:[/] {target}")
    console.print("Next: python -m localvault backup-gmail-api --root E:\\LocalVault --max-messages 1")


@app.command("sources-status")
def sources_status(root: Path = root_option()):
    p = prepare(root); cfg = load_config(root).get("source_sync", {})
    console.print("[bold]Automatic Source Sync[/]")
    console.print(f"Enabled: {cfg.get('enabled', True)}")
    for name, values in [("Google Takeout", cfg.get("google_takeout_sources", [])), ("WhatsApp exports", cfg.get("whatsapp_export_sources", [])), ("WhatsApp media", cfg.get("whatsapp_media_sources", []))]:
        console.print(f"{name}:")
        for value in values:
            console.print(f"- {value}")
    console.print(f"Takeout ZIPs in inbox: {len(list(p.google_takeout_inbox.glob('*.zip')))}")
    console.print(f"WhatsApp exports in inbox: {len(list(p.whatsapp_exports_inbox.glob('*.zip'))) + len(list(p.whatsapp_exports_inbox.glob('*.txt')))}")


@app.command("open-inboxes")
def open_inboxes(root: Path = root_option()):
    p = prepare(root)
    for folder in (p.google_takeout_inbox, p.whatsapp_exports_inbox, p.manual_imports_inbox):
        if os.name == "nt":
            os.startfile(folder)  # type: ignore[attr-defined]
        else:
            console.print(folder)


@app.command("scan-media")
def scan_media(root: Path = root_option(), dry_run: bool = dry_option()):
    print_summary(run_with_report(root, "vault", "scan_media", scan_existing_media, dry_run=dry_run))


@app.command("dedupe")
def dedupe(root: Path = root_option(), dry_run: bool = dry_option()):
    report = run_with_report(root, "vault", "dedupe", build_duplicate_report, dry_run=dry_run)
    print_summary(report)


@app.command("verify")
def verify(root: Path = root_option(), sample_limit: Optional[int] = typer.Option(None, "--sample-limit")):
    print_summary(run_with_report(root, "vault", "verify", verify_vault, dry_run=False, sample_limit=sample_limit))


@app.command("repair-index")
def repair_index(root: Path = root_option()):
    p = prepare(root)
    removed = cleanup_missing_index_entries(p)
    console.print(f"Removed missing index entries: {removed}")


@app.command("health-check")
def health_check(root: Path = root_option()):
    p = prepare(root)
    health = health_snapshot(p)
    console.print(f"Status: {health['status']}")
    for item in health["checks"]:
        marker = "OK" if item["ok"] else "ATENCAO"
        console.print(f"{marker} - {item['name']}: {item['detail']}")


@app.command("serve")
def serve(root: Path = root_option(), host: Optional[str] = typer.Option(None, "--host"), port: Optional[int] = typer.Option(None, "--port")):
    p = prepare(root); cfg = load_config(root)["viewer"]
    selected_host, selected_port = host or cfg.get("host", "127.0.0.1"), int(port or cfg.get("port", 8787))
    if selected_host not in ("127.0.0.1", "localhost") and not cfg.get("allow_lan", False):
        raise typer.BadParameter("LAN exposure is disabled.")
    uvicorn.run(create_app(p.root), host=selected_host, port=selected_port)


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
