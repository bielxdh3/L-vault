from __future__ import annotations

import email
from email import policy
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db
from .config import load_config, paths
from .control_panel import control_panel_data, start_background_command
from .vault_index import cleanup_missing_index_entries, dashboard_data, delete_local_file_and_index, open_in_explorer, safe_vault_path

PACKAGE_DIR = Path(__file__).parent


def create_app(root: Path | None = None) -> FastAPI:
    p = paths(root or Path(load_config()["vault_root"]))
    app = FastAPI(title="LocalVault Backup Manager")
    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(PACKAGE_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        data = dashboard_data(p)
        data["request"] = request
        return templates.TemplateResponse(request, "dashboard.html", data)

    @app.get("/control", response_class=HTMLResponse)
    def control(request: Request):
        data = control_panel_data(p)
        data["request"] = request
        return templates.TemplateResponse(request, "control.html", data)

    @app.post("/control/run")
    def control_run(command: str = Query(...)):
        try:
            start_background_command(p, command)
        except ValueError:
            raise HTTPException(400)
        return RedirectResponse("/control", status_code=303)

    @app.post("/dashboard/backup-now")
    def dashboard_backup_now():
        start_background_command(p, "daily-backup")
        return RedirectResponse("/", status_code=303)

    @app.get("/dashboard/backup-now")
    def dashboard_backup_now_get():
        start_background_command(p, "daily-backup")
        return RedirectResponse("/", status_code=303)

    @app.post("/maintenance/cleanup-missing")
    def cleanup_missing():
        cleanup_missing_index_entries(p)
        return RedirectResponse("/control", status_code=303)

    @app.post("/actions/open-folder")
    def open_folder(path: str = Query(...)):
        try:
            open_in_explorer(safe_vault_path(p.root, path))
        except ValueError:
            raise HTTPException(403)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/delete-file")
    def delete_file(path: str = Query(...)):
        try:
            target = safe_vault_path(p.root, path)
        except ValueError:
            raise HTTPException(403)
        delete_local_file_and_index(p, target)
        return RedirectResponse("/", status_code=303)

    @app.get("/gmail", response_class=HTMLResponse)
    def gmail_page(request: Request, q: str = "", page: int = 1):
        where, params = "", []
        if q:
            where, params = "WHERE sender LIKE ? OR subject LIKE ? OR snippet LIKE ?", [f"%{q}%", f"%{q}%", f"%{q}%"]
        with db.connect(p.db) as conn:
            rows = conn.execute(f"SELECT * FROM gmail_messages {where} ORDER BY id DESC LIMIT 80 OFFSET ?", (*params, max(0, page - 1) * 80)).fetchall()
        items = [{**dict(row), "exists": bool(row["eml_path"] and Path(row["eml_path"]).exists())} for row in rows]
        return templates.TemplateResponse(request, "gmail.html", {"rows": items, "q": q, "page": page})

    @app.get("/gmail/{message_id}", response_class=HTMLResponse)
    def gmail_message(request: Request, message_id: int):
        with db.connect(p.db) as conn:
            msg = conn.execute("SELECT * FROM gmail_messages WHERE id=?", (message_id,)).fetchone()
            attachments = conn.execute("SELECT * FROM gmail_attachments WHERE gmail_message_id=?", (message_id,)).fetchall()
        if not msg:
            raise HTTPException(404)
        body = _email_body(Path(msg["eml_path"])) if msg["eml_path"] else ""
        message = {**dict(msg), "exists": bool(msg["eml_path"] and Path(msg["eml_path"]).exists())}
        attachment_items = [{**dict(item), "exists": bool(item["path"] and Path(item["path"]).exists())} for item in attachments]
        return templates.TemplateResponse(request, "gmail_message.html", {"message": message, "attachments": attachment_items, "body": body})

    @app.get("/photos", response_class=HTMLResponse)
    def photos_page(request: Request, q: str = "", media_type: str = "", page: int = 1):
        clauses, params = [], []
        if q:
            clauses.append("(filename LIKE ? OR album LIKE ? OR creation_date LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if media_type:
            clauses.append("media_type=?")
            params.append(media_type)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with db.connect(p.db) as conn:
            rows = conn.execute(f"SELECT * FROM google_photos_items {where} ORDER BY creation_date DESC LIMIT 80 OFFSET ?", (*params, max(0, page - 1) * 80)).fetchall()
        items = [{**dict(row), "exists": bool(row["path"] and Path(row["path"]).exists())} for row in rows]
        return templates.TemplateResponse(request, "photos.html", {"rows": items, "q": q, "media_type": media_type, "page": page})

    @app.get("/whatsapp", response_class=HTMLResponse)
    def whatsapp_page(request: Request):
        with db.connect(p.db) as conn:
            rows = conn.execute("SELECT c.*,COUNT(m.id) message_count FROM whatsapp_chats c LEFT JOIN whatsapp_messages m ON m.chat_id=c.id GROUP BY c.id ORDER BY c.chat_name").fetchall()
        return templates.TemplateResponse(request, "whatsapp.html", {"rows": rows})

    @app.get("/whatsapp/{chat_id}", response_class=HTMLResponse)
    def whatsapp_chat(request: Request, chat_id: int, q: str = "", page: int = 1):
        where, params = "WHERE chat_id=?", [chat_id]
        if q:
            where += " AND (text LIKE ? OR sender LIKE ?)"
            params += [f"%{q}%", f"%{q}%"]
        with db.connect(p.db) as conn:
            chat = conn.execute("SELECT * FROM whatsapp_chats WHERE id=?", (chat_id,)).fetchone()
            rows = conn.execute(f"SELECT * FROM whatsapp_messages {where} ORDER BY id LIMIT 250 OFFSET ?", (*params, max(0, page - 1) * 250)).fetchall()
        if not chat:
            raise HTTPException(404)
        return templates.TemplateResponse(request, "whatsapp_chat.html", {"chat": chat, "rows": rows, "q": q, "page": page})

    @app.get("/reports", response_class=HTMLResponse)
    def reports_page(request: Request):
        with db.connect(p.db) as conn:
            runs = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 50").fetchall()
            errors = conn.execute("SELECT * FROM import_errors ORDER BY id DESC LIMIT 100").fetchall()
        return templates.TemplateResponse(request, "reports.html", {"runs": runs, "errors": errors})

    @app.get("/file")
    def file(path: str = Query(...)):
        requested = Path(path).resolve()
        root_resolved = p.root.resolve()
        if root_resolved != requested and root_resolved not in requested.parents:
            raise HTTPException(403)
        if not requested.exists() or not requested.is_file():
            raise HTTPException(404)
        return FileResponse(requested)

    return app


def _count(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _email_body(path: Path) -> str:
    try:
        msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_content()
        return msg.get_content()
    except Exception as exc:
        return f"Could not read message body: {exc}"
