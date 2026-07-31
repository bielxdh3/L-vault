from __future__ import annotations

import email
import html
import re
import secrets
import time
from email import policy
from email.message import EmailMessage
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from starlette.middleware.sessions import SessionMiddleware

from . import db
from .config import load_config, paths
from .auth import SESSION_MAX_AGE, load_auth, verify_password
from .control_panel import control_panel_data, start_background_command
from .vault_index import cleanup_missing_index_entries, dashboard_data, delete_local_file_and_index, open_in_explorer, safe_vault_path

PACKAGE_DIR = Path(__file__).parent


def create_app(root: Path | None = None) -> FastAPI:
    p = paths(root or Path(load_config()["vault_root"]))
    app = FastAPI(title="LocalVault Backup Manager")
    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))

    @pass_context
    def csrf_token(context):
        return getattr(context.get("request").state, "csrf_token", "")

    templates.env.globals["csrf_token"] = csrf_token
    app.mount("/static", StaticFiles(directory=str(PACKAGE_DIR / "static")), name="static")

    @app.middleware("http")
    async def require_authentication(request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path == "/login":
            return await call_next(request)
        record = load_auth(p.root)
        session = request.session
        valid = bool(record and session.get("session_version") == record["session_version"] and session.get("authenticated_at"))
        if not valid:
            accepts = request.headers.get("accept", "")
            if path == "/file" or request.method != "GET" or ("text/html" not in accepts and accepts != "*/*"):
                return PlainTextResponse("Authentication required.", status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.csrf_token = session.get("csrf_token", "")
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            token = request.headers.get("x-csrf-token", "")
            if not token:
                body = (await request.body()).decode("utf-8", "replace")
                from urllib.parse import parse_qs
                token = parse_qs(body).get("csrf_token", [""])[0]
            if not isinstance(token, str) or not request.state.csrf_token or not secrets.compare_digest(token, request.state.csrf_token):
                return PlainTextResponse("Invalid CSRF token.", status_code=403)
        return await call_next(request)

    initial_auth = load_auth(p.root)
    app.add_middleware(SessionMiddleware, secret_key=(initial_auth or {}).get("session_secret", secrets.token_urlsafe(48)), max_age=SESSION_MAX_AGE, same_site="strict", https_only=False)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": "Authentication is not configured." if not load_auth(p.root) else ""})

    @app.post("/login")
    async def login(request: Request):
        from urllib.parse import parse_qs
        password = parse_qs((await request.body()).decode("utf-8", "replace")).get("password", [""])[0]
        record = load_auth(p.root)
        if not verify_password(record, password):
            return templates.TemplateResponse(request, "login.html", {"error": "Senha invalida."}, status_code=401)
        request.session.clear()
        request.session.update({"session_version": record["session_version"], "authenticated_at": int(time.time()), "csrf_token": secrets.token_urlsafe(32)})
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        data = dashboard_data(p)
        data["request"] = request
        data["backup_choices"] = {
            "photos-ingest-takeout": "Importar Takeout/Fotos",
            "backup-gmail-api": "Somente Gmail",
            "daily-backup": "Tudo: Gmail, fotos e Takeout",
        }
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

    @app.get("/backups", response_class=HTMLResponse)
    def backups_page(request: Request):
        with db.connect(p.db) as conn:
            runs = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 20").fetchall()
        backup_choices = {
            "photos-ingest-takeout": "Importar Takeout/Fotos",
            "backup-gmail-api": "Somente Gmail",
            "daily-backup": "Tudo: Gmail, fotos e Takeout",
            "verify": "Verificar cofre",
        }
        return templates.TemplateResponse(request, "backups.html", {"runs": runs, "backup_choices": backup_choices})

    @app.post("/dashboard/backup-now")
    def dashboard_backup_now():
        start_background_command(p, "photos-ingest-takeout")
        return RedirectResponse("/", status_code=303)

    @app.get("/dashboard/backup-now")
    def dashboard_backup_now_get():
        return RedirectResponse("/", status_code=303)

    @app.post("/dashboard/run-backup")
    def dashboard_run_backup(command: str = Query("photos-ingest-takeout")):
        try:
            start_background_command(p, command)
        except ValueError:
            raise HTTPException(400)
        return RedirectResponse("/", status_code=303)

    @app.post("/maintenance/cleanup-missing")
    def cleanup_missing():
        cleanup_missing_index_entries(p)
        return RedirectResponse("/control", status_code=303)

    @app.post("/actions/open-folder")
    def open_folder(path: str = Query(...)):
        try:
            open_in_explorer(safe_vault_path(p.root, path, require_vault=True))
        except ValueError:
            raise HTTPException(403)
        return RedirectResponse("/", status_code=303)

    @app.post("/actions/delete-file")
    def delete_file(path: str = Query(...)):
        try:
            target = safe_vault_path(p.root, path, require_vault=True)
        except ValueError:
            raise HTTPException(403)
        delete_local_file_and_index(p, target)
        return RedirectResponse("/", status_code=303)

    @app.get("/gmail", response_class=HTMLResponse)
    def gmail_page(
        request: Request,
        q: str = "",
        sender: str = "",
        date_from: str = "",
        date_to: str = "",
        has_attachments: bool = False,
        page: int = 1,
    ):
        clauses, params = [], []
        if q:
            clauses.append("(m.sender LIKE ? OR m.subject LIKE ? OR m.snippet LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if sender:
            clauses.append("m.sender LIKE ?")
            params.append(f"%{sender}%")
        if date_from:
            clauses.append("m.message_date >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("m.message_date <= ?")
            params.append(date_to + " 23:59:59")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        having = "HAVING COUNT(a.id) > 0" if has_attachments else ""
        with db.connect(p.db) as conn:
            rows = conn.execute(
                f"""
                SELECT m.*, COUNT(a.id) AS attachment_count
                FROM gmail_messages m
                LEFT JOIN gmail_attachments a ON a.gmail_message_id=m.id
                {where}
                GROUP BY m.id
                {having}
                ORDER BY m.message_date DESC, m.id DESC
                LIMIT 80 OFFSET ?
                """,
                (*params, max(0, page - 1) * 80),
            ).fetchall()
        items = []
        for row in rows:
            item = _clean_email_row(dict(row))
            item["exists"] = bool(item["eml_path"] and Path(item["eml_path"]).exists())
            items.append(item)
        return templates.TemplateResponse(
            request,
            "gmail.html",
            {
                "rows": items,
                "q": q,
                "sender": sender,
                "date_from": date_from,
                "date_to": date_to,
                "has_attachments": has_attachments,
                "page": page,
            },
        )

    @app.get("/gmail/{message_id}", response_class=HTMLResponse)
    def gmail_message(request: Request, message_id: int):
        with db.connect(p.db) as conn:
            msg = conn.execute("SELECT * FROM gmail_messages WHERE id=?", (message_id,)).fetchone()
            attachments = conn.execute("SELECT * FROM gmail_attachments WHERE gmail_message_id=?", (message_id,)).fetchall()
            stored_body = conn.execute("SELECT * FROM gmail_bodies WHERE gmail_message_id=?", (message_id,)).fetchone()
        if not msg:
            raise HTTPException(404)
        body = _stored_email_body(stored_body) if stored_body else (_email_body(Path(msg["eml_path"])) if msg["eml_path"] else {"mode": "text", "content": ""})
        message = _clean_email_row(dict(msg))
        message["exists"] = bool(message["eml_path"] and Path(message["eml_path"]).exists())
        attachment_items = []
        for item in attachments:
            attachment = dict(item)
            attachment["filename"] = html.unescape(str(attachment.get("filename") or ""))
            attachment["exists"] = bool(attachment["path"] and Path(attachment["path"]).exists())
            attachment_items.append(attachment)
        return templates.TemplateResponse(request, "gmail_message.html", {"message": message, "attachments": attachment_items, "body": body})

    @app.get("/photos")
    def photos_redirect():
        return RedirectResponse("/fotos", status_code=307)

    @app.get("/fotos", response_class=HTMLResponse)
    def photos_page(
        request: Request,
        q: str = "",
        media_type: str = "",
        album: str = "",
        date_from: str = "",
        date_to: str = "",
        sort: str = "date_desc",
        layout: str = "auto",
        page: int = 1,
    ):
        clauses, params = [], []
        if q:
            clauses.append("(filename LIKE ? OR album LIKE ? OR creation_date LIKE ? OR google_metadata_date LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
        if media_type:
            clauses.append("media_type=?")
            params.append(media_type)
        if album:
            clauses.append("album LIKE ?")
            params.append(f"%{album}%")
        if date_from:
            clauses.append("COALESCE(creation_date, google_metadata_date, exif_date, imported_at) >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("COALESCE(creation_date, google_metadata_date, exif_date, imported_at) <= ?")
            params.append(date_to + " 23:59:59")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        order_by = {
            "date_asc": "COALESCE(creation_date, google_metadata_date, exif_date, imported_at) ASC",
            "name_asc": "filename ASC",
            "name_desc": "filename DESC",
            "size_desc": "file_size DESC",
            "size_asc": "file_size ASC",
        }.get(sort, "COALESCE(creation_date, google_metadata_date, exif_date, imported_at) DESC")
        layout = layout if layout in {"auto", "three", "four", "five", "compact"} else "auto"
        with db.connect(p.db) as conn:
            rows = conn.execute(f"SELECT * FROM photo_items {where} ORDER BY {order_by} LIMIT 80 OFFSET ?", (*params, max(0, page - 1) * 80)).fetchall()
            albums = [
                row["album"]
                for row in conn.execute("SELECT DISTINCT album FROM photo_items WHERE album IS NOT NULL AND album != '' ORDER BY album LIMIT 80").fetchall()
            ]
        items = [{**dict(row), "exists": bool(row["path"] and Path(row["path"]).exists())} for row in rows]
        return templates.TemplateResponse(
            request,
            "fotos.html",
            {
                "rows": items,
                "q": q,
                "media_type": media_type,
                "album": album,
                "albums": albums,
                "date_from": date_from,
                "date_to": date_to,
                "sort": sort,
                "layout": layout,
                "page": page,
            },
        )

    @app.get("/fotos/{item_id}", response_class=HTMLResponse)
    def photo_detail(request: Request, item_id: int):
        with db.connect(p.db) as conn:
            row = conn.execute("SELECT * FROM photo_items WHERE id=?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(404)
        item = {**dict(row), "exists": bool(row["path"] and Path(row["path"]).exists())}
        return templates.TemplateResponse(request, "foto_detail.html", {"item": item})

    @app.get("/reports", response_class=HTMLResponse)
    def reports_page(request: Request):
        with db.connect(p.db) as conn:
            runs = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 50").fetchall()
            errors = conn.execute("SELECT * FROM import_errors ORDER BY id DESC LIMIT 100").fetchall()
        return templates.TemplateResponse(request, "reports.html", {"runs": runs, "errors": errors})

    @app.get("/file")
    def file(path: str = Query(...)):
        try:
            requested = safe_vault_path(p.root, path, require_vault=True)
        except ValueError:
            raise HTTPException(403)
        if not requested.exists() or not requested.is_file():
            raise HTTPException(404)
        return FileResponse(requested)

    return app


def _count(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _email_body(path: Path) -> dict[str, str]:
    try:
        msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        html_body = _message_part(msg, "text/html")
        if html_body:
            sanitized = _sanitize_email_html(html_body)
            preview = _html_to_text(html_body)
            return {"mode": "html", "content": sanitized, "preview": preview}
        text_body = _message_part(msg, "text/plain")
        if text_body:
            return {"mode": "text", "content": text_body}
        return {"mode": "text", "content": msg.get_content() if not msg.is_multipart() else ""}
    except Exception as exc:
        return {"mode": "text", "content": f"Could not read message body: {exc}"}


def _stored_email_body(row) -> dict[str, str]:
    html_path = row["body_html_path"]
    if html_path and Path(html_path).exists():
        raw_html = Path(html_path).read_text(encoding="utf-8", errors="replace")
        return {"mode": "html", "content": _sanitize_email_html(raw_html), "preview": _html_to_text(raw_html)}
    return {"mode": "text", "content": row["body_text"] or ""}


def _message_part(msg: EmailMessage, content_type: str) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type and not part.get_content_disposition():
                return str(part.get_content())
        return ""
    if msg.get_content_type() == content_type:
        return str(msg.get_content())
    return ""


def _clean_email_row(item: dict) -> dict:
    for key in ("subject", "sender", "recipients", "cc", "bcc", "snippet"):
        if item.get(key):
            item[key] = html.unescape(str(item[key]))
    return item


def _html_to_text(value: str) -> str:
    without_blocks = re.sub(r"(?is)<(script|style|iframe|object|embed|head)\b.*?</\1>", " ", value)
    text = re.sub(r"(?s)<[^>]+>", " ", without_blocks)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _sanitize_email_html(value: str) -> str:
    import nh3

    cleaned = nh3.clean(value, tags={"a", "b", "blockquote", "br", "code", "div", "em", "i", "li", "ol", "p", "pre", "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "u", "ul"}, attributes={"a": {"href", "title"}, "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"}}, url_schemes={"http", "https", "mailto"})
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><base target=\"_blank\"><style>body{{font:14px Arial,sans-serif;line-height:1.5;color:#202124;margin:18px}}</style></head><body>{cleaned}</body></html>"
