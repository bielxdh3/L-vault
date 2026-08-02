from __future__ import annotations

"""Headless state model plus the optional Windows native clone window."""

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import paths
from .disk_clone import active_clone_run_id, claim_control_request, create_control_request


WARNING_TEXT = (
    "CLONAGEM COMPLETA DO DISCO\n\n"
    "O L-vault apagará completamente o HD de backup e criará um clone inicializável do SSD principal.\n\n"
    "Evite jogos, atualizações, máquinas virtuais e tarefas pesadas."
)

RUN_STATES = {
    "countdown",
    "preflight",
    "sampling_activity",
    "cloning",
    "verifying",
    "returning_target_offline",
    "success",
    "error",
    "hidden",
}


@dataclass
class CloneUIState:
    state: str = "countdown"
    remaining: int = 300
    hidden: bool = False
    progress_type: str = "unavailable"
    percent: float | None = None
    copied_bytes: int | None = None
    speed_bytes: int | None = None
    eta_seconds: int | None = None
    phase: str = "countdown"
    error: str = ""
    error_until: float = 0.0
    source_label: str = ""
    target_label: str = ""
    source_size_bytes: int | None = None
    target_size_bytes: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


class CountdownController:
    """Testable controller; hiding never cancels and zero confirms exactly once."""

    def __init__(self, seconds: int, *, on_confirm: Callable[[], None], on_cancel: Callable[[], None], on_retry: Callable[[], None] | None = None, on_close: Callable[[], None] | None = None, cancellation_supported: bool = False):
        self.remaining = max(0, int(seconds))
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel
        self.on_retry = on_retry or (lambda: None)
        self.on_close = on_close or (lambda: None)
        self.cancellation_supported = cancellation_supported
        self.hidden = False
        self.state = CloneUIState(remaining=self.remaining)
        self._confirmed = False

    def confirm(self) -> str:
        if self.state.state != "countdown" or self._confirmed:
            return self.state.state
        self._confirmed = True
        self.state.state = "preflight"
        self.state.phase = "preflight"
        self.on_confirm()
        return "confirm"

    def cancel(self) -> str:
        if self.state.state == "cloning" and not self.cancellation_supported:
            return "unsupported_cancel"
        self.state.state = "error" if self.state.state not in {"countdown", "preflight"} else "cancelled"
        self.on_cancel()
        return "cancel"

    def tick(self) -> str:
        if self.state.state != "countdown" or self._confirmed:
            return self.state.state
        if self.remaining <= 0:
            return self.confirm()
        self.remaining -= 1
        self.state.remaining = self.remaining
        return "countdown"

    def hide(self) -> None:
        self.hidden = True
        self.state.hidden = True

    def restore(self) -> None:
        self.hidden = False
        self.state.hidden = False

    def transition(self, state: str, **details: Any) -> str:
        if state not in RUN_STATES:
            raise ValueError(f"unsupported clone UI state: {state}")
        self.state.state = state
        self.state.phase = details.pop("phase", state)
        for key, value in details.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)
        if state == "error":
            self.state.error_until = time.monotonic() + 300
        return state

    def progress(self, event: dict[str, Any]) -> str:
        progress_type = str(event.get("progress_type") or "unavailable")
        if progress_type not in {"exact", "estimated", "unavailable"}:
            progress_type = "unavailable"
        self.transition("cloning", phase=str(event.get("phase") or "cloning"), progress_type=progress_type, percent=event.get("percent"), copied_bytes=event.get("copied_bytes"), speed_bytes=event.get("speed_bytes"), eta_seconds=event.get("eta_seconds"))
        return progress_type

    def error(self, reason: str, **details: Any) -> str:
        return self.transition("error", error=str(reason), details=details)

    def retry(self) -> str:
        if self.state.state != "error":
            return "retry_unavailable"
        self.state.state = "preflight"
        self.state.phase = "preflight"
        self.state.error = ""
        self.on_retry()
        return "retry"

    def close(self) -> str:
        self.on_close()
        return "close"

    def error_expired(self, now: float | None = None) -> bool:
        return self.state.state == "error" and (now if now is not None else time.monotonic()) >= self.state.error_until

    def apply_durable_state(self, run_state: str, *, reason: str = "", progress: dict[str, Any] | None = None) -> str:
        if progress:
            self.progress(progress)
        if run_state in {"countdown", "preflight", "sampling_activity", "verifying", "returning_target_offline", "success"}:
            return self.transition(run_state)
        if run_state == "cloning":
            return self.state.state
        if run_state in {"error", "failed_provider", "failed_verification", "failed_offline_cleanup", "blocked_provider", "blocked_identity", "cancelled_before_start", "interrupted"}:
            return self.error(reason or run_state)
        return self.state.state


CloneUIController = CountdownController


def _spawn_monitor(root: Path) -> None:
    command = [sys.executable, "-m", "localvault", "disk-clone-ui", "--root", str(root), "--monitor"]
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        subprocess.Popen(command, close_fds=True, creationflags=flags)
    except OSError:
        # The orchestration remains authoritative; a missing monitor cannot enable or cancel a provider.
        return


def _run_window(root: Path, seconds: int = 300) -> str:
    if os.name != "nt":
        return "cancel"
    import tkinter as tk
    from tkinter import ttk

    p = paths(root)
    window = tk.Tk()
    window.title("L-vault - Clone do disco")
    window.configure(bg="#e3efeb")
    window.attributes("-topmost", True)
    controller = CountdownController(seconds, on_confirm=lambda: create_control_request(p.db, "preflight", actor="native-ui"), on_cancel=lambda: create_control_request(p.db, "cancel", actor="native-ui"))
    window.protocol("WM_DELETE_WINDOW", controller.hide)
    style = ttk.Style(window)
    style.configure("Clone.TFrame", background="#e3efeb")
    frame = ttk.Frame(window, padding=24, style="Clone.TFrame")
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=WARNING_TEXT, justify="left", wraplength=560).pack(fill="x", pady=(0, 18))
    labels = ttk.Label(frame, text="")
    labels.pack(anchor="w", pady=(0, 14))
    phase = ttk.Label(frame, text="Preflight de seguranca aguardando confirmacao.")
    phase.pack(anchor="w", pady=(0, 14))
    actions = ttk.Frame(frame)
    actions.pack(fill="x")

    def cancel() -> None:
        controller.cancel()
        window.destroy()

    def confirm() -> None:
        controller.confirm()
        _spawn_monitor(root)
        window.destroy()

    ttk.Button(actions, text="Clonar agora", command=confirm).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Ocultar", command=controller.hide).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Cancelar", command=cancel).pack(side="left")

    def tick() -> None:
        state = controller.state
        minutes, seconds_left = divmod(max(0, controller.remaining), 60)
        labels.configure(text=f"A clonagem começará automaticamente em {minutes:02d}:{seconds_left:02d}.")
        if controller.tick() == "countdown":
            window.after(1000, tick)
        else:
            confirm()

    def poll_restore() -> None:
        if not window.winfo_exists():
            return
        run_id = active_clone_run_id(p.db)
        current = claim_control_request(p.db, "show", run_id) if run_id else None
        if current:
            controller.restore()
            window.deiconify()
            window.attributes("-topmost", True)
        window.after(500, poll_restore)

    window.after(0, tick)
    window.after(0, poll_restore)
    window.mainloop()
    return "confirm" if controller._confirmed else "cancel"


def _monitor_window(root: Path) -> None:
    if os.name != "nt":
        return
    import tkinter as tk
    from tkinter import messagebox, ttk
    from . import db

    p = paths(root)
    window = tk.Tk()
    window.title("L-vault - Estado do clone")
    window.configure(bg="#e3efeb")
    window.attributes("-topmost", True)
    controller = CloneUIController(0, on_confirm=lambda: None, on_cancel=lambda: None)
    frame = ttk.Frame(window, padding=24)
    frame.pack(fill="both", expand=True)
    title = ttk.Label(frame, text="Clone do disco")
    title.pack(anchor="w")
    status = ttk.Label(frame, text="Aguardando estado persistido...")
    status.pack(anchor="w", pady=(8, 4))
    detail = ttk.Label(frame, text="", justify="left", wraplength=560)
    detail.pack(anchor="w", pady=(0, 14))
    actions = ttk.Frame(frame)
    actions.pack(fill="x")

    def hide() -> None:
        controller.hide()
        window.withdraw()

    def show_details() -> None:
        messagebox.showinfo("Detalhes do clone", controller.state.error or detail.cget("text") or "Nenhum detalhe adicional.", parent=window)

    def retry() -> None:
        with db.connect(p.db) as conn:
            row = conn.execute("SELECT run_id FROM disk_clone_runs ORDER BY started_at DESC LIMIT 1").fetchone()
        if row:
            create_control_request(p.db, "retry", run_id=row["run_id"], actor="native-ui")
            controller.retry()

    ttk.Button(actions, text="Ocultar", command=hide).pack(side="left", padx=(0, 8))
    details_button = ttk.Button(actions, text="Ver detalhes", command=show_details)
    details_button.pack(side="left", padx=(0, 8))
    retry_button = ttk.Button(actions, text="Retry", command=retry)
    retry_button.pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Fechar", command=window.destroy).pack(side="left")

    def poll() -> None:
        if not window.winfo_exists():
            return
        with db.connect(p.db) as conn:
            run = conn.execute("SELECT * FROM disk_clone_runs ORDER BY started_at DESC LIMIT 1").fetchone()
            progress = None
            if run:
                progress_row = conn.execute("SELECT progress_type,percent,copied_bytes,speed_bytes,eta_seconds,phase FROM disk_clone_progress WHERE run_id=? ORDER BY id DESC LIMIT 1", (run["run_id"],)).fetchone()
                progress = dict(progress_row) if progress_row else None
        if run:
            state = controller.apply_durable_state(run["state"], reason=run["reason"] or "", progress=progress)
            status.configure(text=f"Estado: {state}")
            detail.configure(text=run["reason"] or (progress or {}).get("phase", ""))
            retry_button.configure(state="normal" if state == "error" else "disabled")
            details_button.configure(state="normal" if state == "error" else "disabled")
            if state == "success":
                detail.configure(text="Verificacao estrutural aprovada; boot nao testado manualmente.")
        window.after(1000, poll)

    window.protocol("WM_DELETE_WINDOW", hide)
    window.after(0, poll)
    window.mainloop()


def native_countdown(root: Path, seconds: int = 300) -> str:
    """Run one local warning window; closing it hides it instead of cancelling."""
    return _run_window(root, seconds)


def run_native_ui(root: Path, seconds: int = 300, *, monitor: bool = False) -> None:
    if monitor:
        _monitor_window(root)
    else:
        native_countdown(root, seconds)


def datetime_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
