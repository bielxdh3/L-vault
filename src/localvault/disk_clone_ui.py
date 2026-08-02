from __future__ import annotations

"""Small optional native warning window for the guarded clone workflow."""

import os
from pathlib import Path
from typing import Callable

from .config import paths
from .disk_clone import create_control_request


WARNING_TEXT = (
    "CLONAGEM COMPLETA DO DISCO\n\n"
    "O L-vault apagará completamente o HD de backup e criará um clone inicializável do SSD principal.\n\n"
    "Evite jogos, atualizações, máquinas virtuais e tarefas pesadas."
)


class CountdownController:
    def __init__(self, seconds: int, *, on_confirm: Callable[[], None], on_cancel: Callable[[], None]):
        self.remaining = max(0, int(seconds))
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel
        self.hidden = False

    def confirm(self) -> str:
        self.on_confirm()
        return "confirm"

    def cancel(self) -> str:
        self.on_cancel()
        return "cancel"

    def hide(self) -> None:
        self.hidden = True


def native_countdown(root: Path, seconds: int = 300) -> str:
    """Run one local warning window; closing it hides it instead of cancelling."""
    if os.name != "nt":
        return "cancel"
    import tkinter as tk
    from tkinter import ttk
    p = paths(root)
    window = tk.Tk()
    window.title("L-vault - Clone do disco")
    window.configure(bg="#e3efeb")
    window.attributes("-topmost", True)
    window.protocol("WM_DELETE_WINDOW", window.withdraw)
    frame = ttk.Frame(window, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=WARNING_TEXT, justify="left", wraplength=560).pack(fill="x", pady=(0, 18))
    timer = ttk.Label(frame, text="A clonagem começará automaticamente em 05:00.")
    timer.pack(anchor="w", pady=(0, 14))
    actions = ttk.Frame(frame)
    actions.pack(fill="x")

    remaining = max(0, int(seconds))
    decision = {"value": "cancel"}

    def cancel() -> None:
        decision["value"] = "cancel"
        create_control_request(p.db, "cancel", actor="native-ui")
        window.destroy()

    def confirm() -> None:
        decision["value"] = "confirm"
        create_control_request(p.db, "preflight", actor="native-ui")
        window.destroy()

    ttk.Button(actions, text="Clonar agora", command=confirm).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Ocultar", command=window.withdraw).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Cancelar", command=cancel).pack(side="left")

    def tick() -> None:
        nonlocal remaining
        minutes, seconds_left = divmod(max(0, remaining), 60)
        timer.configure(text=f"A clonagem começará automaticamente em {minutes:02d}:{seconds_left:02d}.")
        if remaining <= 0:
            confirm()
            return
        remaining -= 1
        window.after(1000, tick)

    def poll_restore() -> None:
        if not window.winfo_exists():
            return
        from . import db

        with db.connect(p.db) as conn:
            row = conn.execute("SELECT request_id,action FROM disk_clone_controls WHERE handled_at IS NULL AND action='show' ORDER BY created_at LIMIT 1").fetchone()
            if row:
                conn.execute("UPDATE disk_clone_controls SET handled_at=? WHERE request_id=?", (datetime_now(), row["request_id"]))
                window.deiconify()
                window.attributes("-topmost", True)
        window.after(500, poll_restore)

    window.after(0, tick)
    window.after(0, poll_restore)
    window.mainloop()
    return decision["value"]


def run_native_ui(root: Path, seconds: int = 300) -> None:
    native_countdown(root, seconds)


def datetime_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
