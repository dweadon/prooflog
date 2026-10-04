"""Tracks how far the current analysis has got, so the dashboard can show
progress (GET /status) during the minutes the AI is working."""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_state = {"stage": "idle", "done": 0, "total": 0, "elapsed_seconds": 0}
_started = 0.0


# Starts a new stage, e.g. ("writing_claims", 12 alerts). `done` goes back to 0.
def start_stage(stage: str, total: int = 0) -> None:
    global _started
    with _lock:
        if stage == "parsing":
            _started = time.monotonic()
        _state.update(stage=stage, done=0, total=total)


# Records one finished unit of work (one alert analysed, one claim checked).
def step() -> None:
    with _lock:
        _state["done"] += 1


# A copy of the current progress, safe to return from the API.
def snapshot() -> dict:
    with _lock:
        running = _state["stage"] not in ("idle", "done", "error")
        elapsed = round(time.monotonic() - _started) if running else _state["elapsed_seconds"]
        _state["elapsed_seconds"] = elapsed
        return dict(_state)
