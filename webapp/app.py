from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from storage.secure_storage import SecureStorage
from config import STORAGE, PROTECTED_DIR, CRYPTO, get_env_passphrase
from data_bootstrap import ensure_10_plaintext_originals
from encryption import aes_crypto

try:
    from config import load_dotenv_if_present
except Exception:  # pragma: no cover
    from crypto_ransomware_system.config import load_dotenv_if_present


# Ensure DEMO_SECRET_KEY etc can be read when running with uvicorn directly.
load_dotenv_if_present()


class SystemMode(str, Enum):
    AES_NORMAL = "AES_NORMAL"
    HONEY = "HONEY"


@dataclass(frozen=True)
class FileItem:
    file_id: str
    display_name: str


def _file_path(file_id: str) -> Path:
    return PROTECTED_DIR / f"{file_id}.txt"


class LogLevel(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ALERT = "ALERT"


@dataclass(frozen=True)
class LogEntry:
    id: int
    ts: float
    level: LogLevel
    message: str


class LogBuffer:
    def __init__(self, max_entries: int = 2000):
        self._entries: deque[LogEntry] = deque(maxlen=max_entries)
        self._next_id = 1

    def push(self, level: LogLevel, message: str) -> None:
        entry = LogEntry(id=self._next_id, ts=time.time(), level=level, message=message)
        self._next_id += 1
        self._entries.append(entry)

    def since(self, after_id: int) -> list[LogEntry]:
        return [e for e in self._entries if e.id > after_id]

    def clear(self) -> None:
        self._entries.clear()


class _LogAdapter:
    def __init__(self, buf: LogBuffer):
        self._buf = buf

    def info(self, message: str) -> None:
        self._buf.push(LogLevel.INFO, message)

    def warning(self, message: str) -> None:
        self._buf.push(LogLevel.WARN, message)

    def error(self, message: str) -> None:
        self._buf.push(LogLevel.ALERT, message)


class Predictor:
    """Simulation-friendly ransomware behavior detector.

    Signals:
    - high frequency accesses
    - repeated key failures
    - explicit ransomware simulation button

    This is intentionally lightweight and deterministic for demos.
    """

    def __init__(self):
        self._events: deque[tuple[float, str]] = deque(maxlen=5000)
        self._failed_keys_in_window: deque[float] = deque(maxlen=5000)

    def record(self, event_type: str) -> None:
        now = time.time()
        self._events.append((now, event_type))
        if event_type == "KEY_FAIL":
            self._failed_keys_in_window.append(now)

    def assess(self) -> tuple[bool, list[str]]:
        now = time.time()
        window_s = 15.0
        recent = [t for (t, _) in self._events if t >= now - window_s]
        access_recent = [t for (t, e) in self._events if t >= now - window_s and e == "ACCESS"]
        failed_recent = [t for t in self._failed_keys_in_window if t >= now - window_s]

        reads_per_min = len(access_recent) / max(window_s / 60.0, 1e-6)
        fails_per_min = len(failed_recent) / max(window_s / 60.0, 1e-6)

        reasons: list[str] = []
        if reads_per_min >= 60:
            reasons.append(f"High-frequency reads: {reads_per_min:.1f}/min")
        if fails_per_min >= 20:
            reasons.append(f"Repeated key failures: {fails_per_min:.1f}/min")

        # Consider any explicit ransomware sim events as immediate trigger.
        sim_events = [1 for (t, e) in self._events if t >= now - window_s and e == "SIM_RANSOMWARE"]
        if sim_events:
            reasons.append("Ransomware simulation signal")

        detected = bool(sim_events) or (reads_per_min >= 80) or (fails_per_min >= 30)
        return detected, reasons

    def reset(self) -> None:
        self._events.clear()
        self._failed_keys_in_window.clear()


def _decrypt_latest_for(file_name: str, passphrase: str, storage: SecureStorage) -> str:
    latest = storage.latest_real_version_path(file_name)
    if latest is None:
        raise FileNotFoundError("No encrypted version available")
    pt = aes_crypto.decrypt_bytes(latest.read_bytes(), passphrase, CRYPTO.pbkdf2_iterations)
    return pt.decode("utf-8", errors="replace")


def _garbage_text(file_name: str, entered_key: str, target_len: int) -> str:
    """Deterministic 'garbage' output for wrong-key AES attempts.

    AES-GCM decryption fails fast on wrong keys; for the demo UX we emulate
    the classic "wrong key -> garbage" effect deterministically.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update((file_name + "|" + entered_key).encode("utf-8"))
    seed = digest.finalize()
    out = bytearray()
    while len(out) < max(32, target_len):
        d = hashes.Hash(hashes.SHA256())
        d.update(seed)
        d.update(len(out).to_bytes(4, "big"))
        out.extend(d.finalize())
    blob = bytes(out[: max(32, target_len)])
    return blob.decode("utf-8", errors="replace")


def _fake_sensitive_text(file_name: str, passphrase: str) -> str:
    """Generate plausible fake plaintext deterministically from (file, key).

    No fake files are stored; the content is generated on demand.
    """

    seed_material = (file_name + "|" + passphrase).encode("utf-8")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(seed_material)
    seed = int.from_bytes(digest.finalize()[:8], "big")

    # Simple deterministic PRNG.
    x = seed & 0xFFFFFFFFFFFFFFFF

    def rnd() -> int:
        nonlocal x
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        return x

    names = [
        "A. Sharma",
        "R. Iyer",
        "S. Khan",
        "M. Patel",
        "N. Das",
        "K. Singh",
        "P. Rao",
    ]
    departments = ["Finance", "HR", "Research", "IT", "Admin", "Procurement"]
    cities = ["Pune", "Bengaluru", "Delhi", "Mumbai", "Hyderabad", "Chennai"]

    person = names[rnd() % len(names)]
    dept = departments[rnd() % len(departments)]
    city = cities[rnd() % len(cities)]

    amount = 50000 + (rnd() % 450000)
    account = 10000000 + (rnd() % 90000000)
    ticket = 1000 + (rnd() % 9000)

    # Structured, realistic-looking "sensitive" text.
    return (
        f"CONFIDENTIAL RECORD\n"
        f"File: {file_name}\n"
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Employee: {person}\n"
        f"Department: {dept}\n"
        f"Location: {city}\n"
        f"Reference Ticket: SEC-{ticket}\n\n"
        f"Summary:\n"
        f"- Payroll adjustment approved: INR {amount}\n"
        f"- Account reference: ****{str(account)[-4:]}\n"
        f"- Notes: Review scheduled; action items pending verification.\n"
    )


class OpenFileRequest(BaseModel):
    secret_key: str


class OpenFileResponse(BaseModel):
    file_id: str
    display_name: str
    content: str


def create_app() -> FastAPI:
    app = FastAPI(title="Ransomware-Aware AES/Honey Demo", version="1.0")

    logs = LogBuffer(max_entries=2000)
    log = _LogAdapter(logs)
    predictor = Predictor()

    correct_key = get_env_passphrase(CRYPTO.user_passphrase_env) or (os.environ.get("DEMO_SECRET_KEY") or "").strip()
    if not correct_key:
        correct_key = "demo-secret"
        logs.push(LogLevel.WARN, "[WARNING] Key not set; using demo-secret (demo only)")

    # Ensure originals exist, wipe previous outputs, then encrypt on startup.
    originals = ensure_10_plaintext_originals(PROTECTED_DIR, logger=log)
    storage = SecureStorage(cfg=STORAGE, logger=log)
    storage.wipe_real_storage()
    storage.wipe_fake_storage()
    for p in originals:
        storage.store_real_encrypted(p, correct_key, CRYPTO.pbkdf2_iterations)

    files: list[FileItem] = [
        FileItem(file_id=f"file_{i}", display_name=f"File_{i}.txt") for i in range(1, 11)
    ]

    state: dict[str, Any] = {
        "mode": SystemMode.AES_NORMAL,
        "ransomware_detected": False,
    }

    def _evaluate_and_switch_if_needed() -> None:
        detected, reasons = predictor.assess()
        if detected and state["mode"] != SystemMode.HONEY:
            logs.push(LogLevel.WARN, "[WARN] Multiple rapid reads detected")
            logs.push(LogLevel.ALERT, "[ALERT] Ransomware behavior identified")
            state["mode"] = SystemMode.HONEY
            state["ransomware_detected"] = True
            logs.push(LogLevel.INFO, "[INFO] Switched to Honey Encryption")
            # Create honey snapshots for all 10 files at switch time.
            for f in files:
                try:
                    src = _file_path(f.file_id)
                    storage.store_honey_encrypted(src, correct_key, CRYPTO.pbkdf2_iterations)
                except Exception:
                    pass
            if reasons:
                logs.push(LogLevel.INFO, "[INFO] Reasons: " + "; ".join(reasons[:4]))

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

    app.mount(
        "/static",
        StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
        name="static",
    )

    @app.get("/api/status")
    def get_status() -> dict[str, Any]:
        return {
            "mode": state["mode"],
            "ransomware_detected": state["ransomware_detected"],
        }

    @app.get("/api/files")
    def list_files() -> list[dict[str, str]]:
        return [{"file_id": f.file_id, "display_name": f.display_name} for f in files]

    @app.post("/api/files/{file_id}/open", response_model=OpenFileResponse)
    def open_file(file_id: str, req: OpenFileRequest) -> OpenFileResponse:
        match = [f for f in files if f.file_id == file_id]
        if not match:
            raise HTTPException(status_code=404, detail="Unknown file")
        display_name = match[0].display_name

        predictor.record("ACCESS")
        logs.push(LogLevel.INFO, f"[INFO] {display_name} accessed")

        entered_key = (req.secret_key or "").strip()

        # Honey mode: show attacker-view plaintext derived from stored honey blob.
        if state["mode"] == SystemMode.HONEY:
            logical = f"{file_id}.txt"
            try:
                content = storage.honey_attacker_view(logical, attacker_passphrase=entered_key).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                # Fallback (should be rare): generate plausible fake directly.
                content = _fake_sensitive_text(display_name, entered_key)
            logs.push(LogLevel.INFO, "[INFO] Honey mode: decoy plaintext displayed")
            _evaluate_and_switch_if_needed()
            return OpenFileResponse(file_id=file_id, display_name=display_name, content=content)

        # AES mode: correct key shows real text; wrong key shows garbage.
        logical = f"{file_id}.txt"
        try:
            text = _decrypt_latest_for(logical, entered_key, storage)
            logs.push(LogLevel.INFO, "[INFO] Correct key: real plaintext displayed")
            _evaluate_and_switch_if_needed()
            return OpenFileResponse(file_id=file_id, display_name=display_name, content=text)
        except Exception:
            predictor.record("KEY_FAIL")
            logs.push(LogLevel.WARN, "[WARN] Wrong key: garbage output (AES mode)")
            try:
                target_len = _file_path(file_id).stat().st_size
            except Exception:
                target_len = 1024
            garbage = _garbage_text(display_name, entered_key, target_len)
            _evaluate_and_switch_if_needed()
            return OpenFileResponse(file_id=file_id, display_name=display_name, content=garbage)

    @app.post("/api/simulate_ransomware")
    def simulate_ransomware() -> dict[str, Any]:
        logs.push(LogLevel.WARN, "[WARN] Ransomware simulation triggered")

        # Generate a burst of access + failures to trip the predictor.
        for _ in range(120):
            predictor.record("ACCESS")
        for _ in range(60):
            predictor.record("KEY_FAIL")
        predictor.record("SIM_RANSOMWARE")

        _evaluate_and_switch_if_needed()
        return {"ok": True, "mode": state["mode"]}

    @app.post("/api/reset")
    def reset_system() -> dict[str, Any]:
        predictor.reset()
        state["mode"] = SystemMode.AES_NORMAL
        state["ransomware_detected"] = False
        originals = ensure_10_plaintext_originals(PROTECTED_DIR, logger=log)
        storage.wipe_real_storage()
        storage.wipe_fake_storage()
        for p in originals:
            storage.store_real_encrypted(p, correct_key, CRYPTO.pbkdf2_iterations)
        logs.push(LogLevel.INFO, "[INFO] System reset")
        logs.push(LogLevel.INFO, "[INFO] Status: Normal (AES)")
        return {"ok": True}

    @app.get("/api/logs")
    def get_logs(after_id: int = 0) -> dict[str, Any]:
        entries = logs.since(after_id)
        return {
            "entries": [
                {
                    "id": e.id,
                    "ts": e.ts,
                    "level": e.level,
                    "message": e.message,
                }
                for e in entries
            ]
        }

    # Startup logs
    logs.push(LogLevel.INFO, "[INFO] Browser demo server ready")
    logs.push(LogLevel.INFO, "[INFO] Status: Normal (AES)")

    return app


app = create_app()
