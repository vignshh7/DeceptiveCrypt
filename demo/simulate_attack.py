from __future__ import annotations

"""Demonstration driver (safe sandbox).

This script simulates:
- Normal user edits (slow writes)
- Ransomware-like behavior (rapid bulk renames + high-entropy overwrites)

Safety guard:
- Refuses to operate unless running inside crypto_ransomware_system/data/protected_files
  and sentinel file .SANDBOX_OK exists.

Typical usage (single command):
    python demo/simulate_attack.py

Interactive (choose when to trigger ransomware simulation):
    python demo/simulate_attack.py --interactive

Two-terminal workflow (monitor in one terminal, trigger actions in another):
    Terminal A: python main.py
    Terminal B: python demo/simulate_attack.py --interactive --external-monitor
"""

import os
import sys
import threading
import time
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import PROTECTED_DIR, setup_logging
from config import ENCRYPTED_DIR, FAKE_DIR, CRYPTO, get_env_passphrase
from storage.secure_storage import SecureStorage
from config import STORAGE
from main import run_system


def _require_sandbox(logger) -> None:
    sentinel = PROTECTED_DIR / ".SANDBOX_OK"
    if not sentinel.exists():
        sentinel.write_text(
            "This directory is a safe demo sandbox for crypto_ransomware_system.\n",
            encoding="utf-8",
        )

    # Extra guard: ensure PROTECTED_DIR is inside this project.
    if "crypto_ransomware_system" not in str(PROTECTED_DIR):
        raise RuntimeError("Refusing to run outside project sandbox")

    logger.info("[INFO] Demo sandbox verified")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def simulate_normal_user(logger) -> None:
    logger.info("[INFO] Simulating NORMAL user behavior")

    f1 = PROTECTED_DIR / "report.txt"
    f2 = PROTECTED_DIR / "notes.txt"

    _write_text(f1, "Project report v1\n")
    time.sleep(2)
    _write_text(f2, "Meeting notes: agenda, tasks, deadlines\n")
    time.sleep(2)

    # Gentle edits
    _write_text(f1, "Project report v2\nAdded: results and discussion\n")
    time.sleep(3)
    _write_text(f2, "Meeting notes (updated):\n- finalize slides\n- run demo\n")
    time.sleep(2)

    logger.info("[INFO] Normal phase complete")


def simulate_ransomware_like(logger) -> None:
    logger.info("[INFO] Simulating ransomware-like behavior (SAFE sandbox)")

    targets = list(PROTECTED_DIR.glob("*.txt"))
    if len(targets) < 20:
        logger.warning("[WARNING] Creating additional sandbox samples to simulate bulk attack")
        for i in range(30):
            p = PROTECTED_DIR / f"bulk_{i}.txt"
            if not p.exists():
                # Create as high-entropy content so entropy deltas stay consistently high.
                p.write_bytes(os.urandom(16 * 1024))
        targets = list(PROTECTED_DIR.glob("*.txt"))

    # Rapid bulk sequence: overwrite with high-entropy bytes, then rename, then overwrite again.
    # Important: we add tiny sleeps so the feature extractor can observe entropy on-disk *before*
    # the rename removes the original path (otherwise entropy reads may see empty bytes).
    for p in targets:
        try:
            if not p.exists():
                continue

            # 1) High-entropy overwrite on the original filename
            p.write_bytes(os.urandom(96 * 1024))
            time.sleep(0.03)

            # 2) Rename to "locked" extension
            new_path = p.with_suffix(p.suffix + ".locked")
            if new_path.exists():
                new_path.unlink()
            p.rename(new_path)
            time.sleep(0.01)

            # 3) Another overwrite on the renamed file (common ransomware behavior)
            new_path.write_bytes(os.urandom(96 * 1024))
            time.sleep(0.01)
        except Exception as exc:
            logger.warning(f"[WARNING] Could not simulate on {p.name}: {exc}")

    logger.info("[INFO] Attack simulation burst complete")


def _demonstrate_user_vs_attacker(logger, user_pass: str, attacker_pass: str) -> None:
    storage = SecureStorage(cfg=STORAGE, logger=logger)
    logical = "report.txt"

    try:
        out_user = PROTECTED_DIR / "_USER_DECRYPTED_preview.txt"
        storage.retrieve_real_decrypted(logical, out_user, user_pass, CRYPTO.pbkdf2_iterations)
        preview = out_user.read_text(encoding="utf-8", errors="ignore")[:120].replace("\n", " ")
        logger.info(f"[USER] Real decrypted preview: {preview}")
    except Exception as exc:
        logger.warning(f"[WARNING] User decrypt demo skipped: {exc}")

    try:
        out_att = PROTECTED_DIR / "_ATTACKER_DECRYPTED_preview.txt"
        # Ransomware simulation renames files (e.g., report.txt -> report.txt.locked).
        # Prefer a honey snapshot matching the original logical name; otherwise fall back.
        candidate_names = [logical, logical + ".locked"]
        last_exc: Exception | None = None
        for name in candidate_names:
            try:
                storage.retrieve_honey_for_attacker(name, out_att, attacker_passphrase=attacker_pass)
                preview = out_att.read_text(encoding="utf-8", errors="ignore")[:120].replace("\n", " ")
                logger.error(f"[ATTACKER] Fake decrypted preview ({name}): {preview}")
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
        if last_exc is not None:
            raise last_exc
    except Exception as exc:
        logger.warning(f"[WARNING] Attacker decrypt demo skipped: {exc}")


def _run_interactive(logger, user_pass: str, attacker_pass: str) -> None:
    logger.info("\n[INFO] ===== INTERACTIVE DEMO =====")
    logger.info("[INFO] 1) Simulate NORMAL user edits")
    logger.info("[INFO] 2) Simulate RANSOMWARE-like burst")
    logger.info("[INFO] 3) Show USER vs ATTACKER outputs")
    logger.info("[INFO] q) Quit")

    while True:
        choice = input("demo> ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            break
        if choice == "1":
            simulate_normal_user(logger)
            continue
        if choice == "2":
            simulate_ransomware_like(logger)
            continue
        if choice == "3":
            _demonstrate_user_vs_attacker(logger, user_pass, attacker_pass)
            continue
        logger.info("[INFO] Enter 1, 2, 3, or q")


def run() -> None:
    logger = setup_logging()
    _require_sandbox(logger)

    user_pass = get_env_passphrase(CRYPTO.user_passphrase_env) or "demo-user-passphrase"
    attacker_pass = get_env_passphrase(CRYPTO.attacker_passphrase_env) or "demo-attacker-pass"

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--interactive", action="store_true", help="Run step-by-step interactive demo")
    parser.add_argument(
        "--external-monitor",
        action="store_true",
        help="Do not start the monitoring system in this process (assume main.py is already running)",
    )
    args = parser.parse_args()

    stop_event = threading.Event()
    system_thread: threading.Thread | None = None
    if not args.external_monitor:
        system_thread = threading.Thread(
            target=run_system,
            args=(stop_event, logger, user_pass),
            daemon=True,
        )
        system_thread.start()
        time.sleep(2.0)
    else:
        logger.info("[INFO] External monitor mode: start 'python main.py' separately")

    if args.interactive:
        _run_interactive(logger, user_pass, attacker_pass)
    else:
        logger.info("\n[INFO] ===== DEMO START =====")
        if args.external_monitor:
            logger.info("[INFO] Monitoring should be running in the other terminal (main.py)")
        else:
            logger.info("[INFO] Monitoring is running (in-process)")

        simulate_normal_user(logger)
        time.sleep(5)

        simulate_ransomware_like(logger)
        time.sleep(3.0)

        _demonstrate_user_vs_attacker(logger, user_pass, attacker_pass)
        logger.info("[INFO] ===== DEMO END =====\n")

    stop_event.set()
    if system_thread is not None:
        system_thread.join(timeout=5)


if __name__ == "__main__":
    run()
