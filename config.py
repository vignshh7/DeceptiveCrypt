from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv_if_present() -> None:
    """Load environment variables from a local .env file (if available).

    This keeps the demo exam-friendly: keys are provided via env vars, not hardcoded.
    """

    try:
        from dotenv import find_dotenv, load_dotenv

        # Prefer project-local .env next to this file, regardless of current working directory.
        local_env = Path(__file__).resolve().parent / ".env"
        if local_env.exists():
            load_dotenv(str(local_env), override=False)
            return

        # Fallback: search upward from current working directory.
        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path, override=False)
    except Exception:
        # If python-dotenv isn't available or no .env exists, do nothing.
        return


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PROTECTED_DIR = DATA_DIR / "protected_files"
ENCRYPTED_DIR = DATA_DIR / "encrypted_files"
FAKE_DIR = DATA_DIR / "fake_files"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "system.log"


# Load .env early so other modules can read os.environ.
load_dotenv_if_present()


@dataclass(frozen=True)
class MonitorConfig:
    window_seconds: int = 15
    max_events_per_window: int = 5000
    scan_existing_on_start: bool = True


@dataclass(frozen=True)
class DetectionConfig:
    learning_windows: int = 6
    suspicious_threshold: float = 0.55
    ransomware_threshold: float = 0.80
    use_isolation_forest: bool = True


@dataclass(frozen=True)
class RuleThresholds:
    writes_per_min_suspicious: float = 20.0
    writes_per_min_ransomware: float = 60.0
    rename_rate_suspicious: float = 8.0
    rename_rate_ransomware: float = 25.0
    extension_change_rate_suspicious: float = 6.0
    extension_change_rate_ransomware: float = 18.0
    high_entropy_write_rate_suspicious: float = 0.35
    high_entropy_write_rate_ransomware: float = 0.65
    entropy_jump_bits_suspicious: float = 0.6


@dataclass(frozen=True)
class CryptoConfig:
    # Key material comes from env vars or is generated ephemerally.
    user_passphrase_env: str = "CRYPTO_SYSTEM_PASSPHRASE"
    attacker_passphrase_env: str = "CRYPTO_ATTACKER_PASSPHRASE"
    pbkdf2_iterations: int = 250_000


@dataclass(frozen=True)
class StorageConfig:
    index_file_name: str = "index.json"
    max_versions_per_file: int = 10


MONITOR = MonitorConfig()
DETECTION = DetectionConfig()
THRESHOLDS = RuleThresholds()
CRYPTO = CryptoConfig()
STORAGE = StorageConfig()


def ensure_dirs() -> None:
    for p in [DATA_DIR, PROTECTED_DIR, ENCRYPTED_DIR, FAKE_DIR, LOG_DIR]:
        p.mkdir(parents=True, exist_ok=True)


def setup_logging() -> logging.Logger:
    ensure_dirs()

    logger = logging.getLogger("crypto_ransomware_system")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_env_passphrase(env_name: str) -> str | None:
    value = os.environ.get(env_name)
    if value is None:
        return None
    value = value.strip()
    return value if value else None
