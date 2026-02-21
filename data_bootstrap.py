from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BootstrapSpec:
    count: int = 10
    prefix: str = "file_"
    suffix: str = ".txt"

    def filenames(self) -> list[str]:
        return [f"{self.prefix}{i}{self.suffix}" for i in range(1, self.count + 1)]


def _is_safe_data_path(path: Path) -> bool:
    # Safety guard to avoid accidental deletions outside this demo repo.
    s = str(path.resolve()).lower().replace("\\", "/")
    return "/crypto_ransomware_system/data/" in s


def _wipe_dir_contents(dir_path: Path, keep_names: set[str], logger) -> None:
    if not dir_path.exists():
        return
    if not _is_safe_data_path(dir_path):
        raise RuntimeError(f"Refusing to wipe non-demo directory: {dir_path}")

    for p in dir_path.glob("*"):
        if not p.is_file():
            continue
        if p.name in keep_names:
            continue
        try:
            p.unlink()
        except Exception as exc:
            logger.warning(f"[WARNING] Could not remove {p.name}: {exc}")


def ensure_10_plaintext_originals(protected_dir: Path, logger, spec: BootstrapSpec | None = None) -> list[Path]:
    """Ensure exactly 10 editable plaintext files exist in protected_dir.

    - Preserves existing user files (never overwrites user content)
    - Only creates template files if they don't exist
    - Keeps `.SANDBOX_OK` if present.
    """

    spec = spec or BootstrapSpec()
    protected_dir.mkdir(parents=True, exist_ok=True)

    # Don't wipe directory contents - preserve user files
    # Only remove files that aren't in our expected set
    expected_files = set(spec.filenames()) | {".SANDBOX_OK"}
    if protected_dir.exists():
        for p in protected_dir.glob("*"):
            if p.is_file() and p.name not in expected_files:
                try:
                    p.unlink()
                    logger.info(f"[INFO] Removed unexpected file: {p.name}")
                except Exception as exc:
                    logger.warning(f"[WARNING] Could not remove {p.name}: {exc}")

    created_or_existing: list[Path] = []
    for name in spec.filenames():
        p = protected_dir / name
        if not p.exists():
            template = (
                f"SENSITIVE DOCUMENT (editable demo file)\n"
                f"Name: {name}\n\n"
                "Edit this file content, then restart the system to re-encrypt it.\n"
            )
            p.write_text(template, encoding="utf-8")
            logger.info(f"[INFO] Created template file: {name}")
        else:
            logger.info(f"[INFO] Preserving existing file: {name}")
        created_or_existing.append(p)

    return created_or_existing


def wipe_encryption_outputs(encrypted_dir: Path, fake_dir: Path, logger) -> None:
    """Remove existing encrypted/honey outputs each run.

    This ensures a restart always re-encrypts the current plaintext originals.
    """

    encrypted_dir.mkdir(parents=True, exist_ok=True)
    fake_dir.mkdir(parents=True, exist_ok=True)
    _wipe_dir_contents(encrypted_dir, keep_names=set(), logger=logger)
    _wipe_dir_contents(fake_dir, keep_names=set(), logger=logger)
