from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from config import ENCRYPTED_DIR, FAKE_DIR, StorageConfig, CRYPTO
from encryption import aes_crypto
from encryption.honey_crypto import honey_encrypt_real_text, honey_decrypt_or_fake


@dataclass(frozen=True)
class StoredRef:
    logical_name: str
    version_path: Path


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class SecureStorage:
    def __init__(self, cfg: StorageConfig, logger):
        self._cfg = cfg
        self._logger = logger
        self._real_index_path = ENCRYPTED_DIR / cfg.index_file_name
        self._fake_index_path = FAKE_DIR / cfg.index_file_name
        ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
        FAKE_DIR.mkdir(parents=True, exist_ok=True)

    def wipe_real_storage(self) -> None:
        for p in ENCRYPTED_DIR.glob("*"):
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass

    def wipe_fake_storage(self) -> None:
        for p in FAKE_DIR.glob("*"):
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass

    def latest_real_version_path(self, logical_name: str) -> Path | None:
        index = self._load_index(self._real_index_path)
        versions = index.get(logical_name)
        if not versions:
            return None
        p = ENCRYPTED_DIR / versions[0]
        return p if p.exists() else None

    def latest_honey_version_path(self, logical_name: str) -> Path | None:
        index = self._load_index(self._fake_index_path)
        versions = index.get(logical_name)
        if not versions:
            return None
        p = FAKE_DIR / versions[0]
        return p if p.exists() else None

    def honey_attacker_view(self, logical_name: str, attacker_passphrase: str) -> bytes:
        """Return attacker-view plaintext for latest honey blob.

        Uses enhanced honey_decrypt_or_fake_v2 if available, which provides
        field-aware, semantically consistent decoys.
        """
        index = self._load_index(self._fake_index_path)
        versions = index.get(logical_name)
        if not versions:
            raise FileNotFoundError(f"No honey encrypted version found for {logical_name}")
        version_path = FAKE_DIR / versions[0]
        blob = version_path.read_bytes()
        
        return honey_decrypt_or_fake(blob, attacker_passphrase, filename=logical_name)

    def _load_index(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_index(self, path: Path, index: dict) -> None:
        _atomic_write(path, json.dumps(index, indent=2).encode("utf-8"))

    def store_real_encrypted(self, src_file: Path, passphrase: str, iterations: int) -> StoredRef:
        ts = int(time.time() * 1000)
        logical = src_file.name
        version_name = f"{logical}.{ts}.enc"
        version_path = ENCRYPTED_DIR / version_name

        blob = aes_crypto.encrypt_bytes(src_file.read_bytes(), passphrase, iterations)
        _atomic_write(version_path, blob)

        index = self._load_index(self._real_index_path)
        versions = index.get(logical, [])
        versions.insert(0, version_name)
        index[logical] = versions[: self._cfg.max_versions_per_file]
        self._save_index(self._real_index_path, index)

        self._logger.info(f"[INFO] Stored REAL encrypted version: {version_name}")
        return StoredRef(logical_name=logical, version_path=version_path)

    def retrieve_real_decrypted(self, logical_name: str, out_path: Path, passphrase: str, iterations: int) -> Path:
        index = self._load_index(self._real_index_path)
        versions = index.get(logical_name)
        if not versions:
            raise FileNotFoundError(f"No real encrypted version found for {logical_name}")
        version_path = ENCRYPTED_DIR / versions[0]
        plaintext = aes_crypto.decrypt_bytes(version_path.read_bytes(), passphrase, iterations)
        _atomic_write(out_path, plaintext)
        return out_path

    def store_honey_encrypted(self, src_file: Path, passphrase: str, iterations: int) -> StoredRef:
        ts = int(time.time() * 1000)
        logical = src_file.name
        version_name = f"{logical}.{ts}.hny"
        version_path = FAKE_DIR / version_name

        plaintext = src_file.read_bytes()
        
        blob = honey_encrypt_real_text(
            plaintext,
            correct_passphrase=passphrase,
            iterations=iterations,
            filename=logical,
        )
        self._logger.info(f"[INFO] Stored HONEY encrypted version: {version_name}")
        
        _atomic_write(version_path, blob)

        index = self._load_index(self._fake_index_path)
        versions = index.get(logical, [])
        versions.insert(0, version_name)
        index[logical] = versions[: self._cfg.max_versions_per_file]
        self._save_index(self._fake_index_path, index)

        return StoredRef(logical_name=logical, version_path=version_path)

    def retrieve_honey_for_attacker(self, logical_name: str, out_path: Path, attacker_passphrase: str) -> Path:
        index = self._load_index(self._fake_index_path)
        versions = index.get(logical_name)
        if not versions:
            raise FileNotFoundError(f"No honey encrypted version found for {logical_name}")
        version_path = FAKE_DIR / versions[0]
        blob = version_path.read_bytes()
        
        plaintext = honey_decrypt_or_fake(blob, attacker_passphrase, filename=logical_name)
            
        _atomic_write(out_path, plaintext)
        return out_path
