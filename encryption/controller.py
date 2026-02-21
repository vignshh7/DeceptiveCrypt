from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from config import CRYPTO, STORAGE
from detection.anomaly_detector import DetectionResult, DetectionLabel
from storage.secure_storage import SecureStorage


class CryptoMode:
    AES_REAL = "AES_REAL"
    HONEY = "HONEY"


@dataclass
class ControllerState:
    mode: str = CryptoMode.AES_REAL
    last_label: str = DetectionLabel.NORMAL


class EncryptionController:
    def __init__(self, storage: SecureStorage, logger):
        self._storage = storage
        self._logger = logger
        self._state = ControllerState()
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        with self._lock:
            return self._state.mode

    def on_detection(self, result: DetectionResult) -> None:
        with self._lock:
            prev = self._state.last_label
            self._state.last_label = result.label

            # Once we enter HONEY mode, we do not revert automatically during the same run.
            if self._state.mode == CryptoMode.HONEY:
                if result.label == DetectionLabel.SUSPICIOUS:
                    self._logger.warning("[WARNING] Suspicious behavior detected")
                    if result.reasons:
                        self._logger.warning("[WARNING] Reasons: " + "; ".join(result.reasons[:4]))
                elif result.label == DetectionLabel.RANSOMWARE_DETECTED:
                    if prev != DetectionLabel.RANSOMWARE_DETECTED:
                        self._logger.error("[ALERT] RANSOMWARE DETECTED")
                        if result.reasons:
                            self._logger.error("[ALERT] Reasons: " + "; ".join(result.reasons[:5]))
                return

            if result.label == DetectionLabel.NORMAL:
                if prev != DetectionLabel.NORMAL:
                    self._logger.info("[INFO] Normal file access detected")
                if self._state.mode != CryptoMode.AES_REAL:
                    self._state.mode = CryptoMode.AES_REAL
                    self._logger.info("[INFO] AES encryption enabled")
                return

            if result.label == DetectionLabel.SUSPICIOUS:
                self._logger.warning("[WARNING] Suspicious behavior detected")
                if result.reasons:
                    self._logger.warning("[WARNING] Reasons: " + "; ".join(result.reasons[:4]))
                return

            if result.label == DetectionLabel.RANSOMWARE_DETECTED:
                self._logger.error("[ALERT] RANSOMWARE DETECTED")
                if result.reasons:
                    self._logger.error("[ALERT] Reasons: " + "; ".join(result.reasons[:5]))
                if self._state.mode != CryptoMode.HONEY:
                    self._state.mode = CryptoMode.HONEY
                    self._logger.error("[SECURITY] Switching to Honey Encryption")
                return

    def protect_file_snapshot(self, src_file: Path, user_passphrase: str, iterations: int) -> None:
        """Store a secure snapshot of the current file.

        NORMAL mode: store REAL encrypted snapshot.
        HONEY mode: freeze real data (no new real snapshots) and store only honey snapshots.
        """
        if not src_file.exists() or not src_file.is_file():
            return

        mode = self.mode
        if mode == CryptoMode.AES_REAL:
            self._storage.store_real_encrypted(src_file, user_passphrase, iterations)
            return

        if mode == CryptoMode.HONEY:
            self._storage.store_honey_encrypted(src_file, user_passphrase, iterations)
            self._logger.error("[ATTACKER] Fake encrypted data delivered")
            self._logger.info("[USER] Real data remains secure")
