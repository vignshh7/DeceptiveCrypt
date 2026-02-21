from __future__ import annotations

import threading
import time
from queue import Queue

from config import (
    setup_logging,
    PROTECTED_DIR,
    MONITOR,
    DETECTION,
    THRESHOLDS,
    CRYPTO,
    get_env_passphrase,
)
from monitor.file_monitor import FileAccessMonitor, FileEvent
from features.feature_extractor import FeatureExtractor
from detection.anomaly_detector import AnomalyDetector
from storage.secure_storage import SecureStorage

from encryption.controller import EncryptionController
from data_bootstrap_v2 import EnhancedBootstrap, BootstrapSpecV2
from data_bootstrap_v2 import ensure_10_plaintext_originals

HAS_ENHANCED_FEATURES = True


def _ensure_sandbox_sentinel() -> None:
    # Used by demo script to ensure it only runs inside this repo's sandbox folder.
    sentinel = PROTECTED_DIR / ".SANDBOX_OK"
    if not sentinel.exists():
        sentinel.write_text(
            "This directory is a safe demo sandbox for crypto_ransomware_system.\n",
            encoding="utf-8",
        )


def _resolve_user_passphrase(logger) -> str:
    user_passphrase = get_env_passphrase(CRYPTO.user_passphrase_env)
    if user_passphrase:
        return user_passphrase

    # Exam-safe fallback: random ephemeral key material (won't persist across restarts).
    import os

    user_passphrase = os.urandom(24).hex()
    logger.warning(
        f"[WARNING] {CRYPTO.user_passphrase_env} not set; using ephemeral key (demo only)"
    )
    return user_passphrase


def run_system(stop_event: threading.Event, logger, user_passphrase: str) -> None:
    _ensure_sandbox_sentinel()

    # Enhanced startup with FA-DTE features if available
    if HAS_ENHANCED_FEATURES:
        logger.info("[BOOTSTRAP] Using enhanced startup pipeline with FA-DTE...")
        bootstrap = EnhancedBootstrap(logger)
        spec = BootstrapSpecV2(
            count=10,
            prefix="file_",
            suffix=".txt",
            validate_authenticity=True,
            rotate_seeds=True
        )
        
        try:
            bootstrap_results = bootstrap.full_bootstrap_pipeline(
                PROTECTED_DIR,
                __import__("config").ENCRYPTED_DIR,
                __import__("config").FAKE_DIR,
                spec
            )
            logger.info(f"[BOOTSTRAP] ✓ Enhanced pipeline complete - Features active: {bootstrap_results.get('enhanced_features_active', False)}")
            originals = [PROTECTED_DIR / name for name in spec.filenames()]
        except Exception as e:
            logger.warning(f"[BOOTSTRAP] Enhanced pipeline failed, falling back: {e}")
            # Fallback to legacy bootstrap
            originals = ensure_10_plaintext_originals(PROTECTED_DIR, logger=logger)
    else:
        logger.info("[BOOTSTRAP] Using legacy startup pipeline...")
        originals = ensure_10_plaintext_originals(PROTECTED_DIR, logger=logger)

    event_queue: Queue[FileEvent] = Queue()
    monitor = FileAccessMonitor(PROTECTED_DIR, event_queue, logger)
    extractor = FeatureExtractor(
        window_seconds=MONITOR.window_seconds,
        logger=logger,
        entropy_jump_bits=THRESHOLDS.entropy_jump_bits_suspicious,
    )
    detector = AnomalyDetector(DETECTION, THRESHOLDS, logger)
    storage = SecureStorage(cfg=__import__("config").STORAGE, logger=logger)
    
    # Enhanced controller with state machine if available
    if HAS_ENHANCED_FEATURES:
        controller = EncryptionController(storage=storage, logger=logger)
        logger.info(f"[CONTROLLER] Enhanced state controller initialized - State: {controller.current_state}")
    else:
        controller = EncryptionController(storage=storage, logger=logger)

    # Storage cleanup and initial encryption
    storage.wipe_real_storage()
    storage.wipe_fake_storage()
    for p in originals:
        if p.exists():
            storage.store_real_encrypted(p, user_passphrase, CRYPTO.pbkdf2_iterations)
    logger.info(f"[INFO] Startup encryption complete: {len([p for p in originals if p.exists()])} files protected")

    if MONITOR.scan_existing_on_start:
        for p in monitor.iter_existing_files():
            extractor.warmup_file(p)

    monitor.start()
    logger.info("[INFO] Normal file access detected")
    logger.info("[INFO] AES encryption enabled")
    
    # Log enhanced features status
    if HAS_ENHANCED_FEATURES:
        try:
            from encryption.honey_crypto import HAS_ENHANCED_HONEY
            logger.info(f"[FEATURES] Enhanced FA-DTE honey encryption: {'✓' if HAS_ENHANCED_HONEY else '✗'}")
        except ImportError:
            logger.info("[FEATURES] Enhanced FA-DTE honey encryption: ✗")

    try:
        last_window = time.time()
        while not stop_event.is_set():
            time.sleep(0.75)
            events = monitor.drain_events(limit=MONITOR.max_events_per_window)
            if events:
                fv = extractor.compute(events)
                if fv:
                    result = detector.update_and_detect(fv)
                    controller.on_detection(result)

                for e in events:
                    if e.event_type in ("modified", "created"):
                        controller.protect_file_snapshot(
                            e.src_path, user_passphrase, CRYPTO.pbkdf2_iterations
                        )

            if time.time() - last_window > MONITOR.window_seconds:
                last_window = time.time()
    finally:
        monitor.stop()


def run() -> None:
    logger = setup_logging()
    user_passphrase = _resolve_user_passphrase(logger)
    stop_event = threading.Event()
    try:
        run_system(stop_event, logger, user_passphrase)
    except KeyboardInterrupt:
        logger.info("[INFO] Shutting down...")
        stop_event.set()


if __name__ == "__main__":
    run()
