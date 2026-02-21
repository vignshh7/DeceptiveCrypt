from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import Iterable

from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileMovedEvent
from watchdog.observers import Observer


@dataclass(frozen=True)
class FileEvent:
    ts: float
    event_type: str  # created | modified | moved | deleted
    src_path: Path
    dest_path: Path | None = None


class _Handler(FileSystemEventHandler):
    def __init__(self, root: Path, queue: Queue[FileEvent], logger):
        super().__init__()
        self._root = root
        self._queue = queue
        self._logger = logger

    def _push(self, event_type: str, src: str, dest: str | None = None) -> None:
        try:
            src_path = Path(src)
            if not src_path.is_absolute():
                src_path = (self._root / src_path).resolve()
            dest_path = Path(dest).resolve() if dest else None

            # Ignore directories; we only care about files.
            if src_path.exists() and src_path.is_dir():
                return

            if self._root not in src_path.parents and src_path != self._root:
                return

            self._queue.put(
                FileEvent(ts=time.time(), event_type=event_type, src_path=src_path, dest_path=dest_path)
            )
            if dest_path:
                self._logger.info(f"[INFO] FS event: {event_type} {src_path.name} -> {dest_path.name}")
            else:
                self._logger.info(f"[INFO] FS event: {event_type} {src_path.name}")
        except Exception as exc:
            self._logger.error(f"[ERROR] Failed to record event: {exc}")

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._push("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._push("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._push("deleted", event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        self._push("moved", event.src_path, event.dest_path)


class FileAccessMonitor:
    def __init__(self, watch_dir: Path, event_queue: Queue[FileEvent], logger):
        self._watch_dir = watch_dir
        self._queue = event_queue
        self._logger = logger
        self._observer = Observer()
        self._handler = _Handler(watch_dir, event_queue, logger)

    @property
    def watch_dir(self) -> Path:
        return self._watch_dir

    def start(self) -> None:
        self._observer.schedule(self._handler, str(self._watch_dir), recursive=True)
        self._observer.start()
        self._logger.info("[INFO] Monitoring started...")

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)

    def drain_events(self, limit: int = 5000) -> list[FileEvent]:
        events: list[FileEvent] = []
        while len(events) < limit:
            try:
                events.append(self._queue.get_nowait())
            except Exception:
                break
        return events

    def iter_existing_files(self) -> Iterable[Path]:
        yield from (p for p in self._watch_dir.rglob("*") if p.is_file())
