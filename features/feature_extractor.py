from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path

from monitor.file_monitor import FileEvent


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _safe_read_bytes(path: Path, max_bytes: int = 256 * 1024) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""


@dataclass
class FileState:
    last_entropy: float = 0.0
    last_ext: str = ""
    last_seen_ts: float = 0.0


@dataclass(frozen=True)
class FeatureVector:
    ts: float
    window_seconds: float
    files_touched: int
    writes_per_min: float
    rename_rate: float
    extension_change_rate: float
    avg_entropy: float
    avg_entropy_delta: float
    high_entropy_write_rate: float
    sequential_pattern_score: float

    def as_list(self) -> list[float]:
        return [
            self.files_touched,
            self.writes_per_min,
            self.rename_rate,
            self.extension_change_rate,
            self.avg_entropy,
            self.avg_entropy_delta,
            self.high_entropy_write_rate,
            self.sequential_pattern_score,
        ]


class FeatureExtractor:
    def __init__(self, window_seconds: int, logger, entropy_jump_bits: float = 0.6):
        self._window_seconds = float(window_seconds)
        self._logger = logger
        self._entropy_jump_bits = entropy_jump_bits
        self._high_entropy_abs_bits = 7.2
        self._state: dict[Path, FileState] = {}

    def warmup_file(self, path: Path) -> None:
        data = _safe_read_bytes(path)
        entropy = shannon_entropy(data)
        self._state[path] = FileState(
            last_entropy=entropy,
            last_ext=path.suffix.lower(),
            last_seen_ts=time.time(),
        )

    def compute(self, events: list[FileEvent]) -> FeatureVector | None:
        if not events:
            return None

        now = time.time()
        window_start = now - self._window_seconds
        window_events = [e for e in events if e.ts >= window_start]
        if not window_events:
            return None

        modified = [e for e in window_events if e.event_type in ("modified", "created")]
        moved = [e for e in window_events if e.event_type == "moved"]

        touched_files: set[Path] = set()
        entropy_values: list[float] = []
        entropy_deltas: list[float] = []
        high_entropy_writes = 0
        ext_changes = 0

        for e in window_events:
            p = e.dest_path if e.dest_path else e.src_path
            if not p:
                continue
            touched_files.add(p)

            if e.event_type == "moved" and e.dest_path:
                old_ext = Path(e.src_path).suffix.lower()
                new_ext = Path(e.dest_path).suffix.lower()
                if old_ext != new_ext:
                    ext_changes += 1

            if e.event_type in ("modified", "created"):
                data = _safe_read_bytes(e.src_path)
                new_entropy = shannon_entropy(data)
                prev = self._state.get(e.src_path)
                prev_entropy = prev.last_entropy if prev else 0.0
                delta = new_entropy - prev_entropy

                entropy_values.append(new_entropy)
                entropy_deltas.append(delta)

                if new_entropy >= self._high_entropy_abs_bits or delta >= self._entropy_jump_bits:
                    high_entropy_writes += 1

                self._state[e.src_path] = FileState(
                    last_entropy=new_entropy,
                    last_ext=e.src_path.suffix.lower(),
                    last_seen_ts=e.ts,
                )

        window_minutes = max(self._window_seconds / 60.0, 1e-6)
        writes_per_min = len(modified) / window_minutes
        rename_rate = len(moved) / window_minutes
        extension_change_rate = ext_changes / window_minutes

        avg_entropy = sum(entropy_values) / len(entropy_values) if entropy_values else 0.0
        avg_entropy_delta = sum(entropy_deltas) / len(entropy_deltas) if entropy_deltas else 0.0
        high_entropy_write_rate = (high_entropy_writes / len(modified)) if modified else 0.0

        # Sequential pattern: many distinct files modified with entropy jumps.
        distinct_modified_files = len({e.src_path for e in modified})
        seq_score = 0.0
        if distinct_modified_files:
            seq_score = min(1.0, (high_entropy_writes / distinct_modified_files))

        return FeatureVector(
            ts=now,
            window_seconds=self._window_seconds,
            files_touched=len(touched_files),
            writes_per_min=writes_per_min,
            rename_rate=rename_rate,
            extension_change_rate=extension_change_rate,
            avg_entropy=avg_entropy,
            avg_entropy_delta=avg_entropy_delta,
            high_entropy_write_rate=high_entropy_write_rate,
            sequential_pattern_score=seq_score,
        )
