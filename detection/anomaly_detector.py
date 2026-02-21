from __future__ import annotations

from dataclasses import dataclass

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover
    IsolationForest = None

from config import DetectionConfig, RuleThresholds
from features.feature_extractor import FeatureVector


class DetectionLabel:
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    RANSOMWARE_DETECTED = "RANSOMWARE_DETECTED"


@dataclass(frozen=True)
class DetectionResult:
    label: str
    score: float
    reasons: list[str]


class AnomalyDetector:
    def __init__(
        self,
        config: DetectionConfig,
        thresholds: RuleThresholds,
        logger,
    ):
        self._cfg = config
        self._thr = thresholds
        self._logger = logger
        self._windows_seen = 0
        self._baseline: list[list[float]] = []
        self._model = None

        if self._cfg.use_isolation_forest and IsolationForest is not None:
            self._model = IsolationForest(
                n_estimators=200,
                contamination=0.08,
                random_state=42,
            )

    def _rule_score(self, fv: FeatureVector) -> tuple[float, list[str]]:
        reasons: list[str] = []
        score = 0.0

        def bump(weight: float, reason: str) -> None:
            nonlocal score
            score = min(1.0, score + weight)
            reasons.append(reason)

        if fv.writes_per_min >= self._thr.writes_per_min_ransomware:
            bump(0.35, f"High write rate: {fv.writes_per_min:.1f}/min")
        elif fv.writes_per_min >= self._thr.writes_per_min_suspicious:
            bump(0.20, f"Elevated write rate: {fv.writes_per_min:.1f}/min")

        if fv.rename_rate >= self._thr.rename_rate_ransomware:
            bump(0.20, f"High rename rate: {fv.rename_rate:.1f}/min")
        elif fv.rename_rate >= self._thr.rename_rate_suspicious:
            bump(0.10, f"Elevated rename rate: {fv.rename_rate:.1f}/min")

        if fv.extension_change_rate >= self._thr.extension_change_rate_ransomware:
            bump(0.20, f"High extension change rate: {fv.extension_change_rate:.1f}/min")
        elif fv.extension_change_rate >= self._thr.extension_change_rate_suspicious:
            bump(0.10, f"Elevated extension change rate: {fv.extension_change_rate:.1f}/min")

        if fv.high_entropy_write_rate >= self._thr.high_entropy_write_rate_ransomware:
            bump(0.25, f"Many high-entropy writes: {fv.high_entropy_write_rate:.2f}")
        elif fv.high_entropy_write_rate >= self._thr.high_entropy_write_rate_suspicious:
            bump(0.15, f"Some high-entropy writes: {fv.high_entropy_write_rate:.2f}")

        if fv.sequential_pattern_score >= 0.7:
            bump(0.20, f"Sequential pattern: {fv.sequential_pattern_score:.2f}")
        elif fv.sequential_pattern_score >= 0.45:
            bump(0.10, f"Possible sequential pattern: {fv.sequential_pattern_score:.2f}")

        return score, reasons

    def _ml_score(self, fv: FeatureVector) -> float | None:
        if self._model is None:
            return None
        if self._windows_seen < self._cfg.learning_windows:
            return None

        x = np.array([fv.as_list()], dtype=float)
        # IsolationForest: higher is more normal; we invert to anomaly score in [0,1]
        raw = float(self._model.decision_function(x)[0])
        # Map raw to [0,1] with a smooth-ish transform
        anomaly = 1.0 / (1.0 + np.exp(5.0 * raw))
        return float(np.clip(anomaly, 0.0, 1.0))

    def update_and_detect(self, fv: FeatureVector) -> DetectionResult:
        self._windows_seen += 1

        # Baseline learning
        self._baseline.append(fv.as_list())
        if self._model is not None and self._windows_seen == self._cfg.learning_windows:
            x = np.array(self._baseline, dtype=float)
            self._model.fit(x)
            self._logger.info("[INFO] Baseline learning complete (IsolationForest fitted)")

        rule_score, reasons = self._rule_score(fv)
        ml_score = self._ml_score(fv)
        combined = rule_score

        if ml_score is not None:
            combined = float(np.clip(0.65 * rule_score + 0.35 * ml_score, 0.0, 1.0))
            if ml_score >= 0.65:
                reasons.append(f"ML anomaly score: {ml_score:.2f}")

        if combined >= self._cfg.ransomware_threshold:
            return DetectionResult(DetectionLabel.RANSOMWARE_DETECTED, combined, reasons)
        if combined >= self._cfg.suspicious_threshold:
            return DetectionResult(DetectionLabel.SUSPICIOUS, combined, reasons)
        return DetectionResult(DetectionLabel.NORMAL, combined, reasons)
