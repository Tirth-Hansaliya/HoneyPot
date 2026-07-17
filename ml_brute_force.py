"""
ML Brute Force Detector
------------------------
Detects brute-force / credential-stuffing attacks on SSH and FTP honeypots
using a sliding-window feature approach + Logistic Regression classifier.

The detector keeps an in-memory per-IP event window and raises an alert
when the ML model predicts brute-force behavior.

Usage:
    from ml_brute_force import BruteForceDetector
    detector = BruteForceDetector()
    result = detector.record_attempt(ip, username, password)
    # result: {"is_brute_force": True/False, "confidence": 0.92,
    #          "attempt_count": 15, "unique_usernames": 5}
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_DIR, "ml_models", "brute_force_classifier.pkl")

# Window configuration
WINDOW_SECONDS = 60       # sliding window duration
MIN_ATTEMPTS = 3          # minimum attempts before ML kicks in
BRUTE_FORCE_THRESHOLD = 3 # attempts in window to flag (heuristic fallback)


@dataclass
class _AttemptRecord:
    timestamp: float
    username: str
    password: str


@dataclass
class _IPState:
    window: deque = field(default_factory=deque)  # deque of _AttemptRecord
    alerted: bool = False
    last_alert_time: float = 0.0


def _build_features(state: _IPState, now: float) -> list[float]:
    """
    Build numeric features from the IP's attempt window.

    Features:
        0 — total attempts in window
        1 — unique usernames tried
        2 — unique passwords tried
        3 — attempts per second (rate)
        4 — username diversity ratio (unique_users / total_attempts)
        5 — password diversity ratio
        6 — contains common admin usernames (admin/root/administrator)
        7 — contains common weak passwords (123456/password/admin)
    """
    records = list(state.window)
    total = len(records)
    if total == 0:
        return [0.0] * 8

    usernames = [r.username.lower() for r in records]
    passwords = [r.password.lower() for r in records]

    unique_users = len(set(usernames))
    unique_pass = len(set(passwords))

    time_span = now - records[0].timestamp if len(records) > 1 else 1.0
    rate = total / max(time_span, 0.1)

    admin_names = {"admin", "root", "administrator", "test", "user", "guest", "ubuntu"}
    weak_passwords = {"123456", "password", "admin", "12345", "1234", "pass",
                      "qwerty", "abc123", "letmein", "welcome", "monkey", "dragon"}

    has_admin = float(any(u in admin_names for u in usernames))
    has_weak_pass = float(any(p in weak_passwords for p in passwords))

    return [
        float(total),
        float(unique_users),
        float(unique_pass),
        float(rate),
        unique_users / total,
        unique_pass / total,
        has_admin,
        has_weak_pass,
    ]


class BruteForceDetector:
    """Sliding-window brute-force detector backed by Logistic Regression."""

    def __init__(self) -> None:
        self._model = None
        self._scaler = None
        self._ready = False
        self._lock = threading.Lock()
        self._ip_states: dict[str, _IPState] = defaultdict(_IPState)
        os.makedirs(os.path.join(_DIR, "ml_models"), exist_ok=True)
        self._load_or_train()

    # ── public API ─────────────────────────────────────────────────────────────

    def record_attempt(self, ip: str, username: str, password: str) -> dict:
        """
        Record a login attempt and return detection result.

        Returns dict with:
            is_brute_force  — bool
            confidence      — float 0.0–1.0
            attempt_count   — int (total in current window)
            unique_usernames — int
            alert_message   — str or None
        """
        now = time.time()

        with self._lock:
            state = self._ip_states[ip]

            # Add new record
            state.window.append(_AttemptRecord(now, username, password))

            # Evict old records outside the window
            cutoff = now - WINDOW_SECONDS
            while state.window and state.window[0].timestamp < cutoff:
                state.window.popleft()

            total = len(state.window)
            unique_users = len({r.username for r in state.window})

            if total < MIN_ATTEMPTS:
                return {
                    "is_brute_force": False,
                    "confidence": 0.0,
                    "attempt_count": total,
                    "unique_usernames": unique_users,
                    "alert_message": None,
                }

            features = _build_features(state, now)
            is_bf, confidence = self._predict(features)

            alert_message = None
            if is_bf and (not state.alerted or now - state.last_alert_time > 30):
                alert_message = (
                    f"[ML BruteForce] IP={ip} attempts={total} "
                    f"unique_users={unique_users} confidence={confidence:.2f}"
                )
                state.alerted = True
                state.last_alert_time = now

            return {
                "is_brute_force": is_bf,
                "confidence": confidence,
                "attempt_count": total,
                "unique_usernames": unique_users,
                "alert_message": alert_message,
            }

    def reset_ip(self, ip: str) -> None:
        with self._lock:
            self._ip_states.pop(ip, None)

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ── private ────────────────────────────────────────────────────────────────

    def _predict(self, features: list[float]) -> tuple[bool, float]:
        if self._ready and self._model is not None:
            try:
                import numpy as np
                X = np.array([features])
                if self._scaler:
                    X = self._scaler.transform(X)
                raw_prob = float(self._model.predict_proba(X)[0][1])
                prob = self._calibrate_confidence(raw_prob, features)
                return prob >= 0.55, prob
            except Exception as exc:
                logger.error("BruteForceDetector predict error: %s", exc)

        # Heuristic fallback
        total = features[0]
        rate = features[3]
        is_bf = total >= BRUTE_FORCE_THRESHOLD and rate >= 0.5
        conf = min(total / 10.0, 1.0)
        return is_bf, conf

    @staticmethod
    def _calibrate_confidence(raw_prob: float, features: list[float]) -> float:
        """
        Soften logistic probabilities and reduce confidence for sparse windows.

        This keeps confidence percentages more realistic for early attempts.
        """
        p = max(1e-6, min(1 - 1e-6, float(raw_prob)))

        # Temperature scaling in logit space to avoid overconfident probabilities.
        temperature = 1.7
        logit = math.log(p / (1.0 - p))
        p_temp = 1.0 / (1.0 + math.exp(-(logit / temperature)))

        attempts = float(features[0]) if features else 0.0
        rate = float(features[3]) if len(features) > 3 else 0.0

        # Confidence should grow as we observe more repeated attempts.
        attempts_factor = max(0.45, min(1.0, attempts / 10.0))
        rate_factor = max(0.75, min(1.0, rate / 1.5))

        calibrated = p_temp * attempts_factor * rate_factor
        return max(0.0, min(1.0, calibrated))

    def _load_or_train(self) -> None:
        if os.path.exists(MODEL_PATH):
            try:
                import joblib
                bundle = joblib.load(MODEL_PATH)
                self._model = bundle["model"]
                self._scaler = bundle.get("scaler")
                self._ready = True
                logger.info("BruteForceDetector: loaded from %s", MODEL_PATH)
                return
            except Exception as exc:
                logger.warning("BruteForceDetector: could not load (%s)", exc)

        self._train_default()

    def _train_default(self) -> None:
        try:
            import numpy as np
            from sklearn.linear_model import LogisticRegression
            from sklearn.preprocessing import StandardScaler
            import joblib

            rng = np.random.default_rng(42)

            # --- Normal login samples ---
            # Few attempts, low rate, 1 username, varied passwords
            normal_total = rng.integers(1, 4, size=200).astype(float)
            normal = np.column_stack([
                normal_total,
                np.ones(200),                          # 1 unique username
                normal_total,                          # password = attempt count
                rng.uniform(0.01, 0.3, 200),           # slow rate
                np.ones(200),                          # diversity = 1.0
                np.ones(200),
                rng.integers(0, 2, 200).astype(float),
                rng.integers(0, 2, 200).astype(float),
            ])
            normal_labels = np.zeros(200)

            # --- Brute-force samples ---
            bf_total = rng.integers(5, 30, size=200).astype(float)
            bf_unique_users = rng.integers(1, 8, size=200).astype(float)
            bf_unique_pass = rng.integers(4, 25, size=200).astype(float)
            brute = np.column_stack([
                bf_total,
                bf_unique_users,
                bf_unique_pass,
                rng.uniform(0.5, 5.0, 200),            # fast rate
                bf_unique_users / bf_total,
                bf_unique_pass / bf_total,
                rng.integers(0, 2, 200).astype(float),
                rng.integers(0, 2, 200).astype(float),
            ])
            brute_labels = np.ones(200)

            X = np.vstack([normal, brute])
            y = np.concatenate([normal_labels, brute_labels])

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clf = LogisticRegression(C=1.0, max_iter=500, random_state=42)
            clf.fit(X_scaled, y)

            joblib.dump({"model": clf, "scaler": scaler}, MODEL_PATH)
            self._model = clf
            self._scaler = scaler
            self._ready = True
            logger.info("BruteForceDetector: trained and saved to %s", MODEL_PATH)
        except ImportError:
            logger.warning("BruteForceDetector: scikit-learn not installed — using heuristic fallback")
        except Exception as exc:
            logger.error("BruteForceDetector training failed: %s", exc)
