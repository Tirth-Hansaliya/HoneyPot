"""
ML Threat Scorer
-----------------
Uses Isolation Forest (unsupervised anomaly detection) to score attacker IPs
on a 0–100 scale based on behavioral features extracted from SQLite logs.

High score (≥ 60)  → High threat
Medium score       → Suspicious
Low score (< 30)   → Normal / benign

Usage:
    from ml_threat_scorer import ThreatScorer
    scorer = ThreatScorer()
    score = scorer.score_ip("1.2.3.4", db_logs)   # db_logs = list of log dicts
    result = scorer.score_all_ips(db_logs)         # dict: {ip: score}
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_DIR, "ml_models", "threat_scorer.pkl")

# Regex to extract IP from log messages
_IP_RE = re.compile(r"(?:Connection from|ip=)\s*([\d.]+)")

# Keywords that suggest destructive / high-threat intent
_DESTRUCTIVE_KEYWORDS = [
    "wget", "curl", "nc ", "netcat", "rm -rf", "chmod", "chown",
    "malware", "payload", "reverse shell", "exfiltrat",
    "union select", "drop table", "xp_cmdshell",
    "<script", "onerror=", "onload=",
    "../", "%2e%2e",
]


def _extract_ip_from_log(log: dict) -> str | None:
    """Return the source IP from a log row dict."""
    ip = log.get("source_ip")
    if ip:
        return ip
    m = _IP_RE.search(log.get("raw", "") or log.get("message", ""))
    return m.group(1) if m else None


def _build_feature_vector(ip_logs: list[dict]) -> list[float]:
    """
    Build a numeric feature vector for one IP from its log rows.

    Features:
        0 — total events
        1 — unique services targeted (http/ftp/ssh)
        2 — distinct attack-type labels seen
        3 — credential capture events (login attempts)
        4 — destructive / high-risk keyword hits
        5 — tool-detection events (scanner / tool detected)
        6 — unique commands issued (SSH shell)
        7 — file access / download attempts (FTP/SSH)
    """
    services: set[str] = set()
    attack_labels: set[str] = set()
    cred_captures = 0
    destructive_hits = 0
    tool_detections = 0
    commands: set[str] = set()
    file_accesses = 0

    for log in ip_logs:
        svc = (log.get("service") or "").upper()
        services.add(svc)

        msg = (log.get("message") or "") + (log.get("raw") or "")
        msg_lower = msg.lower()

        # Attack label detection
        for label in ("sqli", "sql injection", "xss", "pathtraversal",
                       "path traversal", "cmdinjection", "command injection",
                       "credential harvest"):
            if label in msg_lower:
                attack_labels.add(label)

        # Credential captures
        if "credential capture" in msg_lower or "username=" in msg_lower:
            cred_captures += 1

        # Destructive / high-risk keywords
        for kw in _DESTRUCTIVE_KEYWORDS:
            if kw in msg_lower:
                destructive_hits += 1
                break

        # Tool detections
        if "tool detection" in msg_lower or "scanner detection" in msg_lower:
            tool_detections += 1

        # SSH commands
        cmd_match = re.search(r"Command from [\d.]+: (.+)", msg)
        if cmd_match:
            commands.add(cmd_match.group(1).strip())

        # File accesses (FTP download, SSH cat)
        if "download attempt" in msg_lower or "file read attempt" in msg_lower or "exfiltrat" in msg_lower:
            file_accesses += 1

    return [
        float(len(ip_logs)),
        float(len(services)),
        float(len(attack_labels)),
        float(min(cred_captures, 50)),
        float(min(destructive_hits, 30)),
        float(min(tool_detections, 20)),
        float(len(commands)),
        float(min(file_accesses, 20)),
    ]


def _normalize_score(raw: float) -> int:
    """
    Isolation Forest decision_function returns roughly [-0.5, 0.5].
    Negative = anomaly (high threat), Positive = normal (low threat).
    We invert and scale to 0–100.
    """
    # Clamp to expected range
    raw = max(-0.5, min(0.5, raw))
    # Invert: -0.5 → 100, +0.5 → 0
    score = int((-raw + 0.5) * 100)
    return max(0, min(100, score))


class ThreatScorer:
    """Isolation Forest–based IP threat scorer."""

    def __init__(self) -> None:
        self._model = None
        self._ready = False
        os.makedirs(os.path.join(_DIR, "ml_models"), exist_ok=True)
        self._load_or_train()

    # ── public API ─────────────────────────────────────────────────────────────

    def score_ip(self, ip: str, all_logs: list[dict]) -> int:
        """Return a 0–100 threat score for the given IP."""
        ip_logs = [l for l in all_logs if _extract_ip_from_log(l) == ip]
        if not ip_logs:
            return 0
        return self._score_features(_build_feature_vector(ip_logs))

    def score_all_ips(self, all_logs: list[dict]) -> dict[str, int]:
        """Return {ip: score} for every unique IP found in all_logs."""
        ip_map: dict[str, list[dict]] = defaultdict(list)
        for log in all_logs:
            ip = _extract_ip_from_log(log)
            if ip:
                ip_map[ip].append(log)

        return {ip: self._score_features(_build_feature_vector(logs))
                for ip, logs in ip_map.items()}

    def score_features_raw(self, ip_logs: list[dict]) -> int:
        """Score directly from a list of log dicts for one IP."""
        if not ip_logs:
            return 0
        return self._score_features(_build_feature_vector(ip_logs))

    @staticmethod
    def threat_level(score: int) -> str:
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ── private ────────────────────────────────────────────────────────────────

    def _score_features(self, features: list[float]) -> int:
        if not self._ready:
            return self._heuristic_score(features)
        try:
            import numpy as np
            X = np.array([features])
            raw = float(self._model.decision_function(X)[0])
            return _normalize_score(raw)
        except Exception as exc:
            logger.error("ThreatScorer predict error: %s", exc)
            return self._heuristic_score(features)

    @staticmethod
    def _heuristic_score(features: list[float]) -> int:
        """Simple rule-based fallback when sklearn is unavailable."""
        total_events, services, attack_types, creds, destructive, tools, cmds, files = features
        score = 0
        score += min(int(total_events * 2), 20)
        score += int(services) * 5
        score += int(attack_types) * 10
        score += min(int(creds) * 3, 15)
        score += min(int(destructive) * 5, 20)
        score += min(int(tools) * 8, 20)
        score += min(int(cmds) * 2, 10)
        score += min(int(files) * 5, 15)
        return min(score, 100)

    def _load_or_train(self) -> None:
        if os.path.exists(MODEL_PATH):
            try:
                import joblib
                self._model = joblib.load(MODEL_PATH)
                self._ready = True
                logger.info("ThreatScorer: loaded from %s", MODEL_PATH)
                return
            except Exception as exc:
                logger.warning("ThreatScorer: could not load model (%s)", exc)

        self._train_default()

    def _train_default(self) -> None:
        """
        Train Isolation Forest on synthetic 'normal' traffic vectors
        so anomalous (attacker) traffic stands out.
        """
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            import joblib

            rng = np.random.default_rng(42)

            # Normal traffic: 1-5 events, 1 service, 0 attacks, ≤2 creds, etc.
            normal = rng.uniform(low=[1, 1, 0, 0, 0, 0, 0, 0],
                                  high=[5, 2, 0, 2, 0, 0, 0, 0],
                                  size=(300, 8))

            # Mildly suspicious: some credential attempts
            mild = rng.uniform(low=[5, 1, 0, 3, 0, 0, 1, 0],
                                high=[20, 2, 1, 10, 2, 1, 5, 1],
                                size=(100, 8))

            X = np.vstack([normal, mild])

            model = IsolationForest(
                n_estimators=200,
                contamination=0.15,
                random_state=42,
            )
            model.fit(X)

            joblib.dump(model, MODEL_PATH)
            self._model = model
            self._ready = True
            logger.info("ThreatScorer: trained and saved to %s", MODEL_PATH)
        except ImportError:
            logger.warning("ThreatScorer: scikit-learn / joblib not installed — using heuristic fallback")
        except Exception as exc:
            logger.error("ThreatScorer training failed: %s", exc)
