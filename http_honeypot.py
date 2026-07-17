import os
import re
import socket
import threading
from html import unescape
from datetime import datetime
from urllib.parse import parse_qs, unquote_plus

# ── ML integration ─────────────────────────────────────────────────────────────
try:
    from ml_attack_classifier import AttackClassifier as _AttackClassifier
    _ml_attack_clf = _AttackClassifier()
except Exception:
    _ml_attack_clf = None

try:
  from ml_brute_force import BruteForceDetector as _BruteForceDetector
  _ml_bf_detector = _BruteForceDetector()
except Exception:
  _ml_bf_detector = None
# ───────────────────────────────────────────────────────────────────────────────


class HTTPHoneypot:
    def __init__(self, port=8080, log_callback=None, html_file=None, banner=None):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        self.html_file = html_file
        self.banner = banner or {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x_powered_by": "PHP/7.4.3",
        }
        self.html_content = self.load_html()

        self.sql_patterns = [
            re.compile(r"\bunion\s+select\b", re.IGNORECASE),
            re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
            re.compile(r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|create\s+table|alter\s+table|truncate\s+table)\b", re.IGNORECASE),
            re.compile(r"\b(waitfor\s+delay|sleep\s*\(|benchmark\s*\()", re.IGNORECASE),
            re.compile(r"\b(mid|substring|ascii|version)\s*\(", re.IGNORECASE),
            re.compile(r"\bin\s*\(\s*select\b", re.IGNORECASE),
            re.compile(r"\binto\s+@+\w+(?:\s*,\s*@+\w+)*", re.IGNORECASE),
            re.compile(r"\bxp_cmdshell\b|\bexec(?:ute)?\b", re.IGNORECASE),
            re.compile(r"\b(order\s+by|group\s+by)\b\s+\d+(?:\s*,\s*\d+)*", re.IGNORECASE),
            re.compile(r"\bhaving\b\s+[\w'\"().@]+\s*=\s*[\w'\"().@]+", re.IGNORECASE),
            re.compile(r"\b(or|and)\b\s+[\w'\"().@]+\s*=\s*[\w'\"().@]+", re.IGNORECASE),
        ]
        self.sql_comment_pattern = re.compile(r"(--|#|/\*|\*/)")
        self.xss_patterns = [
            re.compile(r"<\s*/?\s*script\b", re.IGNORECASE),
            re.compile(r"<\s*(iframe|svg|img|meta|object|embed|isindex|form|input)\b", re.IGNORECASE),
            re.compile(r"on[a-z]+\s*=", re.IGNORECASE),
            re.compile(r"xlink:href\s*=", re.IGNORECASE),
            re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
            re.compile(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.IGNORECASE),
            re.compile(r"vbscript\s*:", re.IGNORECASE),
            re.compile(r"<\s*/\s*script\s*>\s*<\s*script\b", re.IGNORECASE),
        ]
        self.xss_function_patterns = [
            re.compile(r"\b(alert|confirm|prompt)\s*\(", re.IGNORECASE),
            re.compile(r"\bwindow\.open\s*\(", re.IGNORECASE),
        ]
        self.path_traversal_patterns = [
            re.compile(r"(?:^|[=:/\s])\.\.(?:/|\\)", re.IGNORECASE),
            re.compile(r"%2e%2e(?:%2f|%5c|/|\\)", re.IGNORECASE),
            re.compile(r"%252e%252e(?:%252f|%255c)", re.IGNORECASE),
            re.compile(r"(?:/|\\)(?:etc/passwd|proc/self/environ|windows/win\.ini|boot\.ini)", re.IGNORECASE),
        ]
        self.scanners = {
            "nmaplowercheck": "Nmap",
            "nmapuppercheck": "Nmap",
            "/nmap/": "Nmap",
            "nikto": "Nikto",
            "sqlmap": "SQLMap",
            "nmap": "Nmap",
            "masscan": "Masscan",
            "burpsuite": "Burp Suite",
            "metasploit": "Metasploit",
            "acunetix": "Acunetix",
            "wpscan": "WPScan",
            "gobuster": "Gobuster",
            "dirbuster": "DirBuster",
            "curl": "cURL",
            "python-requests": "Python Requests",
        }

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[HTTP] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)

    def load_html(self):
        if self.html_file and os.path.exists(self.html_file):
            try:
                with open(self.html_file, "r", encoding="utf-8") as handle:
                    return handle.read()
            except Exception as exc:
                self.log(f"Failed to load custom HTML file ({self.html_file}): {exc}")

        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #050a0e;
    --panel: #080f14;
    --border: #0ff3;
    --accent: #00f5ff;
    --accent2: #ff003c;
    --accent3: #39ff14;
    --text: #c8f0f5;
    --muted: #4a7a85;
    --glow: 0 0 20px #00f5ff55, 0 0 40px #00f5ff22;
    --glow-red: 0 0 20px #ff003c55;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    min-height: 100vh;
    background: var(--bg);
    font-family: 'Share Tech Mono', monospace;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    position: relative;
  }

  /* Animated grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(#00f5ff08 1px, transparent 1px),
      linear-gradient(90deg, #00f5ff08 1px, transparent 1px);
    background-size: 40px 40px;
    animation: gridShift 20s linear infinite;
    pointer-events: none;
  }

  @keyframes gridShift {
    0% { transform: translateY(0); }
    100% { transform: translateY(40px); }
  }

  /* Scan line overlay */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      #00000033 2px,
      #00000033 4px
    );
    pointer-events: none;
    z-index: 100;
  }

  /* Corner decorations */
  .corner {
    position: fixed;
    width: 80px;
    height: 80px;
    pointer-events: none;
  }
  .corner--tl { top: 20px; left: 20px; border-top: 2px solid var(--accent); border-left: 2px solid var(--accent); }
  .corner--tr { top: 20px; right: 20px; border-top: 2px solid var(--accent); border-right: 2px solid var(--accent); }
  .corner--bl { bottom: 20px; left: 20px; border-bottom: 2px solid var(--accent); border-left: 2px solid var(--accent); }
  .corner--br { bottom: 20px; right: 20px; border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent); }

  /* Animated side bars */
  .sidebar {
    position: fixed;
    top: 0; bottom: 0;
    width: 2px;
    overflow: hidden;
    pointer-events: none;
  }
  .sidebar--left { left: 60px; }
  .sidebar--right { right: 60px; }
  .sidebar::before {
    content: '';
    position: absolute;
    top: -100%;
    left: 0;
    width: 100%;
    height: 40%;
    background: linear-gradient(transparent, var(--accent), transparent);
    animation: scanDown 4s linear infinite;
  }
  .sidebar--right::before { animation-delay: -2s; }

  @keyframes scanDown {
    0% { top: -40%; }
    100% { top: 140%; }
  }

  /* Status bar top */
  .status-bar {
    position: fixed;
    top: 0; left: 0; right: 0;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 100px;
    background: #00f5ff08;
    border-bottom: 1px solid var(--border);
    font-size: 10px;
    color: var(--muted);
    letter-spacing: 0.1em;
    z-index: 50;
  }

  .status-dot {
    display: inline-block;
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent3);
    margin-right: 6px;
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.8); }
  }

  /* Main panel */
  .panel {
    position: relative;
    width: 420px;
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 0;
    animation: panelIn 0.8s cubic-bezier(0.16, 1, 0.3, 1) both;
    z-index: 10;
  }

  @keyframes panelIn {
    from { opacity: 0; transform: translateY(30px) scale(0.97); }
    to { opacity: 1; transform: translateY(0) scale(1); }
  }

  /* Panel glitch effect on load */
  .panel::before {
    content: '';
    position: absolute;
    inset: -1px;
    background: linear-gradient(135deg, var(--accent) 0%, transparent 50%, var(--accent2) 100%);
    opacity: 0;
    animation: borderPulse 6s ease-in-out infinite;
    z-index: -1;
  }

  @keyframes borderPulse {
    0%, 100% { opacity: 0; }
    50% { opacity: 0.3; }
  }

  .panel-header {
    padding: 24px 32px 20px;
    border-bottom: 1px solid var(--border);
    position: relative;
    overflow: hidden;
  }

  .panel-header::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    animation: shimmer 3s ease-in-out infinite;
  }

  @keyframes shimmer {
    0%, 100% { opacity: 0.3; transform: scaleX(0.5); }
    50% { opacity: 1; transform: scaleX(1); }
  }

  .sys-label {
    font-size: 9px;
    letter-spacing: 0.3em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .sys-label::before {
    content: '';
    display: block;
    width: 20px;
    height: 1px;
    background: var(--accent);
  }

  .panel-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 26px;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.05em;
    line-height: 1;
    text-transform: uppercase;
  }

  .panel-title span {
    color: var(--accent);
    text-shadow: var(--glow);
  }

  .panel-sub {
    font-size: 10px;
    color: var(--muted);
    margin-top: 6px;
    letter-spacing: 0.15em;
  }

  .panel-body {
    padding: 28px 32px 32px;
  }


  /* Form fields */
  .field-group {
    margin-bottom: 20px;
    animation: fieldIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
  }
  .field-group:nth-child(1) { animation-delay: 0.1s; }
  .field-group:nth-child(2) { animation-delay: 0.2s; }

  @keyframes fieldIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
  }

  label {
    display: block;
    font-size: 9px;
    letter-spacing: 0.25em;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .input-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-icon {
    position: absolute;
    left: 14px;
    font-size: 12px;
    color: var(--muted);
    pointer-events: none;
    transition: color 0.2s;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    background: #0a1520;
    border: 1px solid #0ff2;
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    padding: 12px 14px 12px 40px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
    letter-spacing: 0.05em;
    caret-color: var(--accent);
  }

  input::placeholder { color: #2a4a55; }

  input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent), inset 0 0 20px #00f5ff08;
  }

  input:focus + .input-icon,
  .input-wrap:focus-within .input-icon {
    color: var(--accent);
  }

  /* Show/hide password toggle */
  .toggle-pass {
    position: absolute;
    right: 12px;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 11px;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 0.1em;
    padding: 4px;
    transition: color 0.2s;
  }
  .toggle-pass:hover { color: var(--accent); }

  /* Remember me */
  .field-options {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 24px;
    font-size: 10px;
  }

  .check-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--muted);
    letter-spacing: 0.1em;
  }

  .check-wrap input[type="checkbox"] {
    appearance: none;
    width: 14px;
    height: 14px;
    border: 1px solid var(--muted);
    background: none;
    cursor: pointer;
    padding: 0;
    position: relative;
    transition: border-color 0.2s;
    flex-shrink: 0;
  }

  .check-wrap input[type="checkbox"]:checked {
    border-color: var(--accent);
    background: var(--accent);
  }

  .check-wrap input[type="checkbox"]:checked::after {
    content: '✓';
    position: absolute;
    top: -2px; left: 1px;
    font-size: 11px;
    color: var(--bg);
  }

  .forgot-link {
    color: var(--accent);
    text-decoration: none;
    font-size: 10px;
    letter-spacing: 0.1em;
    opacity: 0.7;
    transition: opacity 0.2s;
  }
  .forgot-link:hover { opacity: 1; }

  /* Submit button */
  .btn-submit {
    width: 100%;
    background: transparent;
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    padding: 14px;
    cursor: pointer;
    position: relative;
    overflow: hidden;
    transition: color 0.2s;
    animation: fieldIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.3s both;
  }

  .btn-submit::before {
    content: '';
    position: absolute;
    inset: 0;
    background: var(--accent);
    transform: translateX(-101%);
    transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    z-index: 0;
  }

  .btn-submit:hover::before { transform: translateX(0); }
  .btn-submit:hover { color: var(--bg); box-shadow: var(--glow); }

  .btn-submit span { position: relative; z-index: 1; }

  /* Divider */
  .divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 20px 0;
    opacity: 0.4;
  }
  .divider::before, .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--muted);
  }
  .divider span { font-size: 9px; letter-spacing: 0.2em; color: var(--muted); }

  /* Bottom info */
  .panel-footer {
    padding: 14px 32px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .conn-status {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 9px;
    color: var(--muted);
    letter-spacing: 0.1em;
  }

  .conn-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent3);
    box-shadow: 0 0 6px var(--accent3);
    animation: pulse 2s ease-in-out infinite;
  }

  .session-id {
    font-size: 9px;
    color: var(--muted);
    letter-spacing: 0.05em;
    opacity: 0.5;
  }

  /* Glitch text animation on title */
  @keyframes glitch {
    0%, 95%, 100% { clip-path: none; transform: none; }
    96% { clip-path: inset(20% 0 60% 0); transform: translateX(-3px); }
    97% { clip-path: inset(60% 0 10% 0); transform: translateX(3px); }
    98% { clip-path: inset(40% 0 30% 0); transform: translateX(-2px); }
    99% { clip-path: none; transform: none; }
  }

  .panel-title {
    animation: glitch 8s steps(1) infinite;
  }

  /* Floating particles */
  .particles {
    position: fixed;
    inset: 0;
    pointer-events: none;
    overflow: hidden;
  }

  .particle {
    position: absolute;
    width: 1px;
    height: 1px;
    background: var(--accent);
    border-radius: 50%;
    animation: float linear infinite;
  }

  @keyframes float {
    0% { transform: translateY(100vh) translateX(0); opacity: 0; }
    10% { opacity: 0.6; }
    90% { opacity: 0.6; }
    100% { transform: translateY(-100px) translateX(var(--drift)); opacity: 0; }
  }
</style>
</head>
<body>

<div class="corner corner--tl"></div>
<div class="corner corner--tr"></div>
<div class="corner corner--bl"></div>
<div class="corner corner--br"></div>
<div class="sidebar sidebar--left"></div>
<div class="sidebar sidebar--right"></div>
<div class="particles" id="particles"></div>

<div class="status-bar">
  <div><span class="status-dot"></span>SECURE CHANNEL ESTABLISHED &nbsp;|&nbsp; TLS 1.3 &nbsp;|&nbsp; AES-256-GCM</div>
  <div id="clock">--:--:--</div>
  <div>NODE: SYS-ALPHA-07 &nbsp;|&nbsp; REGION: LOCAL</div>
</div>

<div class="panel">
  <div class="panel-header">
    <div class="sys-label">CLASSIFIED ACCESS PORTAL</div>
    <div class="panel-title">ADMIN <span>CONSOLE</span></div>
    <div class="panel-sub">SYSTEM ADMINISTRATION INTERFACE &nbsp;//&nbsp; AUTHENTICATION REQUIRED</div>
  </div>

  <div class="panel-body">

    <form method="POST" action="/login" autocomplete="off">
      <div class="field-group">
        <label for="username">User Identifier</label>
        <div class="input-wrap">
          <input type="text" id="username" name="username" placeholder="Enter credentials..." autocomplete="off" spellcheck="false">
          <span class="input-icon">▸</span>
        </div>
      </div>

      <div class="field-group">
        <label for="password">Access Key</label>
        <div class="input-wrap">
          <input type="password" id="password" name="password" placeholder="••••••••••••" autocomplete="off">
          <span class="input-icon">🔑</span>
          <button type="button" class="toggle-pass" onclick="togglePass()" id="toggleBtn">SHOW</button>
        </div>
      </div>

      <div class="field-options">
        <label class="check-wrap">
          <input type="checkbox" name="remember"> MAINTAIN SESSION
        </label>
        <a href="#" class="forgot-link">RECOVERY PROTOCOL →</a>
      </div>

      <button type="submit" class="btn-submit"><span>AUTHENTICATE &nbsp;▶</span></button>
    </form>

    <div class="divider"><span>SYS-INFO</span></div>
  </div>

  <div class="panel-footer">
    <div class="conn-status">
      <div class="conn-dot"></div>
      ENCRYPTED CONNECTION
    </div>
    <div class="session-id" id="sessionId">SES::--------</div>
  </div>
</div>

<script>
  // Live clock
  function updateClock() {
    const now = new Date();
    document.getElementById('clock').textContent =
      now.toTimeString().slice(0, 8) + ' UTC';
  }
  setInterval(updateClock, 1000);
  updateClock();

  // Session ID display
  const chars = '0123456789ABCDEF';
  let sid = 'SES::';
  for (let i = 0; i < 8; i++) sid += chars[Math.floor(Math.random() * 16)];
  document.getElementById('sessionId').textContent = sid;

  // Password toggle
  function togglePass() {
    const inp = document.getElementById('password');
    const btn = document.getElementById('toggleBtn');
    if (inp.type === 'password') {
      inp.type = 'text';
      btn.textContent = 'HIDE';
    } else {
      inp.type = 'password';
      btn.textContent = 'SHOW';
    }
  }

  // Floating particles
  const container = document.getElementById('particles');
  for (let i = 0; i < 20; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + 'vw';
    p.style.setProperty('--drift', (Math.random() - 0.5) * 100 + 'px');
    p.style.animationDuration = (6 + Math.random() * 10) + 's';
    p.style.animationDelay = (Math.random() * 10) + 's';
    p.style.width = p.style.height = (Math.random() > 0.7 ? '2px' : '1px');
    p.style.opacity = Math.random() * 0.5 + 0.1;
    container.appendChild(p);
  }
</script>
</body>
</html>
"""
    def parse_request(self, data):
        lines = data.split("\r\n")
        request_line = lines[0] if lines else ""
        method, path, version = "GET", "/", "HTTP/1.1"
        if request_line:
            parts = request_line.split()
            if len(parts) >= 3:
                method, path, version = parts[0], parts[1], parts[2]

        headers = {}
        body = ""
        header_done = False
        for line in lines[1:]:
            if not header_done and line == "":
                header_done = True
                continue
            if header_done:
                body += line
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        return method, path, version, headers, body

    def detect_attack_type(self, payload):
        normalized_payload = self.normalize_payload(payload)
        payload_lower = normalized_payload.lower()

        if self.is_xss_payload(normalized_payload):
            return "XSS Attack"

        if self.is_sql_payload(normalized_payload):
            return "SQL Injection"

        if self.is_path_traversal_payload(payload):
            return "Path Traversal"

        if re.search(r"(;|\|\||&&|`|\$\(|\$\{)", normalized_payload) and re.search(
            r"(cat|ls|rm|wget|curl|nc|bash|sh|powershell|cmd\.exe)", payload_lower
        ):
            return "Command Injection"

        if "username" in payload_lower or "password" in payload_lower:
            return "Credential Harvest Attempt"

        return None

    def is_sql_payload(self, payload):
        for pattern in self.sql_patterns:
            if pattern.search(payload):
                return True

        # If SQL comments are present, require SQL context to reduce false positives.
        if self.sql_comment_pattern.search(payload):
            return bool(
                re.search(
                    r"\b(select|union|where|having|order\s+by|group\s+by|and|or|sleep|waitfor|into|exec|xp_cmdshell)\b",
                    payload,
                    re.IGNORECASE,
                )
            )

        return False

    def is_xss_payload(self, payload):
        for pattern in self.xss_patterns:
            if pattern.search(payload):
                return True

        # Treat JS function calls as XSS only when there is clear injection context.
        has_function_call = any(pattern.search(payload) for pattern in self.xss_function_patterns)
        if not has_function_call:
            return False

        return bool(
            re.search(
                r"(<[^>]*>|[\"'`].*;|javascript\s*:|on[a-z]+\s*=|data\s*:\s*text/html|xlink:href)",
                payload,
                re.IGNORECASE,
            )
        )

    def is_path_traversal_payload(self, payload):
        # Evaluate decoded variants to catch encoded and double-encoded traversal attempts.
        variants = {str(payload), self.normalize_payload(payload)}
        decoded = self.normalize_payload(payload)
        for _ in range(3):
            next_decoded = unquote_plus(decoded)
            if next_decoded == decoded:
                break
            variants.add(next_decoded)
            decoded = next_decoded

        for variant in variants:
            lowered = variant.lower().replace("\\", "/")
            lowered = re.sub(r"/+", "/", lowered)

            if "../" in lowered or "/..;" in lowered:
                return True

            for pattern in self.path_traversal_patterns:
                if pattern.search(lowered):
                    return True

        return False

    def normalize_payload(self, payload):
        normalized = payload.replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
        for _ in range(3):
            decoded = unquote_plus(unescape(normalized))
            if decoded == normalized:
                break
            normalized = decoded

        normalized = normalized.replace("\x00", "")
        normalized = re.sub(r"[\t\r\n\f\v]+", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def detect_scanner(self, headers, payload):
        user_agent = headers.get("user-agent", "").lower()
        full = f"{user_agent} {payload.lower()}"
        for marker, label in self.scanners.items():
            if marker in full:
                return label
        return None

    def extract_credentials(self, body):
        try:
            parsed = parse_qs(body, keep_blank_values=True)
        except Exception:
            return "unknown", "unknown"

        username = (
            parsed.get("username", parsed.get("user", parsed.get("login", ["unknown"])))[0]
            if parsed
            else "unknown"
        )
        password = (
            parsed.get("password", parsed.get("pass", parsed.get("pwd", ["unknown"])))[0]
            if parsed
            else "unknown"
        )
        return str(username)[:120], str(password)[:120]

    def has_login_attempt(self, method, path, body):
        method_upper = str(method).upper()
        parsed = parse_qs(body or "", keep_blank_values=True)
        has_creds = any(k in parsed for k in ("username", "user", "login", "email", "password", "pass", "pwd"))
        login_path_markers = ("/login", "/signin", "/auth", "/session", "/admin")
        path_lower = (path or "").lower()
        path_looks_like_login = any(marker in path_lower for marker in login_path_markers)
        return method_upper in {"POST", "PUT", "PATCH"} and (has_creds or path_looks_like_login)

    def build_response(self, method, path):
        body = self.html_content
        status = "200 OK"
        if path.lower().startswith("/admin"):
            status = "401 Unauthorized"
        if path.lower().startswith("/wp-admin"):
            status = "403 Forbidden"
        if method == "OPTIONS":
            body = ""
        if method == "HEAD":
            body = ""

        headers = [
            f"HTTP/1.1 {status}",
            f"Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            f"Server: {self.banner.get('server', 'Apache/2.4.41 (Ubuntu)')}",
            f"X-Powered-By: {self.banner.get('x_powered_by', 'PHP/7.4.3')}",
            "Content-Type: text/html; charset=UTF-8",
            f"Content-Length: {len(body.encode('utf-8'))}",
            "Connection: close",
            "",
            "",
        ]
        return "\r\n".join(headers).encode("utf-8", errors="ignore") + body.encode("utf-8", errors="ignore")

    def handle_client(self, client_socket, addr):
        started_at = datetime.now()
        client_ip, client_port = addr[0], addr[1]

        try:
            self.log(f"Connection from {client_ip}:{client_port} local_port={self.port}")
            raw = client_socket.recv(8192)
            if not raw:
                self.log(f"[Nmap Scan Detection] IP={client_ip} port={self.port} reason=no_payload")
                return

            request_text = raw.decode("utf-8", errors="ignore")
            method, path, version, headers, body = self.parse_request(request_text)

            request_line = request_text.split("\r\n", 1)[0].strip()
            if not request_line or " " not in request_line:
                self.log(
                    f"[Nmap Scan Detection] IP={client_ip} port={self.port} reason=non_http_probe payload={request_line[:120]!r}"
                )
                return

            self.log(
                f"Request from {client_ip}:{client_port}: {method} {path} {version} "
                f"host={headers.get('host', 'unknown')} ua={headers.get('user-agent', 'unknown')} bytes={len(raw)}"
            )

            scanner = self.detect_scanner(headers, request_text)
            if scanner:
                if scanner == "Nmap":
                    self.log(f"[Nmap Scan Detection] IP={client_ip} path={path} method={method}")
                else:
                    self.log(f"[Scanner Detection] IP={client_ip} tool={scanner}")

            attack_type = self.detect_attack_type(request_text)
            username = password = None
            if attack_type:
                if attack_type == "Credential Harvest Attempt":
                    username, password = self.extract_credentials(body)
                    self.log(f"[{attack_type}] IP={client_ip} username={username} password={password}")
                else:
                    self.log(f"[{attack_type}] IP={client_ip} payload_snippet={request_text[:200]!r}")

            # ── ML Brute Force Detection for HTTP login-like attempts ───────
            if _ml_bf_detector is not None and self.has_login_attempt(method, path, body):
                if username is None or password is None:
                    username, password = self.extract_credentials(body)
                result = _ml_bf_detector.record_attempt(client_ip, username, password)
                attempts = result.get("attempt_count", 0)
                confidence = result.get("confidence", 0.0)
                is_bf = result.get("is_brute_force", False)
                self.log(
                    f"[ML Brute Force] IP={client_ip} attempt={attempts} "
                    f"is_brute_force={is_bf} confidence={confidence:.0%} "
                    f"unique_users={result.get('unique_usernames', 1)}"
                )
            # ────────────────────────────────────────────────────────────────

            # ── ML: always run and log independently of regex ─────────────────
            if _ml_attack_clf is not None and _ml_attack_clf.is_ready:
                normalized = self.normalize_payload(request_text)
                ml_label, ml_conf = _ml_attack_clf.predict(normalized)
                if ml_label:
                    self.log(f"[ML Attack Classifier] IP={client_ip} detected={ml_label} confidence={ml_conf:.0%}")
                else:
                    self.log(f"[ML Attack Classifier] IP={client_ip} detected=Normal confidence={ml_conf:.0%}")
            # ─────────────────────────────────────────────────────────────────

            if method in {"POST", "PUT", "PATCH"} and body:
                self.log(f"Body capture from {client_ip}:{client_port}: {body[:300]}")

            response = self.build_response(method, path)
            client_socket.sendall(response)

        except Exception as exc:
            self.log(f"Error handling client {client_ip}:{client_port}: {exc}")
        finally:
            duration = (datetime.now() - started_at).total_seconds()
            self.log(f"Session closed for {client_ip}:{client_port} duration={duration:.3f}s")
            client_socket.close()

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)
            self.running = True
            self.log(
                f"Started on port {self.port} with banner={self.banner.get('server', 'unknown')}"
            )

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as exc:
                    if self.running:
                        self.log(f"Accept loop error: {exc}")
        except Exception as exc:
            self.log(f"Failed to start: {exc}")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.log("Stopped")