import os
import re
import socket
import threading
from datetime import datetime
from urllib.parse import parse_qs


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
            r"(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|\bwaitfor\s+delay\b|\bdrop\s+table\b)",
            r"(\bxp_cmdshell\b|\bexec\b\s*\(|\bbenchmark\b\s*\()",
            r"(--|#|/\*|\*/)",
        ]
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
        ]
        self.scanners = {
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
<html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Admin Login</title></head>
<body style=\"font-family:Arial;background:#111;color:#ddd;padding:40px\">
<h1>System Administration Portal</h1>
<p>Restricted area. Authentication required.</p>
<form method=\"POST\" action=\"/login\">
  <label>User:</label><input type=\"text\" name=\"username\" /><br /><br />
  <label>Password:</label><input type=\"password\" name=\"password\" /><br /><br />
  <button type=\"submit\">Sign In</button>
</form>
</body></html>"""

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
        payload_lower = payload.lower()

        for pattern in self.sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return "SQL Injection"
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return "XSS Attack"
        if re.search(r"\.\.[\\/]|%2e%2e|/etc/passwd|\\windows\\win.ini", payload, re.IGNORECASE):
            return "Path Traversal"
        if re.search(r"(;|\|\||&&|`|\$\(|\$\{)", payload) and re.search(
            r"(cat|ls|rm|wget|curl|nc|bash|sh|powershell|cmd\.exe)", payload_lower
        ):
            return "Command Injection"
        if "username" in payload_lower or "password" in payload_lower:
            return "Credential Harvest Attempt"
        return None

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
            raw = client_socket.recv(8192)
            if not raw:
                return

            request_text = raw.decode("utf-8", errors="ignore")
            method, path, version, headers, body = self.parse_request(request_text)

            self.log(
                f"Connection from {client_ip}:{client_port} | method={method} path={path} version={version} "
                f"host={headers.get('host', 'unknown')} ua={headers.get('user-agent', 'unknown')} bytes={len(raw)}"
            )

            scanner = self.detect_scanner(headers, request_text)
            if scanner:
                self.log(f"[Scanner Detection] IP={client_ip} tool={scanner}")

            attack_type = self.detect_attack_type(request_text)
            if attack_type:
                if attack_type == "Credential Harvest Attempt":
                    username, password = self.extract_credentials(body)
                    self.log(f"[{attack_type}] IP={client_ip} username={username} password={password}")
                else:
                    self.log(f"[{attack_type}] IP={client_ip} payload_snippet={request_text[:200]!r}")

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