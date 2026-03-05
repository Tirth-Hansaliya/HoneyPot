import os
import socket
import threading
from datetime import datetime


class FTPHoneypot:
    def __init__(self, port=2121, log_callback=None, ftp_files_dir="uploads", banner="220 (vsFTPd 2.3.4)"):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        self.ftp_files_dir = ftp_files_dir
        self.banner = banner
        self.passive_port_start = 30000
        self.passive_port_end = 30100
        self._next_passive_port = self.passive_port_start
        self.scanner_markers = {
            "nmap": "Nmap",
            "hydra": "Hydra",
            "medusa": "Medusa",
            "metasploit": "Metasploit",
            "python": "Python script",
            "sqlmap": "SQLMap",
            "nikto": "Nikto",
            "burp": "Burp Suite",
        }

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[FTP] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)

    def _send_line(self, client, text):
        client.sendall(f"{text}\r\n".encode("utf-8", errors="ignore"))

    def _recv_line(self, client, pending_buffer):
        """Read a single CRLF-terminated FTP command line."""
        while b"\n" not in pending_buffer:
            chunk = client.recv(4096)
            if not chunk:
                return None, pending_buffer
            pending_buffer += chunk

        line, pending_buffer = pending_buffer.split(b"\n", 1)
        line = line.rstrip(b"\r")
        return line.decode("utf-8", errors="ignore"), pending_buffer

    def _iter_files(self):
        os.makedirs(self.ftp_files_dir, exist_ok=True)
        for name in sorted(os.listdir(self.ftp_files_dir)):
            path = os.path.join(self.ftp_files_dir, name)
            if os.path.isfile(path):
                yield name, path

    def _build_listing(self):
        lines = []
        for name, path in self._iter_files():
            size = os.path.getsize(path)
            lines.append(f"-rw-r--r--   1 root root {size:10d} Jan 01 12:00 {name}")
        if not lines:
            lines.append("-rw-r--r--   1 root root       1024 Jan 01 12:00 readme.txt")
        return "\r\n".join(lines) + "\r\n"

    def _detect_scanner(self, text):
        lowered = text.lower()
        for marker, scanner in self.scanner_markers.items():
            if marker in lowered:
                return scanner
        return None

    def _open_passive_socket(self):
        # Use a fixed passive port range to improve NAT/firewall compatibility.
        total_ports = self.passive_port_end - self.passive_port_start + 1
        for _ in range(total_ports):
            port = self._next_passive_port
            self._next_passive_port += 1
            if self._next_passive_port > self.passive_port_end:
                self._next_passive_port = self.passive_port_start

            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                data_socket.bind(("0.0.0.0", port))
                data_socket.listen(1)
                data_socket.settimeout(20.0)
                return data_socket, port
            except OSError:
                data_socket.close()

        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_socket.bind(("0.0.0.0", 0))
        data_socket.listen(1)
        data_socket.settimeout(20.0)
        return data_socket, data_socket.getsockname()[1]

    def _build_pasv_reply(self, host_ip, port):
        host = host_ip if host_ip and host_ip != "0.0.0.0" else "127.0.0.1"
        if ":" in host:
            host = "127.0.0.1"

        h1, h2, h3, h4 = host.split(".")
        p1, p2 = divmod(port, 256)
        return f"227 Entering Passive Mode ({h1},{h2},{h3},{h4},{p1},{p2})"

    def _send_via_data_socket(self, data_listen_socket, payload):
        data_client = None
        try:
            data_client, data_addr = data_listen_socket.accept()
            self.log(f"PASV data connection from {data_addr[0]}:{data_addr[1]} bytes={len(payload)}")
            data_client.sendall(payload)
        finally:
            if data_client:
                data_client.close()
            data_listen_socket.close()

    def _parse_port_target(self, arg):
        parts = [p.strip() for p in arg.split(",")]
        if len(parts) != 6:
            return None
        try:
            host = ".".join(parts[:4])
            p1 = int(parts[4])
            p2 = int(parts[5])
            port = p1 * 256 + p2
            if port <= 0 or port > 65535:
                return None
            return host, port
        except ValueError:
            return None

    def _parse_eprt_target(self, arg):
        # EPRT syntax: |<af>|<host>|<port>| (usually |1|x.x.x.x|port| for IPv4)
        if not arg:
            return None
        delim = arg[0]
        fields = arg.split(delim)
        if len(fields) < 5:
            return None
        af = fields[1]
        host = fields[2].strip()
        port_text = fields[3].strip()
        if af != "1":
            return None
        try:
            port = int(port_text)
            if port <= 0 or port > 65535:
                return None
            return host, port
        except ValueError:
            return None

    def _send_via_active_socket(self, target, payload):
        active_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        active_sock.settimeout(20.0)
        try:
            active_sock.connect(target)
            self.log(f"Active data connection to {target[0]}:{target[1]} bytes={len(payload)}")
            active_sock.sendall(payload)
        finally:
            active_sock.close()

    def handle_client(self, client_socket, addr):
        started = datetime.now()
        client_ip, client_port = addr
        username = "unknown"
        logged_in = False
        data_listen_socket = None
        active_data_target = None
        pending_buffer = b""

        try:
            client_socket.settimeout(40.0)
            self.log(f"Connection from {client_ip}:{client_port} local_port={self.port}")
            self._send_line(client_socket, self.banner)

            while self.running:
                try:
                    data, pending_buffer = self._recv_line(client_socket, pending_buffer)
                    if data is None:
                        break
                    data = data.strip()
                    if not data:
                        continue

                    self.log(f"Command from {client_ip}:{client_port}: {data}")
                    scanner = self._detect_scanner(data)
                    if scanner:
                        self.log(f"[Tool Detection] IP={client_ip} scanner={scanner}")

                    parts = data.split()
                    cmd = parts[0].upper()
                    arg = " ".join(parts[1:]) if len(parts) > 1 else ""

                    if cmd == "USER":
                        username = arg or "unknown"
                        self.log(f"Credential capture USER from {client_ip}: username={username}")
                        self._send_line(client_socket, "331 Password required")
                    elif cmd == "PASS":
                        password = arg or ""
                        self.log(f"Credential capture PASS from {client_ip}: username={username} password={password}")
                        logged_in = True
                        self._send_line(client_socket, "230 Login successful")
                    elif cmd == "SYST":
                        self._send_line(client_socket, "215 UNIX Type: L8")
                    elif cmd == "FEAT":
                        self._send_line(client_socket, "211-Features")
                        self._send_line(client_socket, " PASV")
                        self._send_line(client_socket, " EPSV")
                        self._send_line(client_socket, " UTF8")
                        self._send_line(client_socket, " SIZE")
                        self._send_line(client_socket, " MDTM")
                        self._send_line(client_socket, "211 End")
                    elif cmd == "PWD":
                        self._send_line(client_socket, '257 "/" is current directory')
                    elif cmd == "TYPE":
                        self._send_line(client_socket, f"200 Type set to {arg or 'I'}")
                    elif cmd == "CWD":
                        self._send_line(client_socket, "250 Directory changed")
                    elif cmd == "PASV":
                        if data_listen_socket:
                            data_listen_socket.close()
                        active_data_target = None
                        local_ip = client_socket.getsockname()[0]
                        data_listen_socket, port = self._open_passive_socket()
                        reply = self._build_pasv_reply(local_ip, port)
                        self._send_line(client_socket, reply)
                    elif cmd == "EPSV":
                        if data_listen_socket:
                            data_listen_socket.close()
                        active_data_target = None
                        data_listen_socket, port = self._open_passive_socket()
                        self._send_line(client_socket, f"229 Entering Extended Passive Mode (|||{port}|)")
                    elif cmd == "PORT":
                        target = self._parse_port_target(arg)
                        if not target:
                            self._send_line(client_socket, "501 Invalid PORT syntax")
                            continue
                        if data_listen_socket:
                            data_listen_socket.close()
                            data_listen_socket = None
                        active_data_target = target
                        self._send_line(client_socket, "200 PORT command successful")
                    elif cmd == "EPRT":
                        target = self._parse_eprt_target(arg)
                        if not target:
                            self._send_line(client_socket, "522 Network protocol not supported")
                            continue
                        if data_listen_socket:
                            data_listen_socket.close()
                            data_listen_socket = None
                        active_data_target = target
                        self._send_line(client_socket, "200 EPRT command successful")
                    elif cmd in {"LIST", "NLST"}:
                        if not logged_in:
                            self._send_line(client_socket, "530 Not logged in")
                            continue
                        if not data_listen_socket and not active_data_target:
                            self._send_line(client_socket, "425 Use PORT/EPRT or PASV/EPSV first")
                            continue
                        listing = self._build_listing().encode("utf-8", errors="ignore")
                        self.log(f"Directory listing requested by {client_ip} total_bytes={len(listing)}")
                        self._send_line(client_socket, "150 Opening ASCII mode data connection for file list")
                        if data_listen_socket:
                            self._send_via_data_socket(data_listen_socket, listing)
                            data_listen_socket = None
                        else:
                            self._send_via_active_socket(active_data_target, listing)
                            active_data_target = None
                        self._send_line(client_socket, "226 Transfer complete")
                    elif cmd == "RETR":
                        if not logged_in:
                            self._send_line(client_socket, "530 Not logged in")
                            continue
                        if not data_listen_socket and not active_data_target:
                            self._send_line(client_socket, "425 Use PORT/EPRT or PASV/EPSV first")
                            continue

                        target = os.path.basename(arg)
                        file_path = os.path.join(self.ftp_files_dir, target)
                        self.log(f"[FTP Download Attempt] IP={client_ip} file={target}")
                        if not target or not os.path.exists(file_path):
                            self._send_line(client_socket, "550 File not found")
                            data_listen_socket.close()
                            data_listen_socket = None
                            continue

                        with open(file_path, "rb") as handle:
                            payload = handle.read()

                        self._send_line(client_socket, "150 Opening BINARY mode data connection")
                        if data_listen_socket:
                            self._send_via_data_socket(data_listen_socket, payload)
                            data_listen_socket = None
                        else:
                            self._send_via_active_socket(active_data_target, payload)
                            active_data_target = None
                        self._send_line(client_socket, "226 Transfer complete")
                        self.log(f"File exfiltrated by {client_ip} file={target} bytes={len(payload)}")
                    elif cmd == "SIZE":
                        target = os.path.basename(arg)
                        file_path = os.path.join(self.ftp_files_dir, target)
                        if target and os.path.exists(file_path):
                            self._send_line(client_socket, f"213 {os.path.getsize(file_path)}")
                        else:
                            self._send_line(client_socket, "550 File not found")
                    elif cmd == "MDTM":
                        self._send_line(client_socket, "213 20240101010101")
                    elif cmd == "NOOP":
                        self._send_line(client_socket, "200 NOOP ok")
                    elif cmd == "AUTH" and arg.upper() == "TLS":
                        self._send_line(client_socket, "534 AUTH TLS not available")
                    elif cmd == "PBSZ":
                        self._send_line(client_socket, "200 PBSZ=0")
                    elif cmd == "PROT":
                        self._send_line(client_socket, "200 Protection set to Clear")
                    elif cmd == "OPTS":
                        self._send_line(client_socket, "200 OPTS accepted")
                    elif cmd == "QUIT":
                        self._send_line(client_socket, "221 Goodbye")
                        break
                    else:
                        self._send_line(client_socket, "502 Command not implemented")

                except socket.timeout:
                    self.log(f"Session timeout for {client_ip}:{client_port}")
                    break
                except Exception as exc:
                    self.log(f"Error in command loop for {client_ip}:{client_port}: {exc}")
                    break
        except Exception as exc:
            self.log(f"Error handling client {client_ip}:{client_port}: {exc}")
        finally:
            if data_listen_socket:
                data_listen_socket.close()
            client_socket.close()
            duration = (datetime.now() - started).total_seconds()
            self.log(f"Session summary ip={client_ip} port={client_port} user={username} duration={duration:.3f}s")

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)
            self.running = True
            self.log(f"Started on port {self.port} banner={self.banner}")

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