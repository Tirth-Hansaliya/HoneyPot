import os
import shlex
import socket
import threading
from datetime import datetime

import paramiko


class _HoneypotServer(paramiko.ServerInterface):
    def __init__(self, hp, client_ip):
        self.hp = hp
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = "unknown"
        self.password = ""
        self.exec_command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.hp.log(
            f"Credential capture from {self.client_ip}: username={username} password={password}"
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", errors="ignore")
        self.event.set()
        return True


class SSHHoneypot:
    def __init__(self, port=2222, log_callback=None, banner="SSH-2.0-OpenSSH_5.3", filesystem_dir="uploads"):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        self.banner = banner
        self.filesystem_dir = filesystem_dir
        self.host_key = paramiko.RSAKey.generate(2048)
        self.tool_markers = {
            "hydra": "Hydra",
            "metasploit": "Metasploit",
            "paramiko": "Paramiko",
            "nmap": "Nmap",
            "libssh": "libssh",
            "masscan": "Masscan",
        }

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[SSH] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)

    def _detect_tool(self, text):
        lowered = text.lower()
        for marker, name in self.tool_markers.items():
            if marker in lowered:
                return name
        return None

    def _list_files(self):
        os.makedirs(self.filesystem_dir, exist_ok=True)
        return sorted([name for name in os.listdir(self.filesystem_dir) if os.path.isfile(os.path.join(self.filesystem_dir, name))])

    def _run_command(self, command, cwd, client_ip):
        command = command.strip()
        if not command:
            return "", cwd

        tool = self._detect_tool(command)
        if tool:
            self.log(f"[Tool Detection] IP={client_ip} tool={tool} command={command}")

        tokens = shlex.split(command) if command else []
        base = tokens[0] if tokens else ""

        if base in {"pwd"}:
            return f"{cwd}\n", cwd
        if base in {"whoami"}:
            return "root\n", cwd
        if base in {"id"}:
            return "uid=0(root) gid=0(root) groups=0(root)\n", cwd
        if base in {"uname"}:
            if len(tokens) > 1 and tokens[1] == "-a":
                return "Linux honeypot 4.15.0-20-generic #21-Ubuntu SMP x86_64 GNU/Linux\n", cwd
            return "Linux\n", cwd
        if base in {"cd"}:
            new_dir = tokens[1] if len(tokens) > 1 else "/root"
            if not new_dir.startswith("/"):
                new_dir = f"{cwd.rstrip('/')}/{new_dir}"
            return "", new_dir
        if base in {"ls"}:
            files = self._list_files()
            if "-la" in tokens or "-al" in tokens:
                listing = [f"-rw-r--r-- 1 root root {os.path.getsize(os.path.join(self.filesystem_dir, name)):6d} Jan 01 12:00 {name}" for name in files]
                return "\n".join(listing) + ("\n" if listing else "\n"), cwd
            return "\n".join(files) + ("\n" if files else "\n"), cwd
        if base == "cat":
            if len(tokens) < 2:
                return "cat: missing operand\n", cwd
            name = os.path.basename(tokens[1])
            path = os.path.join(self.filesystem_dir, name)
            self.log(f"File read attempt from {client_ip}: file={name}")
            if not os.path.exists(path):
                return f"cat: {name}: No such file or directory\n", cwd
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read(4096)
                return content + ("\n" if not content.endswith("\n") else ""), cwd
            except Exception as exc:
                return f"cat: {name}: {exc}\n", cwd
        if base in {"wget", "curl"}:
            target = tokens[-1] if len(tokens) > 1 else "unknown"
            self.log(f"Malware download attempt from {client_ip}: tool={base} target={target}")
            return f"{base}: failed to connect to {target}\n", cwd
        if base in {"rm", "chmod", "chown", "mv", "cp"}:
            self.log(f"Destructive command attempt from {client_ip}: {command}")
            return "Operation not permitted\n", cwd
        if base == "exit":
            return "__EXIT__", cwd

        return f"{base}: command not found\n", cwd

    def _interactive_shell(self, channel, client_ip):
        cwd = "/root"
        channel.send("Linux ubuntu 4.15.0-20-generic x86_64\r\n")

        while self.running and not channel.closed:
            try:
                channel.send(f"root@server:{cwd}# ")
                buff = ""
                while not buff.endswith("\r"):
                    chunk = channel.recv(1024)
                    if not chunk:
                        return
                    buff += chunk.decode("utf-8", errors="ignore")

                command = buff.strip()
                self.log(f"Command from {client_ip}: {command}")
                output, cwd = self._run_command(command, cwd, client_ip)
                if output == "__EXIT__":
                    channel.send("logout\r\n")
                    return
                if output:
                    channel.send(output.replace("\n", "\r\n"))
            except Exception:
                return

    def handle_client(self, client_socket, addr):
        started = datetime.now()
        client_ip, client_port = addr
        transport = None
        session_user = "unknown"

        try:
            self.log(f"Connection from {client_ip}:{client_port} local_port={self.port}")
            transport = paramiko.Transport(client_socket)
            transport.local_version = self.banner
            transport.add_server_key(self.host_key)

            server = _HoneypotServer(self, client_ip)
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                self.log(f"Handshake failed for {client_ip}:{client_port}")
                return

            session_user = server.username
            peer_version = transport.remote_version or "unknown"
            self.log(
                f"SSH negotiation from {client_ip}:{client_port} peer_version={peer_version} auth_user={session_user}"
            )
            tool = self._detect_tool(peer_version)
            if tool:
                self.log(f"[Tool Detection] IP={client_ip} tool={tool} client_banner={peer_version}")

            server.event.wait(20)
            if server.exec_command:
                self.log(f"Exec request from {client_ip}: {server.exec_command}")
                output, _ = self._run_command(server.exec_command, "/root", client_ip)
                if output == "__EXIT__":
                    output = ""
                if output:
                    channel.send(output.replace("\n", "\r\n"))
                channel.close()
            else:
                self._interactive_shell(channel, client_ip)

        except Exception as exc:
            self.log(f"Error handling client {client_ip}:{client_port}: {exc}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            duration = (datetime.now() - started).total_seconds()
            self.log(
                f"Session summary ip={client_ip} port={client_port} user={session_user} duration={duration:.3f}s"
            )

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(100)
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
            except Exception:
                pass
        self.log("Stopped")