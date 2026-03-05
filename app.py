from __future__ import annotations

import getpass
import logging
import os
import secrets
import socket
import threading

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename

from ftp_honeypot import FTPHoneypot
from http_honeypot import HTTPHoneypot
from ssh_honeypot import SSHHoneypot

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(24)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

HTTP_BANNERS = {
    "apache_2441": {"label": "Apache/2.4.41 (Ubuntu)", "server": "Apache/2.4.41 (Ubuntu)", "x_powered_by": "PHP/7.4.3"},
    "apache_2215": {"label": "Apache/2.2.15 (CentOS)", "server": "Apache/2.2.15 (CentOS)", "x_powered_by": "PHP/5.4.16"},
    "apache_2029": {"label": "Apache/2.0.29 (Unix)", "server": "Apache/2.0.29 (Unix)", "x_powered_by": "PHP/4.4.9"},
    "iis_60": {"label": "Microsoft-IIS/6.0", "server": "Microsoft-IIS/6.0", "x_powered_by": "ASP.NET"},
    "iis_75": {"label": "Microsoft-IIS/7.5", "server": "Microsoft-IIS/7.5", "x_powered_by": "ASP.NET"},
    "nginx_1103": {"label": "nginx/1.10.3", "server": "nginx/1.10.3", "x_powered_by": "PHP/5.6.40"},
    "nginx_1140": {"label": "nginx/1.14.0", "server": "nginx/1.14.0", "x_powered_by": "PHP/7.0.33"},
    "tomcat_70": {"label": "Apache-Coyote/1.1", "server": "Apache-Coyote/1.1", "x_powered_by": "Servlet/2.5"},
    "lighttpd_1455": {"label": "lighttpd/1.4.55", "server": "lighttpd/1.4.55", "x_powered_by": "PHP/5.6.32"},
    "jetty_9429": {"label": "Jetty(9.4.29.v20200521)", "server": "Jetty(9.4.29.v20200521)", "x_powered_by": "Servlet/3.1"},
    "caddy_201": {"label": "Caddy", "server": "Caddy", "x_powered_by": "Go"},
    "openresty_1193": {"label": "openresty/1.19.3.1", "server": "openresty/1.19.3.1", "x_powered_by": "LuaJIT"},
}

FTP_BANNERS = {
    "vsftpd_234": "220 (vsFTPd 2.3.4)",
    "vsftpd_322": "220 (vsFTPd 3.0.2)",
    "proftpd_133c": "220 ProFTPD 1.3.3c Server",
    "proftpd_135": "220 ProFTPD 1.3.5 Server",
    "wuftpd_260": "220 wu-2.6.0(1) FTP server ready.",
    "pureftpd_153": "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------",
    "msftp": "220 Microsoft FTP Service",
    "filezilla": "220-FileZilla Server 0.9.60 beta",
    "servu_150": "220 Serv-U FTP Server v15.0 ready",
    "gene6": "220 Gene6 FTP Server v3.10.0 ready",
    "glftpd": "220 glFTPd 2.01 Linux+TLS ready",
    "drftpd": "220 drftpd 3.2.0 ready",
}

SSH_BANNERS = {
    "openssh_53": "SSH-2.0-OpenSSH_5.3",
    "openssh_66": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2",
    "openssh_74": "SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7",
    "openssh_81": "SSH-2.0-OpenSSH_8.1",
    "libssh_070": "SSH-2.0-libssh-0.7.0",
    "libssh_083": "SSH-2.0-libssh-0.8.3",
    "dropbear_2016": "SSH-2.0-dropbear_2016.74",
    "dropbear_2020": "SSH-2.0-dropbear_2020.81",
    "cisco": "SSH-2.0-Cisco-1.25",
    "mikrotik": "SSH-2.0-MikroTik_6.49",
    "hpnssh": "SSH-2.0-OpenSSH_7.2-hpn14v5",
    "freesshd": "SSH-2.0-freeSSHd",
}

honeypots = {
    "http": {"instance": None, "thread": None, "running": False, "port": 8080, "banner_id": "apache_2441"},
    "ftp": {"instance": None, "thread": None, "running": False, "port": 21, "banner_id": "vsftpd_234"},
    "ssh": {"instance": None, "thread": None, "running": False, "port": 2222, "banner_id": "openssh_53"},
}

stats = {"http": 0, "ftp": 0, "ssh": 0, "total": 0}


def login_required(func):
    return func


def log_callback(message: str) -> None:
    service = "unknown"
    if "[HTTP]" in message:
        service = "http"
    elif "[FTP]" in message:
        service = "ftp"
    elif "[SSH]" in message:
        service = "ssh"

    if "Connection from" in message and service in stats:
        stats[service] += 1
        stats["total"] = stats["http"] + stats["ftp"] + stats["ssh"]
        socketio.emit("stats_update", stats)

    try:
        with open("honeypot_activity.log", "a", encoding="utf-8") as file_handle:
            file_handle.write(message + "\n")
    except OSError as exc:
        logger.error("Error writing to log file: %s", exc)

    socketio.emit("new_log", {"message": message})


def can_bind_port(port: int) -> bool:
    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        test_socket.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        test_socket.close()


@app.route("/")
def root():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("index.html")


@app.route("/api/config")
@login_required
def get_config():
    return jsonify(
        {
            "banners": {
                "http": [{"id": key, **value} for key, value in HTTP_BANNERS.items()],
                "ftp": [{"id": key, "label": value.replace("220 ", "")} for key, value in FTP_BANNERS.items()],
                "ssh": [{"id": key, "label": value} for key, value in SSH_BANNERS.items()],
            }
        }
    )


@app.route("/api/status")
@login_required
def get_status():
    status = {service: data["running"] for service, data in honeypots.items()}
    return jsonify(
        {
            "status": status,
            "stats": stats,
            "ports": {service: data["port"] for service, data in honeypots.items()},
            "selected_banners": {service: data["banner_id"] for service, data in honeypots.items()},
        }
    )


@app.route("/api/start/<service>", methods=["POST"])
@login_required
def start_service(service):
    if service not in honeypots:
        return jsonify({"error": "Invalid service"}), 400
    if honeypots[service]["running"]:
        return jsonify({"message": f"{service} already running"}), 200

    try:
        data = request.json or {}
        port = int(data.get("port", honeypots[service]["port"]))
        if not can_bind_port(port):
            return jsonify({"error": f"Port {port} is unavailable or blocked"}), 409

        banner_id = data.get("banner_id")
        custom_banner = (data.get("custom_banner") or "").strip()

        if service == "http":
            html_file = data.get("html_file")
            if banner_id == "custom" and custom_banner:
                http_banner = {"label": custom_banner, "server": custom_banner, "x_powered_by": "Legacy-CGI/1.1"}
            else:
                resolved_banner = banner_id if banner_id in HTTP_BANNERS else honeypots["http"]["banner_id"]
                http_banner = HTTP_BANNERS[resolved_banner]
                banner_id = resolved_banner
            hp = HTTPHoneypot(port=port, log_callback=log_callback, html_file=html_file, banner=http_banner)

        elif service == "ftp":
            ftp_files_dir = data.get("ftp_files_dir", app.config["UPLOAD_FOLDER"])
            if banner_id == "custom" and custom_banner:
                ftp_banner = f"220 {custom_banner}"
            else:
                resolved_banner = banner_id if banner_id in FTP_BANNERS else honeypots["ftp"]["banner_id"]
                ftp_banner = FTP_BANNERS[resolved_banner]
                banner_id = resolved_banner
            hp = FTPHoneypot(port=port, log_callback=log_callback, ftp_files_dir=ftp_files_dir, banner=ftp_banner)

        else:
            ssh_files_dir = data.get("ssh_files_dir", app.config["UPLOAD_FOLDER"])
            if banner_id == "custom" and custom_banner:
                ssh_banner = custom_banner if custom_banner.startswith("SSH-") else f"SSH-2.0-{custom_banner}"
            else:
                resolved_banner = banner_id if banner_id in SSH_BANNERS else honeypots["ssh"]["banner_id"]
                ssh_banner = SSH_BANNERS[resolved_banner]
                banner_id = resolved_banner
            hp = SSHHoneypot(port=port, log_callback=log_callback, banner=ssh_banner, filesystem_dir=ssh_files_dir)

        honeypots[service]["instance"] = hp
        honeypots[service]["port"] = port
        honeypots[service]["banner_id"] = banner_id or "custom"

        thread = threading.Thread(target=hp.start, daemon=True)
        thread.start()

        honeypots[service]["thread"] = thread
        honeypots[service]["running"] = True

        socketio.emit("status_update", {"service": service, "running": True, "port": port})
        return jsonify({"message": f"{service} started", "port": port})
    except Exception as exc:
        logger.error("Error starting %s: %s", service, exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stop/<service>", methods=["POST"])
@login_required
def stop_service(service):
    if service not in honeypots:
        return jsonify({"error": "Invalid service"}), 400
    if not honeypots[service]["running"]:
        return jsonify({"message": f"{service} is not running"}), 200

    try:
        if honeypots[service]["instance"]:
            honeypots[service]["instance"].stop()
        honeypots[service]["running"] = False
        honeypots[service]["instance"] = None
        honeypots[service]["thread"] = None
        socketio.emit("status_update", {"service": service, "running": False})
        return jsonify({"message": f"{service} stopped"})
    except Exception as exc:
        logger.error("Error stopping %s: %s", service, exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/logs/clear", methods=["POST"])
@login_required
def clear_logs():
    global stats
    stats = {"http": 0, "ftp": 0, "ssh": 0, "total": 0}
    try:
        with open("honeypot_activity.log", "w", encoding="utf-8"):
            pass
    except OSError as exc:
        logger.error("Could not clear log file: %s", exc)
    socketio.emit("stats_update", stats)
    socketio.emit("clear_logs")
    return jsonify({"message": "Logs cleared"})


@app.route("/api/log", methods=["POST"])
@login_required
def log_frontend_message():
    data = request.json or {}
    message = data.get("message")
    if not message:
        return jsonify({"error": "No message"}), 400
    try:
        with open("honeypot_activity.log", "a", encoding="utf-8") as file_handle:
            file_handle.write(message + "\n")
        return jsonify({"status": "logged"}), 200
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file_obj = request.files["file"]
    if not file_obj.filename:
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file_obj.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_obj.save(filepath)
    return jsonify({"message": "File uploaded successfully", "filepath": filepath, "name": filename}), 200


@app.route("/uploads/<filename>")
@login_required
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], secure_filename(filename))


@app.route("/api/uploads/list", methods=["GET"])
@login_required
def list_uploads():
    try:
        files = []
        upload_dir = app.config["UPLOAD_FOLDER"]
        for filename in os.listdir(upload_dir):
            filepath = os.path.join(upload_dir, filename)
            if os.path.isfile(filepath):
                files.append({"name": filename, "size": os.path.getsize(filepath), "url": f"/uploads/{filename}"})
        return jsonify({"files": sorted(files, key=lambda item: item["name"].lower())}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
