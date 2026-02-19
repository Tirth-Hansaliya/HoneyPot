import socket
import threading
import os
from datetime import datetime

class FTPHoneypot:
    def __init__(self, port=2121, log_callback=None, ftp_files_dir='uploads'):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        self.ftp_files_dir = ftp_files_dir
        self.anonymous_login = True  # Allow anonymous login
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[FTP] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)
    
    def get_file_list(self):
        """Get list of files in FTP directory to show attackers"""
        file_list = ""
        try:
            if os.path.exists(self.ftp_files_dir):
                for filename in os.listdir(self.ftp_files_dir):
                    filepath = os.path.join(self.ftp_files_dir, filename)
                    if os.path.isfile(filepath):
                        size = os.path.getsize(filepath)
                        # FTP LIST format: -rw-r--r-- 1 ftp ftp size date filename
                        file_list += f"-rw-r--r--   1 ftp  ftp  {size:8d} Jan 01 12:00 {filename}\r\n"
        except Exception as e:
            self.log(f"Error listing files: {e}")
        
        if not file_list:
            file_list = "-rw-r--r--   1 ftp  ftp      1024 Jan 01 12:00 welcome.txt\r\n"
        
        return file_list
    
    def handle_client(self, client_socket, addr):
        try:
            self.log(f"Connection from {addr[0]}:{addr[1]}")
            
            # Send FTP welcome banner with vulnerable version
            client_socket.send(b"220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n")
            
            while self.running:
                try:
                    data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not data:
                        break
                    
                    self.log(f"Command from {addr[0]}: {data}")
                    
                    # Parse FTP commands
                    cmd = data.split()[0].upper() if data.split() else ""
                    
                    if cmd == "USER":
                        username = data.split()[1] if len(data.split()) > 1 else "unknown"
                        self.log(f"Username attempt from {addr[0]}: {username}")
                        # Allow anonymous login
                        if username.lower() in ['anonymous', 'ftp']:
                            client_socket.send(b"331 Anonymous login ok, send your complete email address as password\r\n")
                        else:
                            client_socket.send(b"331 Password required\r\n")
                    elif cmd == "PASS":
                        password = data.split()[1] if len(data.split()) > 1 else "unknown"
                        self.log(f"Password attempt from {addr[0]}: {password}")
                        if self.anonymous_login:
                            client_socket.send(b"230 Anonymous access granted\r\n")
                            self.log(f"Anonymous login from {addr[0]}")
                        else:
                            client_socket.send(b"530 Login incorrect\r\n")
                    elif cmd == "SYST":
                        client_socket.send(b"215 UNIX Type: L8\r\n")
                    elif cmd == "PWD":
                        client_socket.send(b"257 \"/\" is current directory\r\n")
                    elif cmd == "TYPE":
                        client_socket.send(b"200 Type set to I\r\n")
                    elif cmd == "PASV":
                        client_socket.send(b"227 Entering Passive Mode (127,0,0,1,30,39)\r\n")
                    elif cmd == "LIST" or cmd == "NLST":
                        # List files in uploads directory
                        file_list = self.get_file_list()
                        self.log(f"File listing requested from {addr[0]}")
                        client_socket.send(f"150 Here comes the directory listing\r\n".encode())
                        client_socket.send(file_list.encode())
                        client_socket.send(b"226 Directory send OK\r\n")
                    elif cmd == "RETR":
                        # File download attempt
                        filename = data.split()[1] if len(data.split()) > 1 else "unknown"
                        self.log(f"[FTP Download Attempt] Attacker IP: {addr[0]} - File: {filename} - Port: {self.port}")
                        client_socket.send(b"550 Failed to open file\r\n")
                    elif cmd == "STOR":
                        # File upload - accept and simulate file storage
                        filename = data.split()[1] if len(data.split()) > 1 else "file.txt"
                        self.log(f"File upload from {addr[0]}: {filename}")
                        try:
                            # Create uploads directory if it doesn't exist
                            if not os.path.exists(self.ftp_files_dir):
                                os.makedirs(self.ftp_files_dir)
                            
                            # Accept upload and simulate receiving data
                            filepath = os.path.join(self.ftp_files_dir, filename)
                            client_socket.send(b"150 Ok to send data\r\n")
                            
                            # Receive file data
                            file_data = b""
                            client_socket.settimeout(5.0)
                            try:
                                while True:
                                    chunk = client_socket.recv(4096)
                                    if not chunk:
                                        break
                                    file_data += chunk
                            except socket.timeout:
                                pass
                            finally:
                                client_socket.settimeout(30.0)
                            
                            # Write file to disk
                            with open(filepath, 'wb') as f:
                                f.write(file_data if file_data else b"uploaded content")
                            
                            self.log(f"File stored: {filename} ({len(file_data)} bytes) from {addr[0]}")
                            client_socket.send(b"226 Transfer complete\r\n")
                        except Exception as e:
                            self.log(f"Error storing file: {e}")
                            client_socket.send(b"550 Error storing file\r\n")
                    elif cmd == "QUIT":
                        client_socket.send(b"221 Goodbye\r\n")
                        break
                    else:
                        client_socket.send(b"502 Command not implemented\r\n")
                except socket.timeout:
                    break
                except Exception as e:
                    self.log(f"Error in command loop: {e}")
                    break
        except Exception as e:
            self.log(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            self.running = True
            self.log(f"Started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_socket.settimeout(30.0)
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"Error: {e}")
        except Exception as e:
            self.log(f"Failed to start: {e}")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.log("Stopped")