import socket
import threading
from datetime import datetime

class SSHHoneypot:
    def __init__(self, port=2222, log_callback=None):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[SSH] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)
    
    def handle_client(self, client_socket, addr):
        try:
            self.log(f"Connection from {addr[0]}:{addr[1]}")
            
            # Send SSH banner with vulnerable OpenSSH version
            banner = b"SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7\r\n"
            client_socket.send(banner)
            
            # Try to receive client data
            try:
                client_socket.settimeout(10.0)
                data = client_socket.recv(1024)
                if data:
                    self.log(f"Client banner from {addr[0]}: {data.decode('utf-8', errors='ignore').strip()}")
                    
                    # Log the connection attempt
                    self.log(f"SSH negotiation attempt from {addr[0]}")
                    
                    # Send key exchange init (simplified)
                    # In a real SSH connection, this would be much more complex
                    # We're just simulating the initial stages
                    
            except socket.timeout:
                self.log(f"Timeout from {addr[0]}")
            except Exception as e:
                self.log(f"Error receiving from {addr[0]}: {e}")
                
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