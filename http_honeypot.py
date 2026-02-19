import socket
import threading
from datetime import datetime
import re
from urllib.parse import parse_qs

class HTTPHoneypot:
    def __init__(self, port=8080, log_callback=None, html_file=None):
        self.port = port
        self.running = False
        self.server_socket = None
        self.log_callback = log_callback
        self.html_file = html_file
        self.html_content = self.load_html()
        
        # SQL injection patterns
        self.sql_patterns = [
            r"(\bunion\b.*\bselect\b|\bor\b.*1\s*=\s*1|;\s*drop\s+|;\s*delete\s+|UNION\s+SELECT)",
            r"(\bxp_\w+|sp_\w+|exec\(|execute\()",
            r"(--|#|/\\*|\\*/)",
            r"(\bcaast\(|\bconvert\()",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onclick\s*=",
        ]
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[HTTP] [{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_entry)
        print(log_entry)
    
    def detect_attack_type(self, data):
        """Detect attack type in the request data"""
        data_lower = data.lower()
        
        # # SQL Injection detection
        # for pattern in self.sql_patterns:
        #     if re.search(pattern, data, re.IGNORECASE):
        #         return "SQL Injection"
        
        # XSS detection
        for pattern in self.xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return "XSS Attack"
        
        # Command Injection
        if re.search(r"[;&|`$(){}[\]\\]", data):
            if re.search(r"(cat|ls|rm|wget|curl|bash|sh|nc|ncat)", data_lower):
                return "Command Injection"
        
        # Path Traversal
        if re.search(r"\.\.[\\/]|\.\.%2f|\.\.%5c|/etc/|%2e%2e", data, re.IGNORECASE):
            return "Path Traversal"
        
        # Brute Force (many common weak passwords)
        weak_passwords = ["password", "123456", "admin", "12345", "123456789", "qwerty", "abc123", "password123"]
        for weak_pass in weak_passwords:
            if weak_pass in data_lower:
                return "Brute Force Attempt"
        
        # Default suspicious
        if re.search(r"username|password", data, re.IGNORECASE):
            return "Login Attempt"
        
        return None
    
    def parse_post_data(self, request):
        """Extract POST data from HTTP request"""
        try:
            parts = request.split("\r\n\r\n", 1)
            if len(parts) > 1:
                return parts[1]
        except:
            pass
        return ""

    def extract_credentials(self, request):
        """Extract username/password safely from request body"""
        body = self.parse_post_data(request)
        if not body:
            return "unknown", "unknown"

        try:
            parsed_data = parse_qs(body, keep_blank_values=True)
            username = parsed_data.get("username", ["unknown"])[0]
            password = parsed_data.get("password", ["unknown"])[0]
            return username[:30], password[:30]
        except Exception:
            return "unknown", "unknown"
    
    def load_html(self):
        """Load HTML content from file or use default login page"""
        if self.html_file:
            try:
                with open(self.html_file, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                self.log(f"Failed to load HTML file: {e}. Using default.")
        
        # Default login/register page
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Login - Admin Panel</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .container {
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 450px;
                    padding: 40px;
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    color: #333;
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    margin-bottom: 10px;
                }
                .header p {
                    color: #666;
                    margin: 0;
                    font-size: 14px;
                }
                .tabs {
                    display: flex;
                    margin-bottom: 30px;
                    border-bottom: 2px solid #eee;
                }
                .tab-btn {
                    flex: 1;
                    padding: 15px;
                    background: none;
                    border: none;
                    cursor: pointer;
                    font-size: 14px;
                    font-weight: bold;
                    color: #999;
                    border-bottom: 3px solid transparent;
                    transition: all 0.3s;
                }
                .tab-btn.active {
                    color: #667eea;
                    border-bottom-color: #667eea;
                }
                .tab-content {
                    display: none;
                }
                .tab-content.active {
                    display: block;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 8px;
                    color: #333;
                    font-weight: bold;
                    font-size: 14px;
                }
                input {
                    width: 100%;
                    padding: 12px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 14px;
                    box-sizing: border-box;
                    transition: border-color 0.3s;
                }
                input:focus {
                    outline: none;
                    border-color: #667eea;
                }
                .btn-submit {
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                .btn-submit:hover {
                    transform: translateY(-2px);
                }
                .forgot-link {
                    text-align: right;
                    margin-top: 10px;
                }
                .forgot-link a {
                    color: #667eea;
                    text-decoration: none;
                    font-size: 12px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Secure Portal</h1>
                    <p>Admin Access Required</p>
                </div>
                
                <div class="tabs">
                    <button class="tab-btn active" onclick="switchTab('login')">Login</button>
                    <button class="tab-btn" onclick="switchTab('register')">Register</button>
                </div>

                <div id="login" class="tab-content active">
                    <form method="POST" action="/login">
                        <div class="form-group">
                            <label>Username:</label>
                            <input type="text" name="username" placeholder="Enter username" required>
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" name="password" placeholder="Enter password" required>
                        </div>
                        <button type="submit" class="btn-submit">Login</button>
                        <div class="forgot-link">
                            <a href="#">Forgot password?</a>
                        </div>
                    </form>
                </div>

                <div id="register" class="tab-content">
                    <form method="POST" action="/register">
                        <div class="form-group">
                            <label>Email:</label>
                            <input type="email" name="email" placeholder="Enter email" required>
                        </div>
                        <div class="form-group">
                            <label>Username:</label>
                            <input type="text" name="username" placeholder="Choose username" required>
                        </div>
                        <div class="form-group">
                            <label>Password:</label>
                            <input type="password" name="password" placeholder="Enter password" required>
                        </div>
                        <div class="form-group">
                            <label>Confirm Password:</label>
                            <input type="password" name="confirm_password" placeholder="Confirm password" required>
                        </div>
                        <button type="submit" class="btn-submit">Register</button>
                    </form>
                </div>
            </div>

            <script>
                function switchTab(tab) {
                    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
                    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
                    document.getElementById(tab).classList.add('active');
                    event.target.classList.add('active');
                }
            </script>
        </body>
        </html>
        """
    
    def handle_client(self, client_socket, addr):
        try:
            client_ip = addr[0]
            client_port = addr[1]
            
            # Receive the HTTP request
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            if request:
                request_line = request.split('\r\n')[0]
                self.log(f"Connection from {client_ip}:{client_port} - {request_line}")
                
                # Parse the request
                full_request = request
                
                # Detect attack type
                attack_type = self.detect_attack_type(full_request)
                
                if attack_type:
                    # Log with attack type
                    if "username=" in full_request or "password=" in full_request:
                        username, password = self.extract_credentials(full_request)
                        self.log(f"[{attack_type}] Attacker IP: {client_ip} - Username: {username}, Password: {password}")
                    else:
                        self.log(f"[{attack_type}] Attacker IP: {client_ip} - Suspicious payload detected")
                
                # Send a fake HTTP response
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "Server: Apache/2.4.29 (Ubuntu)\r\n"
                    "X-Powered-By: PHP/7.2.24\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Connection: close\r\n\r\n"
                ) + self.html_content
                client_socket.send(response.encode('utf-8', errors='ignore'))
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