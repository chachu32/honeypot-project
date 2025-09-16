#!/usr/bin/env python3
"""
Multi-Service Honeypot
A customizable honeypot that simulates multiple services for educational purposes.

WARNING: This is for educational and research purposes only. Deploy in isolated environments.
"""

import socket
import threading
import time
import logging
import json
import argparse
import signal
import sys
from datetime import datetime
import re

class HoneypotLogger:
    """Centralized logging system for the honeypot"""
    
    def __init__(self, log_file='honeypot.log'):
        self.log_file = log_file
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_connection(self, service, client_ip, client_port, data=None):
        """Log connection attempts"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'service': service,
            'client_ip': client_ip,
            'client_port': client_port,
            'data': data
        }
        self.logger.info(f"Connection to {service} from {client_ip}:{client_port}")
        if data:
            self.logger.info(f"Data received: {data}")
        
        # Also save to JSON for analysis
        with open('honeypot_data.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

class SSHHoneypot:
    """SSH service honeypot"""
    
    def __init__(self, host='0.0.0.0', port=2222, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
        self.banner = "SSH-2.0-OpenSSH_7.4"
    
    def handle_client(self, client_socket, client_address):
        """Handle SSH client connections"""
        try:
            client_socket.send(f"{self.banner}\r\n".encode())
            
            while True:
                data = client_socket.recv(1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                self.logger.log_connection('SSH', client_address[0], client_address[1], data.strip())
                
                # Simulate authentication failure
                if 'ssh-userauth' in data.lower():
                    client_socket.send(b"Permission denied\r\n")
                    break
                
        except Exception as e:
            self.logger.logger.error(f"SSH handler error: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start the SSH honeypot"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        self.logger.logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                self.logger.logger.error(f"SSH server error: {e}")

class HTTPHoneypot:
    """HTTP service honeypot"""
    
    def __init__(self, host='0.0.0.0', port=8080, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
    
    def handle_client(self, client_socket, client_address):
        """Handle HTTP client connections"""
        try:
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            if not request:
                return
            
            self.logger.log_connection('HTTP', client_address[0], client_address[1], request)
            
            # Parse request for interesting patterns
            self.analyze_http_request(request, client_address)
            
            # Send fake response
            response = self.generate_response(request)
            client_socket.send(response.encode())
            
        except Exception as e:
            self.logger.logger.error(f"HTTP handler error: {e}")
        finally:
            client_socket.close()
    
    def analyze_http_request(self, request, client_address):
        """Analyze HTTP request for attack patterns"""
        lines = request.split('\n')
        if lines:
            request_line = lines[0]
            
            # Check for common attack patterns
            suspicious_patterns = [
                r'\.\./', r'<script', r'union.*select', r'exec\(', 
                r'system\(', r'cmd=', r'phpinfo', r'eval\('
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    self.logger.logger.warning(
                        f"Suspicious HTTP request from {client_address[0]}: {pattern}"
                    )
    
    def generate_response(self, request):
        """Generate appropriate HTTP response"""
        lines = request.split('\n')
        if not lines:
            return "HTTP/1.1 400 Bad Request\r\n\r\n"
        
        request_line = lines[0]
        
        # Basic routing
        if 'GET / ' in request_line:
            return self.get_index_response()
        elif 'GET /admin' in request_line:
            return self.get_admin_response()
        else:
            return "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>"
    
    def get_index_response(self):
        """Generate index page response"""
        html = """<!DOCTYPE html>
<html>
<head><title>Server Status</title></head>
<body>
<h1>Server Running</h1>
<p>System operational.</p>
</body>
</html>"""
        
        response = f"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: {len(html)}\r
Server: Apache/2.4.41\r
\r
{html}"""
        return response
    
    def get_admin_response(self):
        """Generate admin panel response"""
        return """HTTP/1.1 401 Unauthorized\r
WWW-Authenticate: Basic realm="Admin Panel"\r
\r
<h1>401 Unauthorized</h1>"""
    
    def start(self):
        """Start the HTTP honeypot"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        self.logger.logger.info(f"HTTP Honeypot listening on {self.host}:{self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                self.logger.logger.error(f"HTTP server error: {e}")

class FTPHoneypot:
    """FTP service honeypot"""
    
    def __init__(self, host='0.0.0.0', port=2121, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
    
    def handle_client(self, client_socket, client_address):
        """Handle FTP client connections"""
        try:
            # Send FTP banner
            client_socket.send(b"220 FTP Server Ready\r\n")
            
            authenticated = False
            username = None
            
            while True:
                data = client_socket.recv(1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                command = data.strip().upper()
                self.logger.log_connection('FTP', client_address[0], client_address[1], data.strip())
                
                if command.startswith('USER '):
                    username = command[5:]
                    client_socket.send(b"331 Password required\r\n")
                elif command.startswith('PASS '):
                    password = command[5:]
                    self.logger.logger.info(f"FTP login attempt: {username}:{password}")
                    client_socket.send(b"530 Login incorrect\r\n")
                elif command == 'QUIT':
                    client_socket.send(b"221 Goodbye\r\n")
                    break
                else:
                    client_socket.send(b"500 Unknown command\r\n")
                    
        except Exception as e:
            self.logger.logger.error(f"FTP handler error: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start the FTP honeypot"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        self.logger.logger.info(f"FTP Honeypot listening on {self.host}:{self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                self.logger.logger.error(f"FTP server error: {e}")

class TelnetHoneypot:
    """Telnet service honeypot"""
    
    def __init__(self, host='0.0.0.0', port=2323, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
    
    def handle_client(self, client_socket, client_address):
        """Handle Telnet client connections"""
        try:
            client_socket.send(b"Login: ")
            
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            if not username:
                return
            
            client_socket.send(b"Password: ")
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            self.logger.log_connection('Telnet', client_address[0], client_address[1], 
                                     f"Username: {username}, Password: {password}")
            
            client_socket.send(b"Login incorrect\r\n")
            
        except Exception as e:
            self.logger.logger.error(f"Telnet handler error: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start the Telnet honeypot"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        self.logger.logger.info(f"Telnet Honeypot listening on {self.host}:{self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                self.logger.logger.error(f"Telnet server error: {e}")

class HoneypotManager:
    """Main honeypot management class"""
    
    def __init__(self):
        self.logger = HoneypotLogger()
        self.services = []
        self.running = True
    
    def add_service(self, service_class, *args, **kwargs):
        """Add a service to the honeypot"""
        service = service_class(*args, logger=self.logger, **kwargs)
        self.services.append(service)
        return service
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.logger.info("Shutting down honeypot...")
        self.running = False
        sys.exit(0)
    
    def start_all(self):
        """Start all configured services"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Start each service in its own thread
        for service in self.services:
            thread = threading.Thread(target=service.start)
            thread.daemon = True
            thread.start()
        
        self.logger.logger.info("All honeypot services started")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Multi-Service Honeypot')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--ssh-port', type=int, default=2222, help='SSH port')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP port')
    parser.add_argument('--ftp-port', type=int, default=2121, help='FTP port')
    parser.add_argument('--telnet-port', type=int, default=2323, help='Telnet port')
    parser.add_argument('--services', nargs='+', 
                       choices=['ssh', 'http', 'ftp', 'telnet'], 
                       default=['ssh', 'http', 'ftp', 'telnet'],
                       help='Services to enable')
    
    args = parser.parse_args()
    
    manager = HoneypotManager()
    
    # Add selected services
    if 'ssh' in args.services:
        manager.add_service(SSHHoneypot, args.host, args.ssh_port)
    if 'http' in args.services:
        manager.add_service(HTTPHoneypot, args.host, args.http_port)
    if 'ftp' in args.services:
        manager.add_service(FTPHoneypot, args.host, args.ftp_port)
    if 'telnet' in args.services:
        manager.add_service(TelnetHoneypot, args.host, args.telnet_port)
    
    print("=" * 50)
    print("Multi-Service Honeypot")
    print("=" * 50)
    print("WARNING: For educational purposes only!")
    print("Deploy only in isolated environments.")
    print("=" * 50)
    
    manager.start_all()

if __name__ == "__main__":
    main()