import re
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, deque
import threading
import os
from flask import Flask, render_template, jsonify, request
import google.generativeai as genai

class SOCMonitor:
    def __init__(self, log_file="server_logs.txt", db_file="logs.db", gemini_api_key=None):
        self.log_file = log_file
        self.db_file = db_file
        self.running = False
        self.blocked_ips = set()
        self.ip_request_history = defaultdict(lambda: deque(maxlen=100))
        self.alert_counts = {
            "sqli": 0, "xss": 0, "ddos": 0,
            "path_traversal": 0, "command_injection": 0
        }
        self.total_requests = 0
        self.blocked_count = 0
        
        # Initialize Gemini AI
        if gemini_api_key:
            genai.configure(api_key=gemini_api_key)
            self.model = genai.GenerativeModel('gemini-flash-latest')
        else:
            self.model = None
            print("[!] Warning: Gemini API key not provided. AI analysis disabled.")
        
        # Attack patterns
        self.patterns = {
            "sqli": [
                r"(\bOR\b.*=|UNION.*SELECT|DROP.*TABLE|INSERT.*INTO|DELETE.*FROM)",
                r"('|\").*(\bOR\b|\bAND\b).*('|\")",
                r"--|\#|\/\*.*\*\/",
                r"(\bEXEC\b|\bEXECUTE\b).*\("
            ],
            "xss": [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<.*?(iframe|embed|object).*?>"
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"/etc/shadow",
                r"\.\..*\.\."
            ],
            "command_injection": [
                r"[;&|`$].*?(cat|ls|whoami|wget|curl|nc|bash|sh)",
                r"\|\s*(cat|ls|whoami)",
                r"&&.*\w+"
            ]
        }
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                method TEXT,
                endpoint TEXT,
                status_code INTEGER,
                response_size INTEGER,
                threat_type TEXT,
                blocked INTEGER,
                created_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                blocked_at TEXT,
                auto_blocked INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                alert_type TEXT,
                description TEXT,
                severity TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        print(f"[*] Database initialized: {self.db_file}")
    
    def parse_log_line(self, line):
        """Parse Apache-style log line"""
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (.*?) HTTP/\S+" (\d+) (\d+)'
        match = re.match(pattern, line)
        
        if match:
            return {
                "ip": match.group(1),
                "timestamp": match.group(2),
                "method": match.group(3),
                "endpoint": match.group(4),
                "status_code": int(match.group(5)),
                "response_size": int(match.group(6))
            }
        return None
    
    def detect_threat(self, log_data):
        """Detect security threats in log entry"""
        endpoint = log_data["endpoint"]
        threats = []
        
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    threats.append(threat_type)
                    break
        
        return threats
    
    def check_ddos(self, ip):
        """Check for DDoS patterns"""
        current_time = time.time()
        self.ip_request_history[ip].append(current_time)
        
        # Check requests in last 1 second
        recent_requests = [t for t in self.ip_request_history[ip] if current_time - t <= 1.0]
        
        if len(recent_requests) > 10:
            return True
        return False
    
    def block_ip(self, ip, reason, auto_blocked=True):
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.blocked_count += 1
            
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO blocked_ips (ip, reason, blocked_at, auto_blocked)
                VALUES (?, ?, ?, ?)
            """, (ip, reason, datetime.now().isoformat(), 1 if auto_blocked else 0))
            conn.commit()
            conn.close()
            
            print(f"[🚫] IP Blocked: {ip} - Reason: {reason}")
            self.log_alert(ip, "IP_BLOCKED", reason, "HIGH")
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            
            print(f"[✓] IP Unblocked: {ip}")
            return True
        return False
    
    def log_alert(self, ip, alert_type, description, severity):
        """Log security alert"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, ip, alert_type, description, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), ip, alert_type, description, severity))
        conn.commit()
        conn.close()
    
    def store_log(self, log_data, threats):
        """Store log entry in database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        threat_type = ",".join(threats) if threats else None
        blocked = 1 if log_data["ip"] in self.blocked_ips else 0
        
        cursor.execute("""
            INSERT INTO logs (timestamp, ip, method, endpoint, status_code, 
                            response_size, threat_type, blocked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_data["timestamp"], log_data["ip"], log_data["method"],
            log_data["endpoint"], log_data["status_code"], log_data["response_size"],
            threat_type, blocked, datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def analyze_with_gemini(self, log_entries):
        """Analyze logs using Gemini AI"""
        if not self.model:
            return "AI analysis not available (API key not configured)"
        
        try:
            prompt = f"""You are a cybersecurity analyst. Analyze these server logs and provide a security report in HTML format (no markdown code blocks, just raw HTML).
            
            Use these sections:
            1. <h4>Summary of Threats</h4> (Bulleted list)
            2. <h4>Risk Assessment</h4> (High/Medium/Low with reasoning)
            3. <h4>Recommended Actions</h4> (Actionable steps)
            
            Logs:
            {chr(10).join(log_entries[:20])}
            
            Keep the analysis professional, concise, and easy to read. Use <span class="badge-danger"> for high severity items."""
            
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"AI analysis error: {str(e)}"
    
    def monitor_logs(self):
        """Monitor log file in real-time"""
        print(f"[*] Starting log monitoring...")
        
        # Load existing blocked IPs
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM blocked_ips")
        self.blocked_ips = set(row[0] for row in cursor.fetchall())
        conn.close()
        
        if not os.path.exists(self.log_file):
            open(self.log_file, 'a').close()
        
        with open(self.log_file, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    self.total_requests += 1
                    log_data = self.parse_log_line(line.strip())
                    
                    if log_data:
                        ip = log_data["ip"]
                        
                        # Check if IP is blocked
                        if ip in self.blocked_ips:
                            self.store_log(log_data, ["BLOCKED"])
                            continue
                        
                        # Detect threats
                        threats = self.detect_threat(log_data)
                        
                        # Check for DDoS
                        if self.check_ddos(ip):
                            threats.append("ddos")
                            self.block_ip(ip, "DDoS Attack - >10 requests/second", auto_blocked=True)
                            self.alert_counts["ddos"] += 1
                        
                        # Log threats
                        if threats:
                            for threat in threats:
                                if threat in self.alert_counts:
                                    self.alert_counts[threat] += 1
                            
                            severity = "HIGH" if len(threats) > 1 else "MEDIUM"
                            self.log_alert(ip, threats[0].upper(), 
                                         f"Detected: {', '.join(threats)}", severity)
                            
                            print(f"[⚠️] {ip} - {', '.join(threats).upper()} - {log_data['endpoint'][:60]}")
                        
                        # Store in database
                        self.store_log(log_data, threats)
                else:
                    time.sleep(0.1)
    
    def start(self):
        """Start monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self.monitor_logs, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()
    
    def get_stats(self):
        """Get monitoring statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Recent threats
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM logs
            WHERE threat_type IS NOT NULL
            AND created_at > datetime('now', '-1 hour')
            GROUP BY threat_type
        """)
        recent_threats = cursor.fetchall()
        
        # Recent alerts
        cursor.execute("""
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT 10
        """)
        recent_alerts = cursor.fetchall()
        
        # Blocked IPs
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
        blocked_ips = cursor.fetchall()
        
        # Traffic history (requests per minute)
        cursor.execute("""
            SELECT strftime('%H:%M', created_at) as time_bucket, COUNT(*)
            FROM logs 
            WHERE created_at > datetime('now', '-1 hour')
            GROUP BY time_bucket
            ORDER BY time_bucket
        """)
        traffic_history = cursor.fetchall()

        # Threat distribution
        cursor.execute("""
            SELECT threat_type, COUNT(*) 
            FROM logs 
            WHERE threat_type IS NOT NULL 
            GROUP BY threat_type
        """)
        threat_distribution = cursor.fetchall()
        
        conn.close()
        
        return {
            "total_requests": self.total_requests,
            "alert_counts": self.alert_counts,
            "blocked_count": len(self.blocked_ips),
            "recent_threats": recent_threats,
            "recent_alerts": recent_alerts,
            "blocked_ips": blocked_ips,
            "traffic_history": traffic_history,
            "threat_distribution": threat_distribution
        }

# Flask Web Dashboard
app = Flask(__name__)
monitor = None

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    if monitor:
        return jsonify(monitor.get_stats())
    return jsonify({"error": "Monitor not running"})

@app.route('/api/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block')
    
    if monitor and ip:
        monitor.block_ip(ip, reason, auto_blocked=False)
        return jsonify({"success": True, "message": f"IP {ip} blocked"})
    return jsonify({"success": False, "message": "Invalid request"})

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    
    if monitor and ip:
        success = monitor.unblock_ip(ip)
        return jsonify({"success": success, "message": f"IP {ip} unblocked" if success else "IP not found"})
    return jsonify({"success": False, "message": "Invalid request"})

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    if not monitor or not monitor.model:
        return jsonify({"error": "AI analysis not available"})
    
    conn = sqlite3.connect(monitor.db_file)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, method, endpoint, threat_type
        FROM logs
        WHERE created_at > datetime('now', '-10 minutes')
        ORDER BY created_at DESC
        LIMIT 50
    """)
    
    logs = [f"{row[0]} {row[1]} {row[2]} {row[3] or 'normal'}" for row in cursor.fetchall()]
    conn.close()
    
    analysis = monitor.analyze_with_gemini(logs)
    return jsonify({"analysis": analysis})

if __name__ == "__main__":
    import sys
    
    # Get Gemini API key from command line, environment, or file
    api_key = sys.argv[1] if len(sys.argv) > 1 else (os.getenv('GEMINI_API_KEY') or os.getenv('GEMINI_API')) or os.getenv('GEMINI_API')
    
    if not api_key:
        try:
            if os.path.exists("api_key.txt"):
                    if content and content != "PASTE_YOUR_GEMINI_API_KEY_HERE":
                        api_key = content
                        print(f"[*] Loaded Gemini API key from api_key.txt")
        except Exception as e:
            print(f"[!] Error reading api_key.txt: {e}")

    if not api_key:
        print("[!] Warning: No Gemini API key provided.")
        print("Usage: python soc_monitor.py YOUR_GEMINI_API_KEY")
        print("Or set GEMINI_API_KEY environment variable")
        print("Or paste key in api_key.txt")
    
    monitor = SOCMonitor(gemini_api_key=api_key)
    monitor.start()
    
    print("\n" + "="*60)
    print("🔐 SOC MONITORING DASHBOARD STARTED")
    print("="*60)
    print(f"📊 Dashboard: http://localhost:5000")
    print(f"💾 Database: {monitor.db_file}")
    print(f"📝 Log file: {monitor.log_file}")
    print("="*60 + "\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor...")
        monitor.stop()
        print("[*] Monitor stopped.")