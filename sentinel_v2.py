import re
import os
import time
import json
import requests
from datetime import datetime
from pathlib import Path

# --- CONFIGURATION ---
LOG_FILE_PATH = "access.log"
REPORT_FILE = "threat_report.json"
FAILED_THRESHOLD = 3
# Using a free, no-key-required API for demo purposes
GEO_API_URL = "http://ip-api.com/json/"

class SecuritySentinel:
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.failed_attempts = {}
        self.reported_ips = set() # Avoid duplicate alerts
        
        # Regex to extract IP from failed SSH attempts
        self.pattern = re.compile(r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    def get_ip_intel(self, ip):
        """Fetches Geolocation and ISP data for a suspicious IP."""
        try:
            response = requests.get(f"{GEO_API_URL}{ip}", timeout=5)
            if response.status_status == 200:
                data = response.json()
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown")
                }
        except:
            return {"country": "Error", "city": "Error", "isp": "Error"}

    def log_incident(self, ip, count):
        """Creates a structured JSON report for the detected threat."""
        intel = self.get_ip_intel(ip)
        incident = {
            "timestamp": datetime.now().isoformat(),
            "ip_address": ip,
            "failed_attempts": count,
            "geo_location": f"{intel['city']}, {intel['country']}",
            "isp": intel['isp'],
            "severity": "HIGH"
        }
        
        # Write to JSON file (Append mode logic)
        feeds = []
        if os.path.exists(REPORT_FILE):
            with open(REPORT_FILE, "r") as f:
                try: feeds = json.load(f)
                except: feeds = []
        
        feeds.append(incident)
        with open(REPORT_FILE, "w") as f:
            json.dump(feeds, indent=4, fp=f)
        
        return incident

    def monitor(self):
        """Monitors the log file in real-time (similar to tail -f)."""
        print(f"[*] Sentinel Active. Monitoring {self.log_path}...")
        
        # Move to the end of the file so we only process NEW entries
        with open(self.log_path, "r") as f:
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1) # Wait for new log entries
                    continue

                match = self.pattern.search(line)
                if match:
                    ip = match.group(1)
                    self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1
                    
                    # Check if threshold reached
                    if self.failed_attempts[ip] >= FAILED_THRESHOLD and ip not in self.reported_ips:
                        print(f"\n[!] ALERT: Brute force detected from {ip}!")
                        incident = self.log_incident(ip, self.failed_attempts[ip])
                        print(f"    Location: {incident['geo_location']}")
                        print(f"    ISP: {incident['isp']}")
                        print(f"    Report saved to {REPORT_FILE}")
                        
                        self.reported_ips.add(ip)

if __name__ == "__main__":
    # Ensure the log file exists before starting
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w") as f: f.write("") 
        
    sentinel = SecuritySentinel(LOG_FILE_PATH)
    try:
        sentinel.monitor()
    except KeyboardInterrupt:
        print("\n[+] Sentinel shutting down safely.")