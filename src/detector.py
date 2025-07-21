import re
import time
from datetime import datetime
from collections import defaultdict

# Define the structure of a security incident
class Incident:
    def __init__(self, timestamp, category, severity, message):
        self.timestamp = timestamp
        self.category = category    # e.g., "failed_login", "sudo", "unauthorized"
        self.severity = severity    # "low", "medium", "high"
        self.message = message
    
    def __repr__(self):
        return f"[{self.timestamp}] ({self.severity.upper()}) {self.category}: {self.message}"


class Detector:
    def __init__(self):
        self.incidents = []

    def get_incidents(self):
        """Return the list of detected incidents"""
        return self.incidents

    def scan(self, log_type="auth", watch=False):
        """Scan the specified log file once or continuously."""
        path = "/var/log/auth.log" if log_type == "auth"  else "/var/log/syslog"

        if watch:
            self._watch_log(path)
        else:
            self._parse_log(path)

    def _parse_log(self, filepath):
        """Read the log file and detect suspicious events."""
        try:
            with open(filepath, "r") as f:
                for line in f:
                    self._analyze_line(line)
        
        except FileNotFoundError:
            print(f"[!] Log file not found: {filepath}")

        except PermissionError:
            print(f"[!] Permission denied when accessing: {filepath}")
    
    def _watch_log(self, filepath):
        """Continuously watch the log file for new entries (like tail -f)."""
        print(f"Watching {filepath} ...")
        try:
            with open(filepath, "r") as f:
                # seek to end of file
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue

                    self._analyze_line(line)
        
        except Exception as e:
            print(f"[!] Error watching log: {e}")

    
    def _analyze_line(self, line):
        """Apply regex rules to detect specific suspicious patterns."""

        ts = self._extract_timestamp(line)
        msg = line.strip()
        
        # detect failed SSH login attempts
        if "Failed password for" in line:
            self.incidents.append(
                Incident(ts, "failed_login", "medium", msg)
            )

            # Brute-force detection by IP
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                if not hasattr(self, "_fail_counter"):
                    self._fail_counter = {}

                self._fail_counter.setdefault(ip, []).append(ts)
                
                # If more than 5 failures within short time window
                if len(self._fail_counter[ip]) >= 5:
                    self.incidents.append(
                        Incident(ts, "brute_force", "high", f"Muptiple failed logins from {ip}")
                    )
                    self._fail_counter[ip] = {} # reset counter for this IP



        # detect successful sudo usage
        elif "sudo:" in line and "COMMAND=" in line:
            self.incidents.append(
                Incident(ts, "sudo_command", "low", msg)
            )

        # detect user not in sudoers
        elif "user is not in the sudoers file" in line:
            self.incidents.append(
                Incident(ts, "unauthorized_sudo", "high", msg)
            )

        # Detect new user added
        elif re.search(r'new user: name=', line) or "useradd" in line:
            self.incidents.append(
                Incident(ts, "account_change", "medium", msg)
            )

        # Detect package installation (apt/yum/dnf)
        elif re.search(r'apt{-get}? install|dnf install|yum install', line):
            self.incidents.append(
                Incident(ts, "package_activity", "medium", msg)
            )

    
    def _extract_timestamp(self, line):
        """Extract timestamp from log line and normalize to ISO format."""
        try:
            # Example format: "Jul 21 18:43:55"
            ts_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            if ts_match:
                dt = datetime.strptime(ts_match.group(1),"%b %d %H:%M:%S")
                # patch current year (since logs don't include it)
                dt = dt.replace(year=datetime.now().year)
                return dt.isoformat()
        
        except:
            pass

        return datetime.now().isoformat()