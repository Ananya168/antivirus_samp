import os
import time
from typing import List, Dict

class RealTimeFileMonitor:
    def __init__(self, scanner):
        self.scanner = scanner
        self.monitored_dirs = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"), 
            os.path.expanduser("~/Documents")
        ]
        self.is_monitoring = False
        self.alerts = []
        
    def start_monitoring(self):
        """Start real-time file monitoring (simulated)"""
        if self.is_monitoring:
            return False
            
        self.is_monitoring = True
        self.alerts.append("🛡️ Real-time file monitoring started")
        self.alerts.append(f"📁 Monitoring directories: {', '.join(self.monitored_dirs)}")
        return True
        
    def stop_monitoring(self):
        """Stop real-time file monitoring"""
        if not self.is_monitoring:
            return False
            
        self.is_monitoring = False
        self.alerts.append("🛑 Real-time file monitoring stopped")
        return True
        
    def scan_new_file(self, file_path):
        """Simulate scanning a new file"""
        if self.is_monitoring and os.path.exists(file_path):
            result = self.scanner.scan_file(file_path)
            if result["status"] == "INFECTED":
                alert_msg = f"🚨 THREAT DETECTED: {file_path}"
                self.alerts.append(alert_msg)
                return alert_msg
            else:
                self.alerts.append(f"✅ File safe: {os.path.basename(file_path)}")
        return None
        
    def get_alerts(self):
        """Get recent alerts"""
        alerts = self.alerts.copy()
        self.alerts = []  # Clear alerts after reading
        return alerts