import socket
import threading
import time
from typing import Dict, List
import psutil

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ports = [4444, 31337, 12345, 54321]  # Common backdoor ports
        self.suspicious_ips = []
        self.connection_log = []
        self.is_monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start network monitoring"""
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_network)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
    def _monitor_network(self):
        """Monitor network connections"""
        while self.is_monitoring:
            try:
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        # Check for suspicious ports
                        if conn.laddr.port in self.suspicious_ports or conn.raddr.port in self.suspicious_ports:
                            alert = {
                                'type': 'SUSPICIOUS_PORT',
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                                'timestamp': time.time()
                            }
                            self.connection_log.append(alert)
                            
                        # Check for unusual connections
                        if self._is_unusual_connection(conn):
                            alert = {
                                'type': 'UNUSUAL_CONNECTION',
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                                'timestamp': time.time()
                            }
                            self.connection_log.append(alert)
                            
            except Exception as e:
                print(f"Network monitoring error: {e}")
                
            time.sleep(5)  # Check every 5 seconds
            
    def _is_unusual_connection(self, conn) -> bool:
        """Detect unusual network connections"""
        # Add your detection logic here
        # Example: Check for connections to known malicious IPs
        if conn.raddr and conn.raddr.ip in self.suspicious_ips:
            return True
        return False
        
    def get_network_alerts(self) -> List[Dict]:
        """Get recent network alerts"""
        recent_alerts = [alert for alert in self.connection_log 
                        if time.time() - alert['timestamp'] < 3600]  # Last hour
        return recent_alerts
        
    def add_suspicious_ip(self, ip: str):
        """Add IP to suspicious list"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips.append(ip)