import socket
from typing import List, Dict

class SimpleFirewall:
    def __init__(self):
        self.blocked_ips = []
        self.blocked_ports = []
        
    def block_ip(self, ip_address: str) -> bool:
        """Block a specific IP address (simulated)"""
        if ip_address in self.blocked_ips:
            return False
            
        # Validate IP format
        try:
            socket.inet_aton(ip_address)
            self.blocked_ips.append(ip_address)
            return True
        except socket.error:
            return False
    
    def block_port(self, port: int) -> bool:
        """Block a specific port (simulated)"""
        try:
            port = int(port)
            if 1 <= port <= 65535 and port not in self.blocked_ports:
                self.blocked_ports.append(port)
                return True
        except:
            pass
        return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            return True
        return False
    
    def unblock_port(self, port: int) -> bool:
        """Unblock a port"""
        if port in self.blocked_ports:
            self.blocked_ports.remove(port)
            return True
        return False
    
    def get_blocked_items(self) -> Dict:
        """Get list of blocked IPs and ports"""
        return {
            'blocked_ips': self.blocked_ips,
            'blocked_ports': self.blocked_ports
        }
    
    def check_connection(self, ip: str, port: int) -> bool:
        """Check if a connection would be blocked"""
        return ip in self.blocked_ips or port in self.blocked_ports