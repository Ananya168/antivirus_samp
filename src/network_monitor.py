import socket
import time
import subprocess
import platform
from typing import List, Dict
import threading

class NetworkMonitor:
    def __init__(self):
        self.suspicious_ports = [4444, 31337, 1337, 12345, 54321, 9999]
        self.suspicious_processes = ['nc.exe', 'ncat.exe', 'telnet.exe', 'backdoor.exe']
        self.connection_log = []
        self.is_monitoring = False
        
    def get_network_connections(self) -> List[Dict]:
        """Get current network connections"""
        connections = []
        try:
            if platform.system() == "Windows":
                connections = self._get_windows_connections()
            else:
                connections = self._get_unix_connections()
        except Exception as e:
            print(f"Network connection error: {e}")
        return connections
    
    def _get_windows_connections(self) -> List[Dict]:
        """Get network connections on Windows"""
        connections = []
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'TCP' in line or 'UDP' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        conn_info = {
                            'protocol': parts[0],
                            'local_address': parts[1] if len(parts) > 1 else '',
                            'remote_address': parts[2] if len(parts) > 2 else '',
                            'state': parts[3] if len(parts) > 3 else '',
                            'timestamp': time.time()
                        }
                        connections.append(conn_info)
        except Exception as e:
            print(f"Windows connection error: {e}")
        return connections
    
    def _get_unix_connections(self) -> List[Dict]:
        """Get network connections on Unix-like systems"""
        connections = []
        try:
            result = subprocess.run(['netstat', '-tunap'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'tcp' in line or 'udp' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        conn_info = {
                            'protocol': parts[0],
                            'local_address': parts[3],
                            'remote_address': parts[4] if len(parts) > 4 else '',
                            'state': parts[5] if len(parts) > 5 else '',
                            'timestamp': time.time()
                        }
                        connections.append(conn_info)
        except Exception as e:
            print(f"Unix connection error: {e}")
        return connections
    
    def analyze_connections(self, connections: List[Dict]) -> List[Dict]:
        """Analyze connections for suspicious activity"""
        alerts = []
        for conn in connections:
            local_port = self._extract_port(conn['local_address'])
            remote_port = self._extract_port(conn['remote_address'])
            
            if local_port in self.suspicious_ports or remote_port in self.suspicious_ports:
                alerts.append({
                    'type': 'SUSPICIOUS_PORT',
                    'local_address': conn['local_address'],
                    'remote_address': conn['remote_address'],
                    'port': local_port if local_port in self.suspicious_ports else remote_port,
                    'timestamp': time.time(),
                    'severity': 'HIGH'
                })
        return alerts
    
    def _extract_port(self, address: str) -> int:
        """Extract port number from address string"""
        try:
            if ':' in address:
                return int(address.split(':')[-1])
        except:
            pass
        return 0
    
    def quick_port_scan(self, target_ip: str = "127.0.0.1") -> List[Dict]:
        """FAST port scan - optimized for speed"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        results = []
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0)
                    start_time = time.time()
                    result = sock.connect_ex((target_ip, port))
                    response_time = time.time() - start_time
                    
                    status = 'OPEN' if result == 0 else 'CLOSED'
                    service = self._get_service_name(port)
                    
                    results.append({
                        'port': port,
                        'status': status,
                        'service': service,
                        'response_time': round(response_time, 3),
                        'timestamp': time.time()
                    })
            except socket.timeout:
                results.append({
                    'port': port,
                    'status': 'TIMEOUT',
                    'service': self._get_service_name(port),
                    'response_time': 1.0,
                    'timestamp': time.time()
                })
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'ERROR',
                    'service': self._get_service_name(port),
                    'error': str(e),
                    'timestamp': time.time()
                })
        return results
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS',
            3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            3306: 'MySQL', 5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')
    
    def get_network_info(self) -> Dict:
        """Get basic network information"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'timestamp': time.time()
            }
        except:
            return {'hostname': 'Unknown', 'local_ip': 'Unknown', 'timestamp': time.time()}