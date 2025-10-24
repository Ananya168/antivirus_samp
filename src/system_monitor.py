import psutil
import time
import threading
from typing import Dict, List

class SystemMonitor:
    def __init__(self):
        self.process_log = []
        self.performance_alerts = []
        self.is_monitoring = False
        self.monitor_thread = None
        self.suspicious_processes = ['mimikatz.exe', 'procdump.exe', 'psexec.exe']
        
    def start_monitoring(self):
        """Start system monitoring"""
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.is_monitoring = False
        
    def _monitor_system(self):
        """Monitor system processes and performance"""
        known_processes = set()
        
        while self.is_monitoring:
            try:
                # Monitor CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90:  # High CPU usage
                    self.performance_alerts.append({
                        'type': 'HIGH_CPU_USAGE',
                        'value': cpu_percent,
                        'timestamp': time.time()
                    })
                
                # Monitor memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 90:  # High memory usage
                    self.performance_alerts.append({
                        'type': 'HIGH_MEMORY_USAGE',
                        'value': memory.percent,
                        'timestamp': time.time()
                    })
                
                # Monitor processes
                current_processes = set()
                for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        process_info = process.info
                        current_processes.add(process_info['name'].lower())
                        
                        # Check for suspicious processes
                        if any(suspicious in process_info['name'].lower() 
                              for suspicious in self.suspicious_processes):
                            self.process_log.append({
                                'type': 'SUSPICIOUS_PROCESS',
                                'process_name': process_info['name'],
                                'pid': process_info['pid'],
                                'timestamp': time.time()
                            })
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Detect new processes
                new_processes = current_processes - known_processes
                if new_processes and known_processes:  # Only alert after initial scan
                    for process in new_processes:
                        self.process_log.append({
                            'type': 'NEW_PROCESS',
                            'process_name': process,
                            'timestamp': time.time()
                        })
                
                known_processes = current_processes
                
            except Exception as e:
                print(f"System monitoring error: {e}")
                
            time.sleep(10)  # Check every 10 seconds
            
    def get_system_alerts(self) -> List[Dict]:
        """Get recent system alerts"""
        recent_alerts = [alert for alert in self.process_log + self.performance_alerts
                        if time.time() - alert['timestamp'] < 3600]  # Last hour
        return recent_alerts