import os
import time
from typing import Dict, List
import threading

class RansomwareDetector:
    def __init__(self, monitor_dirs=None):
        self.monitor_dirs = monitor_dirs or [os.path.expanduser("~/Documents"), os.getcwd()]
        self.file_operations = []
        self.is_monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start ransomware monitoring"""
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_files)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop ransomware monitoring"""
        self.is_monitoring = False
        
    def _monitor_files(self):
        """Monitor for ransomware-like file operations"""
        known_files = {}
        
        # Initial scan of files
        for directory in self.monitor_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            known_files[file_path] = os.path.getsize(file_path)
                        except:
                            pass
        
        while self.is_monitoring:
            try:
                current_files = {}
                encryption_suspicion = 0
                
                for directory in self.monitor_dirs:
                    if os.path.exists(directory):
                        for root, dirs, files in os.walk(directory):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    current_size = os.path.getsize(file_path)
                                    current_files[file_path] = current_size
                                    
                                    # Check for file size changes (possible encryption)
                                    if file_path in known_files:
                                        old_size = known_files[file_path]
                                        if old_size > 0 and current_size > old_size * 1.5:
                                            encryption_suspicion += 1
                                            self.file_operations.append({
                                                'type': 'SUSPICIOUS_SIZE_CHANGE',
                                                'file_path': file_path,
                                                'old_size': old_size,
                                                'new_size': current_size,
                                                'timestamp': time.time()
                                            })
                                    
                                    # Check for encrypted file extensions
                                    if self._is_encrypted_extension(file_path):
                                        encryption_suspicion += 2
                                        self.file_operations.append({
                                            'type': 'ENCRYPTED_EXTENSION',
                                            'file_path': file_path,
                                            'timestamp': time.time()
                                        })
                                        
                                except:
                                    continue
                
                # High encryption suspicion alert
                if encryption_suspicion > 5:
                    self.file_operations.append({
                        'type': 'POSSIBLE_RANSOMWARE',
                        'suspicion_level': encryption_suspicion,
                        'timestamp': time.time()
                    })
                
                known_files = current_files
                
            except Exception as e:
                print(f"Ransomware monitoring error: {e}")
                
            time.sleep(30)  # Check every 30 seconds
            
    def _is_encrypted_extension(self, file_path: str) -> bool:
        """Check for encrypted file extensions"""
        encrypted_extensions = ['.encrypted', '.crypted', '.locked', '.ransom']
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in encrypted_extensions
        
    def get_ransomware_alerts(self) -> List[Dict]:
        """Get recent ransomware alerts"""
        recent_alerts = [alert for alert in self.file_operations
                        if time.time() - alert['timestamp'] < 3600]  # Last hour
        return recent_alerts