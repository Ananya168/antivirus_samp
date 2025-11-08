import os
import shutil
import hashlib
from datetime import datetime
from typing import List

class QuarantineManager:
    def __init__(self, quarantine_dir: str = "quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)
        self.quarantine_log = os.path.join(quarantine_dir, "quarantine_log.txt")
    
    def quarantine_file(self, file_path: str, reason: str = "Virus detected") -> bool:
        """Move a file to quarantine"""
        if not os.path.exists(file_path):
            return False
        
        try:
            # Generate unique quarantine filename
            file_hash = self._calculate_file_hash(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantined_filename = f"{timestamp}_{file_hash}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantined_filename)
            
            # Copy file to quarantine instead of move (safer for testing)
            shutil.copy2(file_path, quarantine_path)
            
            # Log the action
            self._log_quarantine(file_path, quarantine_path, reason)
            
            return True
            
        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")
            return False
    
    def restore_file(self, quarantined_filename: str, restore_path: str) -> bool:
        """Restore a file from quarantine"""
        quarantine_path = os.path.join(self.quarantine_dir, quarantined_filename)
        
        if not os.path.exists(quarantine_path):
            return False
        
        try:
            # Copy file back from quarantine
            shutil.copy2(quarantine_path, restore_path)
            
            # Update log
            self._log_restoration(quarantined_filename, restore_path)
            
            return True
            
        except Exception as e:
            print(f"Error restoring file {quarantined_filename}: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "unknown_hash"
    
    def _log_quarantine(self, original_path: str, quarantine_path: str, reason: str):
        """Log quarantine action"""
        try:
            with open(self.quarantine_log, 'a', encoding='utf-8') as f:
                f.write(f"QUARANTINE|{datetime.now()}|{original_path}|{quarantine_path}|{reason}\n")
        except:
            pass
    
    def _log_restoration(self, quarantined_filename: str, restore_path: str):
        """Log restoration action"""
        try:
            with open(self.quarantine_log, 'a', encoding='utf-8') as f:
                f.write(f"RESTORE|{datetime.now()}|{quarantined_filename}|{restore_path}\n")
        except:
            pass
    
    def get_quarantined_files(self) -> List[str]:
        """Get list of quarantined files"""
        files = []
        try:
            for file in os.listdir(self.quarantine_dir):
                if file != "quarantine_log.txt":
                    files.append(file)
        except:
            pass
        return files