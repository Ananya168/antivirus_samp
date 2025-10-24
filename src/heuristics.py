import re
import os  # Add this import
from typing import Dict, List  # Ensure these imports are present

class HeuristicAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            "format", "delete", "erase", "remove", "corrupt",
            "encrypt", "decrypt", "password", "keylogger",
            "inject", "hook", "modify", "alter", "bypass"
        ]
        
        self.suspicious_functions = [
            "exec", "system", "popen", "spawn", "createprocess",
            "writeprocessmemory", "virtualalloc", "getprocaddress"
        ]
    
    def analyze_file(self, content: str, file_path: str) -> Dict:
        """Analyze file using heuristic methods"""
        score = 0
        warnings = []
        
        # Check for suspicious keywords
        keyword_matches = self._check_keywords(content)
        if keyword_matches:
            score += len(keyword_matches) * 2
            warnings.extend([f"Suspicious keyword: {kw}" for kw in keyword_matches])
        
        # Check for suspicious function calls
        function_matches = self._check_functions(content)
        if function_matches:
            score += len(function_matches) * 3
            warnings.extend([f"Suspicious function: {func}" for func in function_matches])
        
        # Check for encoded/obfuscated content
        if self._detect_obfuscation(content):
            score += 5
            warnings.append("Possible code obfuscation detected")
        
        # Check file size anomalies
        file_size_score = self._check_file_size(file_path)
        score += file_size_score
        
        return {"score": min(score, 10), "warnings": warnings}
    
    def _check_keywords(self, content: str) -> List[str]:
        """Check for suspicious keywords"""
        matches = []
        content_lower = content.lower()
        for keyword in self.suspicious_keywords:
            if keyword in content_lower:
                matches.append(keyword)
        return matches
    
    def _check_functions(self, content: str) -> List[str]:
        """Check for suspicious function calls"""
        matches = []
        content_lower = content.lower()
        for function in self.suspicious_functions:
            if function in content_lower:
                matches.append(function)
        return matches
    
    def _detect_obfuscation(self, content: str) -> bool:
        """Detect potential code obfuscation"""
        # Check for high entropy (simple version)
        if len(content) > 1000:
            unique_chars = len(set(content))
            entropy = unique_chars / len(content)
            if entropy > 0.9:  # High entropy might indicate encryption/compression
                return True
        
        # Check for base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        if re.findall(base64_pattern, content):
            return True
            
        return False
    
    def _check_file_size(self, file_path: str) -> int:
        """Check for file size anomalies"""
        try:
            size = os.path.getsize(file_path)
            if size == 0:
                return 2  # Empty file
            elif size > 100 * 1024 * 1024:  # > 100MB
                return 3  # Very large file
            elif size < 100:  # < 100 bytes
                return 2  # Very small file
        except:
            pass
        return 0