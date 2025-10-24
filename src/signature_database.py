import json
import os
from typing import List, Dict

class SignatureDatabase:
    def __init__(self, signature_file: str = "config/signatures.json"):
        self.signature_file = signature_file
        self.virus_signatures = self.load_signatures()
    
    def load_signatures(self) -> Dict[str, List[str]]:
        """Load virus signatures from JSON file"""
        try:
            with open(self.signature_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default signatures for demonstration
            default_signatures = {
                "suspicious_patterns": [
                    "malicious_code_pattern",
                    "virus_signature_123",
                    "trojan_marker",
                    "EXECUTE_SHELLCODE",
                    "SYSTEM_COMPROMISE"
                ],
                "suspicious_extensions": [".exe", ".bat", ".cmd", ".ps1", ".vbs"],
                "heuristic_patterns": [
                    "format C:",
                    "rm -rf",
                    "del /f",
                    "shutdown"
                ]
            }
            os.makedirs(os.path.dirname(self.signature_file), exist_ok=True)
            with open(self.signature_file, 'w') as f:
                json.dump(default_signatures, f, indent=4)
            return default_signatures
    
    def add_signature(self, pattern: str, category: str = "suspicious_patterns"):
        """Add a new virus signature"""
        if category not in self.virus_signatures:
            self.virus_signatures[category] = []
        
        if pattern not in self.virus_signatures[category]:
            self.virus_signatures[category].append(pattern)
            self.save_signatures()
    
    def save_signatures(self):
        """Save signatures to file"""
        with open(self.signature_file, 'w') as f:
            json.dump(self.virus_signatures, f, indent=4)
    
    def get_signatures(self) -> Dict[str, List[str]]:
        """Get all virus signatures"""
        return self.virus_signatures