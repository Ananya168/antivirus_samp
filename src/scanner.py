import os
import hashlib
from typing import List, Dict, Tuple
from .signature_database import SignatureDatabase
from .heuristics import HeuristicAnalyzer

class VirusScanner:
    def __init__(self):
        self.signature_db = SignatureDatabase()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.scan_results = []
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a single file for viruses"""
        if not os.path.exists(file_path):
            return {"file": file_path, "status": "ERROR", "message": "File not found"}
        
        results = {
            "file": file_path,
            "signature_matches": [],
            "heuristic_score": 0,
            "heuristic_warnings": [],
            "status": "CLEAN"
        }
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Signature-based detection
            signatures = self.signature_db.get_signatures()
            
            # Check for suspicious patterns
            for pattern in signatures["suspicious_patterns"]:
                if pattern.lower() in content.lower():
                    results["signature_matches"].append(f"Suspicious pattern: {pattern}")
            
            # Check file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in signatures["suspicious_extensions"]:
                results["signature_matches"].append(f"Suspicious extension: {file_ext}")
            
            # Heuristic analysis
            heuristic_result = self.heuristic_analyzer.analyze_file(content, file_path)
            results["heuristic_score"] = heuristic_result["score"]
            results["heuristic_warnings"] = heuristic_result["warnings"]
            
            # Determine final status
            if results["signature_matches"] or results["heuristic_score"] > 7:
                results["status"] = "INFECTED"
            elif results["heuristic_score"] > 4:
                results["status"] = "SUSPICIOUS"
            else:
                results["status"] = "CLEAN"
                
        except Exception as e:
            results["status"] = "ERROR"
            results["message"] = str(e)
        
        self.scan_results.append(results)
        return results
    
    def scan_directory(self, directory_path: str) -> List[Dict]:
        """Scan all files in a directory"""
        if not os.path.exists(directory_path):
            return [{"file": directory_path, "status": "ERROR", "message": "Directory not found"}]
        
        results = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                result = self.scan_file(file_path)
                results.append(result)
        
        return results
    
    def get_scan_summary(self) -> Dict:
        """Get summary of scan results"""
        total_files = len(self.scan_results)
        clean_files = len([r for r in self.scan_results if r["status"] == "CLEAN"])
        infected_files = len([r for r in self.scan_results if r["status"] == "INFECTED"])
        suspicious_files = len([r for r in self.scan_results if r["status"] == "SUSPICIOUS"])
        
        return {
            "total_files": total_files,
            "clean_files": clean_files,
            "infected_files": infected_files,
            "suspicious_files": suspicious_files,
            "clean_percentage": (clean_files / total_files * 100) if total_files > 0 else 0
        }