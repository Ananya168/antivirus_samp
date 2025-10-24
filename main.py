#!/usr/bin/env python3
"""
Antivirus Prototype - Main Application
"""

import os
import sys
import argparse
from src.scanner import VirusScanner
from src.quarantine import QuarantineManager

def main():
    parser = argparse.ArgumentParser(description="Antivirus Prototype Scanner")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--quarantine", "-q", action="store_true", 
                       help="Automatically quarantine infected files")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = VirusScanner()
    quarantine_manager = QuarantineManager()
    
    print("=== Antivirus Prototype Scanner ===")
    print(f"Scanning: {args.target}")
    print("-" * 40)
    
    if os.path.isfile(args.target):
        results = [scanner.scan_file(args.target)]
    elif os.path.isdir(args.target):
        results = scanner.scan_directory(args.target)
    else:
        print(f"Error: {args.target} not found")
        return 1
    
    # Display results
    infected_files = []
    for result in results:
        status_icon = "✓" if result["status"] == "CLEAN" else "✗"
        print(f"{status_icon} {result['file']} - {result['status']}")
        
        if args.verbose and result["status"] != "CLEAN":
            if result["signature_matches"]:
                print("  Signature matches:")
                for match in result["signature_matches"]:
                    print(f"    - {match}")
            if result["heuristic_warnings"]:
                print("  Heuristic warnings:")
                for warning in result["heuristic_warnings"]:
                    print(f"    - {warning}")
            print(f"  Heuristic score: {result['heuristic_score']}/10")
        
        if result["status"] == "INFECTED":
            infected_files.append(result["file"])
    
    # Display summary
    summary = scanner.get_scan_summary()
    print("-" * 40)
    print(f"Scan Summary:")
    print(f"Total files: {summary['total_files']}")
    print(f"Clean: {summary['clean_files']}")
    print(f"Infected: {summary['infected_files']}")
    print(f"Suspicious: {summary['suspicious_files']}")
    print(f"Clean percentage: {summary['clean_percentage']:.1f}%")
    
    # Handle quarantine
    if args.quarantine and infected_files:
        print("\nQuarantining infected files...")
        for file_path in infected_files:
            if quarantine_manager.quarantine_file(file_path, "Virus detected"):
                print(f"✓ Quarantined: {file_path}")
            else:
                print(f"✗ Failed to quarantine: {file_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())