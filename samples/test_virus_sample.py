#!/usr/bin/env python3
"""
SAFE TEST VIRUS SAMPLE - NOT ACTUALLY MALICIOUS
This file contains patterns that will be detected by the antivirus
but does not actually harm your system.
"""

# These patterns will trigger signature detection
SUSPICIOUS_PATTERNS = [
    "malicious_code_pattern",
    "virus_signature_123",
    "trojan_marker",
    "EXECUTE_SHELLCODE",
    "SYSTEM_COMPROMISE"
]

# These functions will trigger heuristic detection
def suspicious_function():
    """This function looks suspicious but does nothing harmful"""
    # Simulating suspicious behavior patterns
    command = "format C:"
    system_call = "rm -rf /"
    shutdown_command = "shutdown /s /t 0"
    
    # But actually, we're just defining strings, not executing them
    dummy_data = [
        "This is not real malware",
        "Just educational content",
        "Safe for demonstration"
    ]
    
    return dummy_data

def another_suspicious_function():
    """Another function that looks dangerous but is safe"""
    # Simulating encryption patterns (heuristic trigger)
    password = "secret_key_123"
    encrypted_data = "fake_encrypted_content_here"
    
    # Fake system modification attempts
    system_modification = "modify_system_files"
    bypass_security = "bypass_antivirus"
    
    return "This is completely safe"

# Fake main execution that looks like malware
if __name__ == "__main__":
    print("This is a SAFE test virus sample for antivirus development.")
    print("It contains patterns that trigger detection but does nothing harmful.")
    print("Do not worry - this file is safe for educational purposes.")
    
    # Just print the suspicious patterns, don't execute them
    for pattern in SUSPICIOUS_PATTERNS:
        print(f"Pattern found: {pattern} (SAFE)")