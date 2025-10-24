#!/usr/bin/env python3
"""
SAFE RANSOMWARE TEST SAMPLE
This file simulates ransomware behavior for testing
but does NOT actually encrypt or harm any files.
"""

# Ransomware-like patterns that will trigger detection
ENCRYPTION_KEYWORDS = [
    "AES256", "RSA2048", "encrypt", "decrypt", "ransom",
    "bitcoin", "payment", "decryption_key", "your_files"
]

def fake_encryption_routine():
    """This looks like encryption code but does nothing"""
    # These patterns will trigger heuristic detection
    fake_key = "this_is_a_fake_encryption_key_12345"
    fake_iv = "fake_initialization_vector"
    
    # Fake file operations that look suspicious
    operations = [
        "Opening target files...",
        "Generating encryption keys...",
        "Encrypting file contents...",  # This will trigger alerts
        "Renaming files with .encrypted extension...",
        "Creating ransom note...",
        "Payment required: 0.5 BTC"  # Fake ransom demand
    ]
    
    # Just return the operations list, don't execute
    return operations

def suspicious_network_activity():
    """Simulate suspicious network behavior"""
    # These would normally connect to C&C servers
    servers = [
        "http://malicious-server.com/checkin",
        "tcp://command.control:4444",
        "udp://data.exfiltrate:31337"
    ]
    return servers

# Fake main execution
if __name__ == "__main__":
    print("⚠️  THIS IS A SAFE TEST FILE FOR ANTIVIRUS DEVELOPMENT")
    print("⚠️  It contains ransomware-like patterns but is COMPLETELY HARMLESS")
    print("⚠️  No files are being encrypted or modified")
    
    # Display the fake routines (but don't execute them)
    print("\nSimulated ransomware patterns:")
    for pattern in ENCRYPTION_KEYWORDS:
        print(f"  - {pattern}")
        
    print("\nThis file is safe for educational purposes only!")