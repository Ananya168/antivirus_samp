#!/usr/bin/env python3
"""
Safe Network Test File
Contains network-related patterns for testing
"""

# Network attack simulation patterns (safe)
ATTACK_PATTERNS = [
    "port_scanning_simulation",
    "brute_force_pattern", 
    "ddos_attack_simulation",
    "packet_sniffing_code",
    "sql_injection_attempt",
    "cross_site_scripting_payload"
]

# Suspicious port numbers
SUSPICIOUS_PORTS = [4444, 31337, 1337, 12345]

def simulate_network_scan():
    """Simulate network scanning behavior (safe)"""
    target_ips = ["192.168.1.1", "10.0.0.1", "127.0.0.1"]
    scan_commands = [
        f"nmap -p 1-1000 {ip}" for ip in target_ips  # Just strings, not executed
    ]
    return scan_commands

def suspicious_network_functions():
    """Network functions that might look suspicious"""
    functions = [
        "socket.create_connection()",
        "subprocess.Popen()", 
        "threading.Thread()",
        "requests.get()",
        "urllib.urlopen()"
    ]
    return functions

if __name__ == "__main__":
    print("🔍 This is a SAFE network test file for antivirus development")
    print("🔍 It contains network patterns but executes NOTHING")
    print("🔍 Safe for testing network monitoring features")