#!/usr/bin/env python3
"""
Network Scan Test File - Safe for testing
"""

import socket

def test_local_ports():
    """Test if common ports are open on localhost"""
    print("Testing common ports on localhost...")
    
    ports_to_test = [80, 443, 22, 21, 3389, 5432, 8080, 3306]
    
    for port in ports_to_test:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                status = "OPEN" if result == 0 else "CLOSED"
                print(f"Port {port}: {status}")
        except Exception as e:
            print(f"Port {port}: ERROR - {e}")

if __name__ == "__main__":
    print("🔍 Network Port Scanner Test")
    print("This script tests port scanning detection")
    test_local_ports()