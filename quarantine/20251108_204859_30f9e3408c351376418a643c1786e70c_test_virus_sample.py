# Safe test file with virus-like patterns
malicious_patterns = [
    "virus_signature_123",
    "trojan_marker",
    "EXECUTE_SHELLCODE"
]

def suspicious_function():
    password = "secret"
    encrypted_data = "fake_encrypted_content"
    return "This is safe"