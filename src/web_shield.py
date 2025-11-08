import re
from typing import List, Dict

class WebShield:
    def __init__(self):
        self.malicious_domains = [
            "malicious.com", "phishing-site.com", "fake-login.com",
            "virus-download.com", "trojan-horse.net", "evil-tracker.org"
        ]
        
        self.suspicious_keywords = [
            "free_money", "win_prize", "urgent_action", "account_suspended",
            "password_reset", "verify_account", "security_alert", "click_here"
        ]
        
        self.checked_urls = []
    
    def check_url(self, url: str) -> Dict:
        """Check if a URL is malicious"""
        result = {
            'url': url,
            'safe': True,
            'threats': [],
            'confidence': 0,
            'risk_level': 'LOW'
        }
        
        # Check against known malicious domains
        for domain in self.malicious_domains:
            if domain in url:
                result['safe'] = False
                result['threats'].append(f'Known malicious domain: {domain}')
                result['confidence'] += 80
        
        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in url.lower():
                result['threats'].append(f'Suspicious keyword: {keyword}')
                result['confidence'] += 40
        
        # Check URL structure
        if self._has_suspicious_structure(url):
            result['threats'].append('Suspicious URL structure')
            result['confidence'] += 30
            
        # Determine risk level
        if result['confidence'] >= 80:
            result['risk_level'] = 'HIGH'
            result['safe'] = False
        elif result['confidence'] >= 50:
            result['risk_level'] = 'MEDIUM'
            result['safe'] = False
        elif result['confidence'] >= 20:
            result['risk_level'] = 'LOW'
            
        self.checked_urls.append(result)
        return result
    
    def _has_suspicious_structure(self, url: str) -> bool:
        """Check for suspicious URL patterns"""
        # IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            return True
            
        # Too many subdomains
        if url.count('.') > 4:
            return True
            
        # Unusual characters
        if '--' in url or '__' in url or '//' in url[8:]:
            return True
            
        # Very long URLs
        if len(url) > 100:
            return True
            
        return False
    
    def get_check_history(self) -> List[Dict]:
        """Get history of checked URLs"""
        return self.checked_urls[-10:]  # Last 10 checks