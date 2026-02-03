#!/usr/bin/env python3
import requests
import re
import json
import sys
import concurrent.futures
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings untuk pentesting
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AntiWareAdvanced:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (AntiWareScanner/2.0)'})
        self.findings = []

    def fetch(self, url, params=None):
        try:
            return self.session.get(url, params=params, timeout=7, verify=False)
        except Exception:
            return None

    # --- 1. Enhanced RCE Detector (Parallel) ---
    def check_rce(self):
        # Tambahan payload untuk variasi OS
        payloads = ["; ls", "| whoami", "`id`", "cat /etc/passwd", "timeout /t 5"]
        params = ['cmd', 'exec', 'shell', 'query', 'id', 'file']
        
        def test_p(p):
            for param in params:
                resp = self.fetch(self.target, params={param: p})
                if resp and any(key in resp.text for key in ["root:x:", "uid=", "Active Internet connections"]):
                    self.findings.append({
                        'type': 'RCE', 'endpoint': resp.url, 'severity': 'critical', 'evidence': p
                    })

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(test_p, payloads)

    # --- 2. XSS Detector (Context Aware) ---
    def check_xss(self):
        payloads = ["<script>alert(1)</script>", "';alert(1)//", "\"><svg/onload=alert(1)>"]
        for p in payloads:
            resp = self.fetch(self.target, params={'q': p})
            if resp and p in resp.text:
                self.findings.append({
                    'type': 'Reflected XSS', 'endpoint': resp.url, 'severity': 'high'
                })
                break

    # --- 3. Header Security & Cookie ---
    def check_security_configs(self, resp):
        headers = resp.headers
        missing = []
        for h in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
            if h not in headers:
                missing.append(h)
        
        if missing:
            self.findings.append({
                'type': 'Missing Security Headers', 'evidence': missing, 'severity': 'low'
            })

        cookies = resp.cookies
        for cookie in cookies:
            if not cookie.secure or 'httponly' not in cookie._rest.keys():
                self.findings.append({
                    'type': 'Insecure Cookie', 'evidence': f"Cookie: {cookie.name}", 'severity': 'medium'
                })

    # --- 4. JS Static Analysis (Optimized) ---
    def scan_js(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        scripts = [urljoin(self.target, s['src']) for s in soup.find_all('script', src=True)]
        
        patterns = {
            'eval()': r'eval\s*\(',
            'innerHTML': r'\.innerHTML\s*=',
            'document.write': r'document\.write\(',
            'PostMessage Leak': r'\.postMessage\('
        }

        for js_url in scripts:
            js_resp = self.fetch(js_url)
            if js_resp and js_resp.status_code == 200:
                for name, regex in patterns.items():
                    if re.search(regex, js_resp.text):
                        self.findings.append({
                            'type': 'Insecure JS Pattern', 'evidence': name, 'location': js_url, 'severity': 'medium'
                        })

    def run(self):
        print(f"[*] Scanning: {self.target}")
        initial_resp = self.fetch(self.target)
        if not initial_resp:
            print("[!] Target unreachable.")
            return

        # Running modules
        self.check_security_configs(initial_resp)
        self.scan_js(initial_resp.text)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(self.check_rce)
            executor.submit(self.check_xss)

        return {
            'target': self.target,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(self.findings),
            'vulnerabilities': self.findings
        }

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 antiware_advanced.py <url>")
        sys.exit(1)
    
    scanner = AntiWareAdvanced(sys.argv[1])
    report = scanner.run()
    print(json.dumps(report, indent=2))
