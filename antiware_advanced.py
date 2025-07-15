#!/usr/bin/env python3
"""
antiware_advanced.py - Pemindaian Keamanan Tingkat Lanjut
Mendeteksi:
- RCE
- XSS Reflected
- Script Berbahaya dari CDN
- Header & Cookie Security
- Fingerprint Teknologi & Korelasi CVE
"""

import requests
import re
import json
import sys
from urllib.parse import urlparse, urlencode
from datetime import datetime
from bs4 import BeautifulSoup

# === Helper ===
def fetch(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (AntiWareScanner)'}
        r = requests.get(url, timeout=10, headers=headers)
        return r
    except Exception as e:
        print(f"[!] Error accessing {url}: {e}")
        return None

# === 1. RCE Detector ===
def check_rce(url):
    payloads = ["ls", "cat /etc/passwd", "whoami"]
    rce_findings = []
    for param in ['cmd', 'exec', 'shell', 'query']:
        for p in payloads:
            crafted = f"{url}?{param}={p}"
            resp = fetch(crafted)
            if resp and any(key in resp.text for key in ["root", "/bin/bash", "apache", "uid="]):
                rce_findings.append({
                    'type': 'Remote Code Execution',
                    'endpoint': crafted,
                    'evidence': p,
                    'severity': 'critical'
                })
    return rce_findings

# === 2. XSS Reflection Test ===
def check_xss(url):
    xss_payload = "<svg/onload=alert(1)>"
    parsed = urlparse(url)
    test_url = f"{url}?xss={xss_payload}"
    resp = fetch(test_url)
    if resp and xss_payload in resp.text:
        return [{
            'type': 'Reflected XSS',
            'endpoint': test_url,
            'evidence': 'payload reflected in response',
            'severity': 'high'
        }]
    return []

# === 3. Suspicious CDN JS ===
def check_cdn_js(url):
    findings = []
    resp = fetch(url)
    if resp:
        soup = BeautifulSoup(resp.text, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script['src']
            if any(domain in src for domain in ['raw.githubusercontent', 'pastebin', 'anonfiles', 'cdn.discordapp']):
                findings.append({
                    'type': 'Suspicious External JS',
                    'evidence': src,
                    'severity': 'high'
                })
    return findings

# === 4. Header & Cookie Security ===
def check_headers(resp):
    issues = []
    headers = resp.headers
    set_cookie = headers.get('Set-Cookie', '')
    if 'HttpOnly' not in set_cookie:
        issues.append({'type': 'Insecure Cookie', 'evidence': 'Missing HttpOnly', 'severity': 'medium'})
    if 'Secure' not in set_cookie:
        issues.append({'type': 'Insecure Cookie', 'evidence': 'Missing Secure', 'severity': 'medium'})
    if 'Content-Security-Policy' not in headers:
        issues.append({'type': 'Missing Header', 'evidence': 'Content-Security-Policy not set', 'severity': 'medium'})
    if 'X-Frame-Options' not in headers:
        issues.append({'type': 'Missing Header', 'evidence': 'X-Frame-Options not set', 'severity': 'low'})
    return issues

# === 5. Teknologi & Versi (Dummy Fingerprint) ===
def fingerprint_cms(resp):
    findings = []
    html = resp.text
    if 'wp-content' in html:
        findings.append({
            'type': 'CMS Detected',
            'evidence': 'WordPress Detected',
            'cve_refs': ['CVE-2022-21661'],
            'severity': 'medium'
        })
    return findings

# === Main Scanner ===
def scan(url):
    report = {
        'url': url,
        'scan_time': datetime.utcnow().isoformat() + 'Z',
        'vulnerabilities': []
    }

    print("\n[+] Memulai pemindaian tingkat lanjut...")

    resp = fetch(url)
    if not resp:
        print("[!] Gagal mengakses target.")
        return report

    report['vulnerabilities'].extend(check_rce(url))
    report['vulnerabilities'].extend(check_xss(url))
    report['vulnerabilities'].extend(check_cdn_js(url))
    report['vulnerabilities'].extend(check_headers(resp))
    report['vulnerabilities'].extend(fingerprint_cms(resp))

    return report

# === Entry Point ===
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} https://target.com")
        sys.exit(1)

    url = sys.argv[1]
    hasil = scan(url)

    print("\n[=== REPORT ===]")
    print(json.dumps(hasil, indent=2))
