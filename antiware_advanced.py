#!/usr/bin/env python3
"""
antiware_advanced.py - Pemindaian Keamanan Tingkat Lanjut
Mendeteksi:
- RCE
- XSS Reflected
- Script Berbahaya dari CDN
- Header & Cookie Security
- Fingerprint Teknologi & Korelasi CVE
- Static Analysis pada JavaScript eksternal
"""

import requests
import re
import json
import sys
from urllib.parse import urlparse, urlencode, urljoin
from datetime import datetime, timezone
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
                    'location': 'parameter ' + param,
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
            'location': 'query parameter xss',
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
                    'location': 'script tag src attribute',
                    'severity': 'high'
                })
    return findings

# === 4. Header & Cookie Security ===
def check_headers(resp):
    issues = []
    headers = resp.headers
    set_cookie = headers.get('Set-Cookie', '')
    if 'HttpOnly' not in set_cookie:
        issues.append({'type': 'Insecure Cookie', 'evidence': 'Missing HttpOnly', 'location': 'Set-Cookie header', 'severity': 'medium'})
    if 'Secure' not in set_cookie:
        issues.append({'type': 'Insecure Cookie', 'evidence': 'Missing Secure', 'location': 'Set-Cookie header', 'severity': 'medium'})
    if 'Content-Security-Policy' not in headers:
        issues.append({'type': 'Missing Header', 'evidence': 'Content-Security-Policy not set', 'location': 'HTTP response headers', 'severity': 'medium'})
    if 'X-Frame-Options' not in headers:
        issues.append({'type': 'Missing Header', 'evidence': 'X-Frame-Options not set', 'location': 'HTTP response headers', 'severity': 'low'})
    return issues

# === 5. Teknologi & Versi (Dummy Fingerprint) ===
def fingerprint_cms(resp):
    findings = []
    html = resp.text
    if 'wp-content' in html:
        findings.append({
            'type': 'CMS Detected',
            'evidence': 'WordPress Detected',
            'location': 'HTML body contains wp-content path',
            'cve_refs': ['CVE-2022-21661'],
            'severity': 'medium'
        })
    return findings

# === 6. Static JS Analyzer ===
def scan_javascript_static(base_url):
    resp = fetch(base_url)
    if not resp:
        return []
    soup = BeautifulSoup(resp.text, 'html.parser')
    findings = []
    for script in soup.find_all('script', src=True):
        js_url = urljoin(base_url, script['src'])
        js_resp = fetch(js_url)
        if not js_resp or js_resp.status_code != 200:
            continue
        lines = js_resp.text.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'eval\s*\(', line):
                findings.append({
                    'type': 'Insecure JavaScript Eval',
                    'evidence': 'eval() digunakan',
                    'location': f'{js_url} line {i+1}',
                    'severity': 'high'
                })
            elif re.search(r'\.innerHTML\s*=\s*', line):
                findings.append({
                    'type': 'XSS via innerHTML',
                    'evidence': 'innerHTML assignment',
                    'location': f'{js_url} line {i+1}',
                    'severity': 'high'
                })
            elif re.search(r'document\.write\s*\(', line):
                findings.append({
                    'type': 'Document.write Usage',
                    'evidence': 'document.write digunakan',
                    'location': f'{js_url} line {i+1}',
                    'severity': 'medium'
                })
    return findings

# === Main Scanner ===
def scan(url):
    report = {
        'url': url,
        'scan_time': datetime.now(timezone.utc).isoformat(),
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
    report['vulnerabilities'].extend(scan_javascript_static(url))

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
