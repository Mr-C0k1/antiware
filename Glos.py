#!/usr/bin/env python3
"""
Glos Engine v2 - Advanced Web Vulnerability & Malware Pattern Scanner
Fitur Baru: 
1. Deep Scan (Mengejar file JS eksternal)
2. API Key & Secret Detection
3. Severity Rating (High/Medium/Low)
4. Advanced Regex Obfuscation Detection
"""

import re
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Palet Warna untuk Output
class Colors:
    HIGH = '\033[91m'    # Merah
    MEDIUM = '\033[93m'  # Kuning
    LOW = '\033[94m'     # Biru
    INFO = '\033[96m'    # Cyan
    RESET = '\033[0m'
    SUCCESS = '\033[92m' # Hijau

# Database Pola yang diperluas
VULNERABLE_PATTERNS = [
    # --- HIGH SEVERITY: Eksekusi Kode ---
    {
        'name': 'Insecure Eval/Function',
        'pattern': r'(eval|setTimeout|setInterval)\s*\(\s*["\'`].*["\'`]\s*,|new\s+Function\s*\(',
        'severity': 'HIGH',
        'description': 'Eksekusi string sebagai kode (RCE/XSS Risk).'
    },
    {
        'name': 'Malicious Domain Source',
        'pattern': r'src=["\']https?://[^\s]+(pastebin|anonfiles|cdn\.discordapp|raw\.githubusercontent|temp-mail)',
        'severity': 'HIGH',
        'description': 'Script dimuat dari hosting pihak ketiga yang sering disalahgunakan malware.'
    },

    # --- MEDIUM SEVERITY: DOM Injection & Secrets ---
    {
        'name': 'DOM XSS (innerHTML/write)',
        'pattern': r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|document\.writeln\(',
        'severity': 'MEDIUM',
        'description': 'Menulis langsung ke DOM tanpa sanitasi.'
    },
    {
        'name': 'Potential API Key/Secret',
        'pattern': r'(?:key|api_key|secret|token|auth|password|password_hash)["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,40}["\']',
        'severity': 'MEDIUM',
        'description': 'Ditemukan string yang menyerupai API Key atau Secret hardcoded.'
    },
    {
        'name': 'Insecure PostMessage',
        'pattern': r'\.postMessage\s*\(.*,\s*["\']\*["\']\)',
        'severity': 'MEDIUM',
        'description': 'Pengiriman data via postMessage tanpa memvalidasi origin (*).'
    },

    # --- LOW SEVERITY: Obfuscation & Info Gathering ---
    {
        'name': 'JS Obfuscation (Base64/Hex)',
        'pattern': r'atob\s*\(|btoa\s*\(|\\x[0-9a-fA-F]{2}|String\.fromCharCode',
        'severity': 'LOW',
        'description': 'Penggunaan encoding untuk menyembunyikan payload script.'
    }
]

def fetch_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) GLOS-Security-Scanner/2.0'}
        resp = requests.get(url, timeout=10, headers=headers, verify=True)
        return resp.text
    except Exception as e:
        print(f"{Colors.HIGH}[!] Error fetching {url}: {e}{Colors.RESET}")
        return ""

def scan_logic(content, source_name):
    findings = []
    for p in VULNERABLE_PATTERNS:
        matches = re.findall(p['pattern'], content, re.IGNORECASE)
        if matches:
            findings.append({
                'name': p['name'],
                'severity': p['severity'],
                'count': len(matches),
                'desc': p['description']
            })
    
    if findings:
        print(f"\n{Colors.INFO}[+] Hasil untuk: {source_name}{Colors.RESET}")
        for f in findings:
            color = Colors.LOW
            if f['severity'] == 'HIGH': color = Colors.HIGH
            elif f['severity'] == 'MEDIUM': color = Colors.MEDIUM
            
            print(f"  {color}[{f['severity']}] {f['name']} ({f['count']} hits){Colors.RESET}")
            print(f"    └─ {f['desc']}")
    return len(findings)

def main():
    parser = argparse.ArgumentParser(description='Glos Engine v2 - Web Script Security Analyzer')
    parser.add_argument('url', help='URL Target (contoh: https://example.com)')
    args = parser.parse_args()

    print(f"{Colors.SUCCESS}=== GLOS ENGINE v2 STARTING ==={Colors.RESET}")
    print(f"[*] Target: {args.url}\n")

    # 1. Scan Main HTML
    html_main = fetch_content(args.url)
    if not html_main: return
    
    total_issues = scan_logic(html_main, "Main Page HTML")

    # 2. Extract and Scan External Scripts
    soup = BeautifulSoup(html_main, 'html.parser')
    scripts = soup.find_all('script')
    
    found_js_files = []
    for s in scripts:
        src = s.get('src')
        if src:
            full_url = urljoin(args.url, src)
            if full_url not in found_js_files:
                found_js_files.append(full_url)

    if found_js_files:
        print(f"\n{Colors.INFO}[*] Menemukan {len(found_js_files)} file JS eksternal. Memulai Deep Scan...{Colors.RESET}")
        for js_url in found_js_files:
            js_content = fetch_content(js_url)
            if js_content:
                total_issues += scan_logic(js_content, js_url)

    print(f"\n{Colors.SUCCESS}=== Scan Selesai. Total Isu Ditemukan: {total_issues} ==={Colors.RESET}")

if __name__ == '__main__':
    main()
