#!/usr/bin/env python3
"""
Glos.py - Deteksi Script Pemrograman Web yang Lemah
Fokus pada deteksi pola coding berbahaya pada halaman web target (XSS, RCE, Insecure Eval, dll).
"""
import re
import argparse
import requests
from bs4 import BeautifulSoup

# Daftar pola script lemah
VULNERABLE_PATTERNS = [
    {
        'name': 'Insecure JavaScript Eval',
        'pattern': r'eval\s*\(',
        'description': 'Penggunaan eval() dapat menyebabkan RCE jika input tidak difilter dengan benar.'
    },
    {
        'name': 'XSS via innerHTML',
        'pattern': r'\.innerHTML\s*=\s*',
        'description': 'Manipulasi langsung innerHTML bisa menyebabkan XSS.'
    },
    {
        'name': 'Insecure jQuery Selector Injection',
        'pattern': r'\$\([^\)]+location\.hash',
        'description': 'Menggunakan location.hash secara langsung di jQuery selector membuka celah XSS.'
    },
    {
        'name': 'Document.write Usage',
        'pattern': r'document\.write\s*\(',
        'description': 'document.write raw dapat disusupi XSS pada runtime.'
    },
    {
        'name': 'Obfuscated Payload (Base64 in JS)',
        'pattern': r'atob\s*\(|btoa\s*\(',
        'description': 'Payload JS mencurigakan menggunakan encoding base64.'
    },
    {
        'name': 'Suspicious script domain',
        'pattern': r'src=["\']https?://[^\s]+(pastebin|anonfiles|cdn\\.discordapp|raw\\.githubusercontent)',
        'description': 'Script dimuat dari sumber mencurigakan pihak ketiga.'
    }
]

def fetch_web_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; GLOS-Bot/1.0)'}
        resp = requests.get(url, timeout=10, headers=headers)
        return resp.text
    except Exception as e:
        print(f"[!] Gagal mengambil konten: {e}")
        return ""

def scan_for_weak_scripts(html, url):
    findings = []
    for pattern in VULNERABLE_PATTERNS:
        matches = re.findall(pattern['pattern'], html, re.IGNORECASE)
        if matches:
            findings.append({
                'type': pattern['name'],
                'description': pattern['description'],
                'count': len(matches)
            })
    print(f"\n[+] Hasil pemindaian {url}:")
    if not findings:
        print("[-] Tidak ditemukan script berbahaya atau lemah.")
    else:
        for f in findings:
            print(f"[*] {f['type']} (ditemukan {f['count']} kali)\n    - {f['description']}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='GLOS - Deteksi Script Lemah pada Situs Web')
    parser.add_argument('url', help='URL target yang ingin dipindai')
    args = parser.parse_args()

    html = fetch_web_content(args.url)
    scan_for_weak_scripts(html, args.url)
