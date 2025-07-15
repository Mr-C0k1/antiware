#!/usr/bin/env python3
"""
AntiWare - Website Threat & Malware Scanner (CLI + API)
"""

import re
import requests
import argparse
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from flask import Flask, request, jsonify

# === Kelas Detektor Ancaman ===
class AntiWareScanner:
    def __init__(self):
        self.patterns = [
            {
                'type': 'Malware Injection',
                'pattern': r'<script[^>]+src=["\']?https?://[^>]*obfuscated',
                'description': 'Injeksi script obfuscated terdeteksi.'
            },
            {
                'type': 'Backdoor Upload',
                'pattern': r'(shell\.php|r57\.php|cmd\.php)',
                'description': 'File backdoor terdeteksi.'
            }
        ]

    def scan_url(self, url):
        result = {
            'url': url,
            'vulnerabilities': []
        }
        try:
            response = requests.get(url, timeout=10)
            html = response.text
            for rule in self.patterns:
                if re.search(rule['pattern'], html, re.IGNORECASE):
                    result['vulnerabilities'].append({
                        'type': rule['type'],
                        'description': rule['description']
                    })
        except Exception as e:
            result['error'] = str(e)
        return result

# === Fungsi Utama ===
def main():
    parser = argparse.ArgumentParser(description="AntiWare Web Threat Scanner")
    parser.add_argument('url', nargs='?', help='URL target untuk pemindaian')
    args = parser.parse_args()

    if not args.url:
        print("[!] Tidak ada input yang diberikan.")
        return

    scanner = AntiWareScanner()
    result = scanner.scan_url(args.url)

    print(f"\n[✔] Hasil Pemindaian: {args.url}")
    if 'vulnerabilities' in result and result['vulnerabilities']:
        for v in result['vulnerabilities']:
            print(f"- {v['type']}: {v['description']}")
    else:
        print("[✓] Tidak ditemukan ancaman yang teridentifikasi.")

if __name__ == '__main__':
    main()
