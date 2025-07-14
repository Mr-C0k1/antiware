#!/usr/bin/env python3
"""
AntiWare - Website Threat & Malware Scanner (CLI & API)
Versi CLI lengkap dan bisa dieksekusi seperti tool di Kali Linux
"""

import re
import requests
import argparse
import os
import json
import hashlib
import time
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv, set_key
from PIL import Image
import sys
import base64

# Load dan buat konfigurasi
ENV_FILE = '.env'
load_dotenv(ENV_FILE)

if not os.path.exists(ENV_FILE):
    with open(ENV_FILE, 'w') as f:
        f.write('API_TOKEN=changeme\nVT_API_KEY=your_virustotal_key\nREPORT_DASHBOARD=https://dashboard.example.com/api/report\n')

# Setup logging
logging.basicConfig(
    filename='antiware_scanner.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

REPORT_DIR = 'antiware_reports'
os.makedirs(REPORT_DIR, exist_ok=True)

# Hash signature database
KNOWN_MALWARE_HASHES = {
    "e99a18c428cb38d5f260853678922e03": "Akira ransomware variant",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file"
    # Tambahkan hash signature lainnya sesuai kebutuhan
}

# Tampilkan logo saat dijalankan
def tampilkan_logo():
    try:
        from io import BytesIO
        logo_path = os.path.join(os.path.dirname(__file__), 'antiware_logo.png')
        if not os.path.exists(logo_path):
            print("[!] Gambar logo tidak ditemukan: antiware_logo.png")
            return
        img = Image.open(logo_path)
        img = img.convert('L').resize((60, 30))
        pixels = img.load()
        for y in range(img.size[1]):
            for x in range(img.size[0]):
                brightness = pixels[x, y]
                char = ' ' if brightness > 128 else '#'
                print(char, end='')
            print()
        print("\nANTIWARE - Website Threat Scanner\n")
    except Exception as e:
        print(f"[!] Gagal menampilkan logo: {e}")

app = Flask(__name__)
app.config['API_TOKEN'] = os.getenv('API_TOKEN', 'changeme')
app.config['VT_API_KEY'] = os.getenv('VT_API_KEY', 'your_virustotal_key')
app.config['REPORT_DASHBOARD'] = os.getenv('REPORT_DASHBOARD', 'https://dashboard.example.com/api/report')

class AntiWareScanner:
    def __init__(self):
        self.threat_patterns = [...]  # (tidak diubah)

    def hash_file(self, filepath):
        ...  # (tidak diubah)

    def monitor_directory(self, path='.'):  # (tidak diubah)
        ...

    # kode lainnya tetap digunakan seperti scan_url, scan_file_content, dll.

def main():
    tampilkan_logo()

    parser = argparse.ArgumentParser(description='AntiWare Website Threat Detector')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-l', '--list', help='File list of URLs to scan')
    parser.add_argument('-f', '--file', help='Scan local file content')
    parser.add_argument('-o', '--output', help='Save result to .txt')
    parser.add_argument('--api', nargs='?', const=True, help='Run as API server (optionally with token)')
    parser.add_argument('--monitor', action='store_true', help='Monitor direktori untuk file mencurigakan')
    parser.add_argument('--set-token', help='Set API Token')
    parser.add_argument('--set-vtkey', help='Set VirusTotal API Key')
    parser.add_argument('--set-dashboard', help='Set Dashboard Endpoint')

    args = parser.parse_args()

    scanner = AntiWareScanner()

    if args.set_token:
        set_key(ENV_FILE, 'API_TOKEN', args.set_token)
        print("[+] API token disimpan.")

    if args.set_vtkey:
        set_key(ENV_FILE, 'VT_API_KEY', args.set_vtkey)
        print("[+] VirusTotal API key disimpan.")

    if args.set_dashboard:
        set_key(ENV_FILE, 'REPORT_DASHBOARD', args.set_dashboard)
        print("[+] Dashboard endpoint disimpan.")

    if args.api:
        print("[+] Menjalankan mode API...")
        app.run(host='0.0.0.0', port=5000)
        return

    if args.monitor:
        scanner.monitor_directory()
        return

    all_results = []

    if args.list:
        with open(args.list) as f:
            urls = [line.strip() for line in f if line.strip()]
            all_results = [scanner.scan_url(url) for url in urls]
    elif args.file:
        result = scanner.scan_file_content(args.file)
        all_results = [result]
    elif args.url:
        result = scanner.scan_url(args.url)
        all_results = [result]
    else:
        print("[!] Tidak ada input yang diberikan.")
        return

    for result in all_results:
        report = scanner.generate_text_report(result)
        if args.output:
            with open(args.output, 'a') as f:
                f.write(report + '\n' + '='*40 + '\n')
        else:
            print(report)

if __name__ == '__main__':
    main()
