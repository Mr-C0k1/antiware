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
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv, set_key
from PIL import Image

# Load konfigurasi dari .env
ENV_FILE = '.env'
load_dotenv(ENV_FILE)

if not os.path.exists(ENV_FILE):
    with open(ENV_FILE, 'w') as f:
        f.write('API_TOKEN=changeme\nVT_API_KEY=your_virustotal_key\nREPORT_DASHBOARD=https://dashboard.example.com/api/report\n')

# Logging
logging.basicConfig(
    filename='antiware_scanner.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

REPORT_DIR = 'antiware_reports'
os.makedirs(REPORT_DIR, exist_ok=True)

# Flask app untuk API
app = Flask(__name__)
app.config['API_TOKEN'] = os.getenv('API_TOKEN', 'changeme')
app.config['VT_API_KEY'] = os.getenv('VT_API_KEY', 'your_virustotal_key')
app.config['REPORT_DASHBOARD'] = os.getenv('REPORT_DASHBOARD', 'https://dashboard.example.com/api/report')

# Logo
def tampilkan_logo():
    print("""
 █████╗ ███╗   ██╗████████╗██╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗████╗  ██║╚══██╔══╝██║██║    ██║██╔══██╗██╔══██╗██╔════╝
███████║██╔██╗ ██║   ██║   ██║██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██║██║╚██╗██║   ██║   ██║██║███╗██║██╔══██║██╔═══╝ ██╔══╝  
██║  ██║██║ ╚████║   ██║   ██║╚███╔███╔╝██║  ██║██║     ███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚══════╝
    Website Threat & Malware Scanner
    """)

class AntiWareScanner:
    def __init__(self):
        self.threat_patterns = [
            {
                'type': 'Malicious Script',
                'pattern': r'<script[^>]*src=[\"\']http.*?(obfuscated|malicious)',
                'description': 'Script mencurigakan ditemukan dalam HTML',
                'solution': 'Hapus script mencurigakan, update plugin'
            },
            {
                'type': 'Shell Upload',
                'pattern': r'(r57|c99|cmd)\.php',
                'description': 'Shell backdoor ditemukan',
                'solution': 'Hapus file, audit file permission'
            }
        ]

    def scan_url(self, url):
        result = {
            'url': url,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': []
        }
        try:
            r = requests.get(url, timeout=10)
            html = r.text
            for rule in self.threat_patterns:
                if re.search(rule['pattern'], html, re.IGNORECASE):
                    result['vulnerabilities'].append(rule)
        except Exception as e:
            result['error'] = str(e)
        self.save_report(result)
        return result

    def save_report(self, data):
        filename = os.path.join(REPORT_DIR, f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        logging.info(f"Report saved to {filename}")

# API endpoint
@app.route('/api/scan', methods=['POST'])
def api_scan():
    token = request.headers.get('Authorization')
    if token != f"Bearer {app.config['API_TOKEN']}":
        return jsonify({'error': 'Unauthorized'}), 401
    url = request.json.get('url')
    scanner = AntiWareScanner()
    result = scanner.scan_url(url)
    return jsonify(result)

def main():
    tampilkan_logo()
    parser = argparse.ArgumentParser(description='AntiWare - Web Threat Scanner')
    parser.add_argument('url', nargs='?', help='URL yang akan discan')
    parser.add_argument('--api', action='store_true', help='Jalankan sebagai REST API')
    args = parser.parse_args()

    if args.api:
        app.run(host='0.0.0.0', port=5000)
        return

    if not args.url:
        print("[!] URL tidak diberikan.")
        return

    scanner = AntiWareScanner()
    result = scanner.scan_url(args.url)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
