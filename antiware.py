#!/usr/bin/env python3
"""
GreenWare - Website Threat & Malware Scanner (CLI & API)
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
import sys
import base64

# Load dan buat konfigurasi
ENV_FILE = '.env'
if not os.path.exists(ENV_FILE):
    with open(ENV_FILE, 'w') as f:
        f.write('API_TOKEN=changeme\nVT_API_KEY=your_virustotal_key\nREPORT_DASHBOARD=https://dashboard.example.com/api/report\n')

load_dotenv(ENV_FILE)

# Setup logging
logging.basicConfig(
    filename='greenware_scanner.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

REPORT_DIR = 'greenware_reports'
os.makedirs(REPORT_DIR, exist_ok=True)

app = Flask(__name__)
app.config['API_TOKEN'] = os.getenv('API_TOKEN', 'changeme')
app.config['VT_API_KEY'] = os.getenv('VT_API_KEY', 'your_virustotal_key')
app.config['REPORT_DASHBOARD'] = os.getenv('REPORT_DASHBOARD', 'https://dashboard.example.com/api/report')

class GreenWareScanner:
    def __init__(self):
        self.threat_patterns = [
            {
                'type': 'Ransomware Behavior',
                'pattern': r'encrypt\\.(php|asp|js)',
                'cve': 'CVE-2022-26134',
                'description': 'Script mencurigakan yang mencoba mengenkripsi file secara massal.',
                'solution': 'Isolasi server dan periksa backup. Blokir script dan ganti kredensial.'
            },
            {
                'type': 'Malware Injection',
                'pattern': r'<script[^>]+src=["\']?https?://[^>]*obfuscated',
                'cve': 'CVE-2023-28546',
                'description': 'Indikasi injeksi script malware obfuscated dari domain tidak dikenal.',
                'solution': 'Hapus script mencurigakan, update CMS/plugin, dan scan file server.'
            },
            {
                'type': 'Backdoor Upload',
                'pattern': r'(shell\\.php|cmd\\.php|r57\\.php)',
                'cve': 'CVE-2023-23924',
                'description': 'File backdoor populer ditemukan di path web.',
                'solution': 'Hapus file, audit akses file, dan pasang Web Application Firewall.'
            },
            {
                'type': 'Cryptojacking Script',
                'pattern': r'coinhive|crypto-miner|mining\\.js',
                'cve': 'CVE-2018-1000402',
                'description': 'Script mining crypto ilegal ditemukan.',
                'solution': 'Blokir domain mining, hapus script, dan update patch CMS.'
            },
            {
                'type': 'Suspicious iFrame',
                'pattern': r'<iframe[^>]+src=["\']?https?://[^\s]+',
                'cve': 'CVE-2019-6339',
                'description': 'iFrame mencurigakan bisa jadi phishing/malware injection.',
                'solution': 'Verifikasi sumber iframe, pastikan tidak menyematkan domain luar yang tidak dikenal.'
            },
            {
                'type': '0-Day Pattern Match',
                'pattern': r'(webadmin|debug|unauthorized_access|eval\\(base64_decode)',
                'cve': 'POTENTIAL-0DAY',
                'description': 'Kemungkinan eksploitasi 0-day atau backdoor umum.',
                'solution': 'Segera isolasi sistem, laporkan ke vendor terkait dan gunakan patch virtual.'
            }
        ]

    def normalize_url(self, url):
        if not url.startswith('http'):
            return 'http://' + url
        return url

    def scan_url(self, url):
        url = self.normalize_url(url)
        logging.info(f"[Scan] {url}")
        result = {
            'url': url,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': []
        }
        try:
            response = requests.get(url, timeout=10)
            html_content = response.text
            for rule in self.threat_patterns:
                if re.search(rule['pattern'], html_content, re.IGNORECASE):
                    result['vulnerabilities'].append({
                        'type': rule['type'],
                        'cve': rule['cve'],
                        'description': rule['description'],
                        'solution': rule['solution'],
                        'detected_on': url
                    })
            self.virustotal_check(url, result)
        except requests.RequestException as e:
            logging.error(f"[Error] {e}")
            result['error'] = str(e)

        self.save_json_report(result)
        self.send_to_dashboard(result)
        return result

    def virustotal_check(self, url, result):
        api_key = app.config['VT_API_KEY']
        if not api_key or api_key == 'your_virustotal_key':
            return
        try:
            resp = requests.get(
                'https://www.virustotal.com/api/v3/urls',
                headers={'x-apikey': api_key},
                params={'url': url}
            )
            if resp.status_code == 200:
                result['virustotal'] = resp.json()
        except Exception as e:
            logging.error(f"[VirusTotal] {e}")

    def send_to_dashboard(self, result):
        dashboard_url = app.config['REPORT_DASHBOARD']
        try:
            resp = requests.post(dashboard_url, json=result, timeout=10)
            if resp.status_code in [200, 201]:
                logging.info("[Dashboard] Report uploaded")
            else:
                logging.warning(f"[Dashboard] Failed to upload: {resp.status_code}")
        except Exception as e:
            logging.error(f"[Dashboard] {e}")

    def save_json_report(self, result):
        name = result.get('url')
        identifier = urlparse(name).netloc.replace(':', '_') if 'url' in result else os.path.basename(name)
        fname = os.path.join(REPORT_DIR, f"{identifier}.json")
        with open(fname, 'w') as f:
            json.dump(result, f, indent=2)
        logging.info(f"[Report] Saved to {fname}")

@app.route('/api/scan', methods=['POST'])
def api_scan():
    token = request.headers.get('Authorization')
    if not token or token != f"Bearer {app.config['API_TOKEN']}":
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'Missing URL'}), 400
    scanner = GreenWareScanner()
    result = scanner.scan_url(url)
    return jsonify(result)

def main():
    parser = argparse.ArgumentParser(description='GreenWare Website Threat Detector')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('--api', nargs='?', const=True, help='Run as API server (optional token)')
    args = parser.parse_args()

    if args.api:
        if args.api is not True:
            set_key(ENV_FILE, 'API_TOKEN', args.api)
            print(f'[✔] API Token set to {args.api}')
            load_dotenv(ENV_FILE, override=True)
            app.config['API_TOKEN'] = os.getenv('API_TOKEN')
        print("[✓] Running GreenWare API server on http://0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000)
        return

    if not args.url:
        print("[!] Target URL is required.")
        return

    scanner = GreenWareScanner()
    result = scanner.scan_url(args.url)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
