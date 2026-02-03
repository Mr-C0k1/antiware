#!/usr/bin/env python3
import re
import requests
import random
import time
import argparse
import json
import sys
import threading
import signal
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# --- KONFIGURASI GLOBAL ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36"
]

FUZZ_WORDLIST = [
    ".env", ".git/config", "backup.sql", "config.php", "phpinfo.php", 
    "node_modules", ".vscode/sftp.json", "setup.zip", ".htaccess", "db.sql"
]

class AntiWareEngine:
    def __init__(self, target, threads, stealth, vt_key):
        self.target = target.rstrip('/')
        self.threads = threads
        self.stealth = stealth
        self.vt_key = vt_key
        self.delay = 1.0 if stealth else 0.1
        self.found_issues = []
        self.discovered_assets = {self.target}
        self.is_running = True
        self.lock = threading.Lock()
        self.session = requests.Session()

    # --- HANDLER EXIT (CTRL+C) ---
    def stop_engine(self):
        print(f"\n\n[!] Menangkap sinyal interupsi. Menghentikan aktivitas...")
        self.is_running = False

    def get_headers(self):
        return {'User-Agent': random.choice(USER_AGENTS), 'Referer': self.target}

    def safe_request(self, url):
        if not self.is_running: return None
        try:
            if self.stealth:
                time.sleep(random.uniform(self.delay, self.delay + 1))
            
            resp = self.session.get(url, headers=self.get_headers(), timeout=10)
            
            # Adaptive Rate Limit Detection
            if resp.status_code in [429, 403] and self.stealth:
                print(f"    [!] Limit terdeteksi di {url}. Cooldown...")
                self.delay += 2.0
                time.sleep(5)
                return self.safe_request(url)
            
            return resp
        except Exception:
            return None

    # --- MODULE: VIRUSTOTAL ---
    def check_vt(self, url):
        if not self.vt_key: return "N/A"
        headers = {"x-apikey": self.vt_key}
        try:
            # Menggunakan endpoint v3 untuk URL analysis
            api_url = "https://www.virustotal.com/api/v3/urls"
            res = requests.post(api_url, data={"url": url}, headers=headers, timeout=10)
            stats = res.json()['data']['attributes']['last_analysis_stats']
            return f"Malicious: {stats.get('malicious', 0)}"
        except:
            return "Error/Quota"

    # --- MODULE: FUZZER ---
    def fuzz_path(self, path):
        if not self.is_running: return
        full_url = f"{self.target}/{path}"
        resp = self.safe_request(full_url)
        if resp and resp.status_code == 200:
            with self.lock:
                print(f"    [!!!] SENSITIF DITEMUKAN: {full_url}")
                self.found_issues.append({"type": "Fuzz Discovery", "url": full_url})

    # --- CORE ENGINE ---
    def run_scan(self):
        print(f"[*] Memulai AntiWare Pro pada: {self.target}")
        print(f"[*] Konfigurasi: Threads={self.threads}, Stealth={self.stealth}")
        print("[*] Tekan CTRL+C untuk menghentikan paksa dan melihat laporan sementara.\n")

        # 1. Fuzzing Module
        print("[+] Tahap 1: Menjalankan Stealth Fuzzer...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.fuzz_path, FUZZ_WORDLIST)

        # 2. VirusTotal Check pada Target Utama
        if self.vt_key:
            print("[+] Tahap 2: Mengecek Reputasi VirusTotal...")
            vt_res = self.check_vt(self.target)
            print(f"    [-] Hasil VT: {vt_res}")

        self.generate_report()

    def generate_report(self):
        print("\n" + "="*40)
        print("         LAPORAN SCAN ANTIWARE")
        print("="*40)
        print(f"Target: {self.target}")
        print(f"Total Temuan: {len(self.found_issues)}")
        for issue in self.found_issues:
            print(f"- [{issue['type']}] {issue['url']}")
        print("="*40)

# --- CLI HANDLER ---
def main():
    parser = argparse.ArgumentParser(
        description='AntiWare Pro - Engineering Stealth Toolkit',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('url', help='URL Target (https://site.com)')
    parser.add_argument('--stealth', action='store_true', help='Aktifkan Adaptive Rate Limiting')
    parser.add_argument('--fuzz', action='store_true', help='Jalankan Fuzzer file sensitif')
    parser.add_argument('--threads', type=int, default=3, help='Jumlah Thread')
    parser.add_argument('--vt', metavar='KEY', help='VirusTotal API Key')

    args = parser.parse_args()

    engine = AntiWareEngine(args.url, args.threads, args.stealth, args.vt)

    # Tangkap CTRL+C (signal.SIGINT)
    signal.signal(signal.SIGINT, lambda sig, frame: engine.stop_engine() or sys.exit(0))

    engine.run_scan()

if __name__ == "__main__":
    main()
