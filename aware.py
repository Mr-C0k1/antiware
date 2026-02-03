#!/usr/bin/env python3
import asyncio
import aiohttp
import re
import time
import sys
import json
from urllib.parse import urljoin

class AntiWareAsyncScanner:
    def __init__(self):
        self.findings = []
        self.start_time = None
        
        # Payload untuk pengecekan file sensitif secara massal
        self.paths_to_check = [
            '/.env', '/wp-config.php.bak', '/.git/config', '/shell.php',
            '/admin.php', '/config.php.swp', '/backup.sql', '/.vscode/sftp.json',
            '/phpinfo.php', '/info.php', '/cmd.jsp', '/index.php.bak'
        ]

    def log(self, level, message):
        colors = {'CRITICAL': '\033[91m', 'HIGH': '\033[93m', 'INFO': '\033[94m', 'RESET': '\033[0m'}
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {colors.get(level, '')}[{level}]{colors.get('RESET')} {message}", flush=True)

    async def check_path(self, session, base_url, path):
        """Mengecek keberadaan file secara real-time"""
        url = urljoin(base_url, path)
        try:
            async with session.head(url, timeout=5, allow_redirects=False) as response:
                if response.status == 200:
                    self.log('CRITICAL', f"FILE SENSITIF DITEMUKAN: {url}")
                    self.findings.append({'type': 'Exposed File', 'url': url, 'severity': 'CRITICAL'})
                elif response.status == 403:
                    self.log('HIGH', f"Access Forbidden (Terdeteksi Direktori): {url}")
        except:
            pass

    async def analyze_content(self, session, url):
        """Menganalisis konten halaman utama untuk malware secara real-time"""
        try:
            async with session.get(url, timeout=10) as response:
                html = await response.text()
                
                # Deteksi Malware Signature (Heuristic)
                if re.search(r'(eval\(base64|system\(|shell_exec\(|passthru\()', html):
                    self.log('CRITICAL', f"Malware Signature terdeteksi di konten: {url}")
                    self.findings.append({'type': 'Malware Injection', 'severity': 'CRITICAL'})
                
                # Cek Header
                if 'Content-Security-Policy' not in response.headers:
                    self.log('INFO', "CSP Header tidak ditemukan (Info)")
        except Exception as e:
            self.log('CRITICAL', f"Gagal menganalisis konten: {str(e)}")

    async def run_scan(self, target_url):
        self.start_time = time.time()
        self.log('INFO', f"Memulai Async Scan pada {target_url}...")

        # Menggunakan TCPConnector untuk membatasi jumlah koneksi agar tidak dianggap DDoS
        connector = aiohttp.TCPConnector(limit=50) 
        async with aiohttp.ClientSession(connector=connector) as session:
            # Membuat list tugas (tasks)
            tasks = []
            
            # Tugas 1: Analisis Konten
            tasks.append(self.analyze_content(session, target_url))
            
            # Tugas 2: Fuzzing Direktori Massal
            for path in self.paths_to_check:
                tasks.append(self.check_path(session, target_url, path))
            
            # Menjalankan semua tugas secara paralel
            await asyncio.gather(*tasks)

        duration = time.time() - self.start_time
        print(f"\n--- Scan Selesai dalam {duration:.2f} detik ---")
        print(f"Total Kerentanan Real-time: {len(self.findings)}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 antiware_async.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    scanner = AntiWareAsyncScanner()
    asyncio.run(scanner.run_scan(target))
