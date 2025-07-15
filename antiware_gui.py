#!/usr/bin/env python3
"""
AntiWare GUI - Antarmuka Grafis untuk Website Threat Scanner
Mendukung deteksi Ransomware, Malware, Website Vulnerability, dan Valid Virus Scanner
Dengan indikator warna tingkat risiko dan CVE lookup
"""

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog
)
from PyQt5.QtGui import QTextCharFormat, QColor
from PyQt5.QtCore import Qt
import subprocess
import sys
import os
import json
import re
import requests

class AntiWareGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiWare Scanner GUI")
        self.setGeometry(300, 200, 720, 520)

        layout = QVBoxLayout()

        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Masukkan URL target (misal: https://example.com)")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)

        self.scan_button = QPushButton("Scan Ransomware Website & Deteksi Kunci Enkripsi", self)
        self.scan_button.clicked.connect(self.run_ransomware_website_scan)
        layout.addWidget(self.scan_button)

        self.malware_button = QPushButton("Deteksi Malware & Signature", self)
        self.malware_button.clicked.connect(self.run_malware_scan)
        layout.addWidget(self.malware_button)

        self.deep_button = QPushButton("Deteksi Virus Valid & Advanced", self)
        self.deep_button.clicked.connect(self.run_deep_analysis)
        layout.addWidget(self.deep_button)

        self.upload_button = QPushButton("Unggah File & Scan CVE", self)
        self.upload_button.clicked.connect(self.run_file_upload_scan)
        layout.addWidget(self.upload_button)

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def scan_ransomware_site(self, url):
        result = {
            "url": url,
            "attacker_ip": None,
            "encryption_algorithm": None,
            "ransom_key_hint": None,
            "suspicious_file": None
        }
        try:
            response = requests.get(url, timeout=10)
            html = response.text

            # Cek alamat IP penyerang dari ransom note (simulasi)
            ip_match = re.findall(r'(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})', html)
            if ip_match:
                result['attacker_ip'] = ip_match[0]

            # Deteksi algoritma enkripsi yang digunakan
            if "AES-256" in html:
                result['encryption_algorithm'] = "AES-256"
            elif "RSA" in html:
                result['encryption_algorithm'] = "RSA"

            # Petunjuk kunci ransom
            ransom_hint = re.findall(r'key=[a-zA-Z0-9+/=]{32,}', html)
            if ransom_hint:
                result['ransom_key_hint'] = ransom_hint[0]

            # Deteksi file mencurigakan
            if "ransom_note.txt" in html or "decrypt_instructions.html" in html:
                result['suspicious_file'] = "ransom_note.txt"

        except Exception as e:
            result["error"] = str(e)

        return result

    def run_ransomware_website_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.output_area.setText("⚠️ Masukkan URL terlebih dahulu.")
            return
        try:
            result = self.scan_ransomware_site(url)
            output = json.dumps(result, indent=2)
            self.render_output(output, scan_type="ransomwareweb")
        except Exception as e:
            self.output_area.setText(f"[!] Error saat scanning ransomware website:\n{str(e)}")

    def run_malware_scan(self):
        try:
            output = subprocess.check_output(
                ['python3', 'aware.py'],
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_area.setText("🛡️ Hasil Deteksi Malware:\n\n" + output)
        except subprocess.CalledProcessError as e:
            self.output_area.setText(f"[!] Error saat scan malware:\n{e.output}")
        except FileNotFoundError:
            self.output_area.setText("❌ File 'aware.py' tidak ditemukan. Pastikan file tersebut ada.")

    def run_deep_analysis(self):
        url = self.url_input.text().strip()
        if not url:
            self.output_area.setText("⚠️ Masukkan URL terlebih dahulu.")
            return
        try:
            output = subprocess.check_output(
                ['python3', 'antiware_advanced.py', url],
                stderr=subprocess.STDOUT,
                text=True
            )
            self.render_output(output, scan_type="advanced")
        except subprocess.CalledProcessError as e:
            self.output_area.setText(f"[!] Error saat deep analysis:\n{e.output}")
        except FileNotFoundError:
            self.output_area.setText("❌ File 'antiware_advanced.py' tidak ditemukan.")

    def run_file_upload_scan(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Pilih file untuk discan", "", "All Files (*)")
        if file_path:
            self.output_area.setText(f"📂 File terpilih: {file_path}\n\n🔎 (simulasi) CVE Lookup untuk file ini belum diimplementasikan secara penuh.")

    def render_output(self, output, scan_type):
        try:
            parsed = json.loads(output)
            if scan_type == "ransomwareweb":
                ip = parsed.get('attacker_ip', 'Tidak ditemukan')
                algo = parsed.get('encryption_algorithm', 'Tidak terdeteksi')
                ransom_key = parsed.get('ransom_key_hint', 'Tidak diketahui')
                file_hint = parsed.get('suspicious_file', '-')
                self.output_area.setText(
                    f"🛡️ Hasil Deteksi Ransomware Website:\n\n"
                    f"🔍 IP Penyerang: {ip}\n"
                    f"🔐 Algoritma Kriptografi: {algo}\n"
                    f"🧩 Petunjuk Kunci: {ransom_key}\n"
                    f"📄 Lokasi File Terkait: {file_hint}\n"
                )
            else:
                vuln_list = parsed.get('vulnerabilities', [])
                vuln_count = len(vuln_list)
                summary = f"✅ Total Deteksi: {vuln_count} kerentanan ditemukan\n\n"
                detail = ""
                for vuln in vuln_list:
                    severity = vuln.get("severity", "unknown").lower()
                    color = {
                        "low": "🟢", "medium": "🟡", "high": "🔴"
                    }.get(severity, "⚪")
                    detail += f"{color} [{severity.upper()}] {vuln.get('type')}\n - {vuln.get('description')}\n\n"
                self.output_area.setText(summary + detail)
        except Exception:
            self.output_area.setText(output)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = AntiWareGUI()
    gui.show()
    sys.exit(app.exec_())
