#!/usr/bin/env python3
"""
AntiWare GUI - Antarmuka Grafis untuk Website Threat Scanner
Mendukung deteksi Ransomware, Malware, Website Vulnerability, dan Valid Virus Scanner
"""

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
import subprocess
import sys
import os

class AntiWareGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiWare Scanner GUI")
        self.setGeometry(300, 200, 640, 400)

        layout = QVBoxLayout()

        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Masukkan URL target (misal: https://example.com)")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)

        self.scan_button = QPushButton("Scan Website & Vulnerability", self)
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button)

        self.malware_button = QPushButton("Deteksi Ransomware / Malware", self)
        self.malware_button.clicked.connect(self.run_malware_scan)
        layout.addWidget(self.malware_button)

        self.deep_button = QPushButton("Deteksi Virus Valid & Advanced", self)
        self.deep_button.clicked.connect(self.run_deep_analysis)
        layout.addWidget(self.deep_button)

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def run_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.output_area.setText("⚠️ Masukkan URL terlebih dahulu.")
            return
        try:
            output = subprocess.check_output(
                ['python3', 'antiware.py', url],
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_area.setText(output)
        except subprocess.CalledProcessError as e:
            self.output_area.setText(f"[!] Error:\n{e.output}")
        except FileNotFoundError:
            self.output_area.setText("❌ File 'antiware.py' tidak ditemukan di direktori saat ini.")

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
            self.output_area.setText("🔬 Hasil Deep Analysis (Valid Virus/Vuln):\n\n" + output)
        except subprocess.CalledProcessError as e:
            self.output_area.setText(f"[!] Error saat deep analysis:\n{e.output}")
        except FileNotFoundError:
            self.output_area.setText("❌ File 'antiware_advanced.py' tidak ditemukan.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = AntiWareGUI()
    gui.show()
    sys.exit(app.exec_())
