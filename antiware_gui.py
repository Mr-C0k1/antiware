#!/usr/bin/env python3
"""
AntiWare GUI - Antarmuka Grafis untuk Website Threat Scanner
"""

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
import subprocess
import sys

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

        self.scan_button = QPushButton("Scan Sekarang", self)
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button)

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def run_scan(self):
        url = self.url_input.text()
        if not url.strip():
            self.output_area.setText("⚠️ Masukkan URL terlebih dahulu.")
            return
        try:
            # Jalankan antiware via CLI
            output = subprocess.check_output(['antiware', url], stderr=subprocess.STDOUT, text=True)
            self.output_area.setText(output)
        except subprocess.CalledProcessError as e:
            self.output_area.setText(f"[!] Error:\n{e.output}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = AntiWareGUI()
    gui.show()
    sys.exit(app.exec_())
