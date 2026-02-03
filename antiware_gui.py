import sys
import json
import subprocess
import signal
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QTextCursor

class ScanWorker(QThread):
    output_received = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None

    def run(self):
        try:
            # Menggunakan Popen agar bisa di-terminate nantinya
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid # Penting untuk kill seluruh group process di Linux
            )

            full_output = ""
            for line in self.process.stdout:
                self.output_received.emit(line.strip())
                full_output += line

            self.process.wait()
            
            try:
                json_start = full_output.find('{')
                if json_start != -1:
                    data = json.loads(full_output[json_start:])
                    self.finished.emit(data)
            except:
                self.finished.emit({})

        except Exception as e:
            self.output_received.emit(f"CRITICAL: Error executing scan: {str(e)}")

    def stop(self):
        """Menghentikan proses scanning secara paksa"""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.output_received.emit("WARNING: Scanning dihentikan oleh pengguna.")
            except Exception as e:
                self.output_received.emit(f"ERROR: Gagal menghentikan proses: {e}")

class AntiWareGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AntiWare Scanner Pro - Engine v2.1")
        self.setGeometry(300, 200, 900, 650)
        self.setStyleSheet("background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', Arial;")

        layout = QVBoxLayout()

        # Input Area
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Masukkan URL target (Contoh: https://target.com)")
        self.url_input.setStyleSheet("""
            padding: 12px; background: #1e1e1e; border: 1px solid #333; 
            border-radius: 5px; color: #00ff00; font-weight: bold;
        """)
        layout.addWidget(QLabel("Target Vulnerability URL:"))
        layout.addWidget(self.url_input)

        # Button Layout
        btn_layout = QHBoxLayout()
        
        self.btn_start = QPushButton("🚀 START SCAN")
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_start.setStyleSheet("background: #1b5e20; color: white; padding: 12px; font-weight: bold; border-radius: 5px;")
        
        self.btn_stop = QPushButton("🛑 STOP SCAN")
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background: #b71c1c; color: white; padding: 12px; font-weight: bold; border-radius: 5px;")
        
        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        layout.addLayout(btn_layout)

        # Output Area (HTML Enabled)
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("""
            background-color: #000000; border: 1px solid #444; 
            font-family: 'Consolas', 'Courier New'; font-size: 13px;
        """)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def log(self, message):
        """Fungsi log cerdas dengan deteksi warna berbasis HTML"""
        msg_lower = message.lower()
        
        # Logika Warna Berdasarkan Keyword
        if "critical" in msg_lower or "rce" in msg_lower:
            color = "#ff1744" # Bright Red
            prefix = "<b>[CRITICAL]</b>"
        elif "high" in msg_lower or "xss" in msg_lower:
            color = "#ff9100" # Orange
            prefix = "<b>[HIGH]</b>"
        elif "medium" in msg_lower:
            color = "#ffea00" # Yellow
            prefix = "<b>[MEDIUM]</b>"
        elif "warning" in msg_lower or "error" in msg_lower:
            color = "#f44336" # Soft Red
            prefix = "[!]"
        elif "✅" in message or "selesai" in msg_lower:
            color = "#00e676" # Green
            prefix = "[+]"
        else:
            color = "#ffffff" # White (Default)
            prefix = "[>]"

        formatted_msg = f"<span style='color:{color};'>{prefix} {message}</span>"
        self.output_area.append(formatted_msg)
        
        # Auto-scroll
        self.output_area.moveCursor(QTextCursor.End)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.log("ERROR: URL target tidak boleh kosong!")
            return

        self.output_area.clear()
        self.log(f"Menginisialisasi engine untuk target: {url}")
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

        # Menjalankan script eksternal
        self.worker = ScanWorker(['python3', 'antiware_advanced.py', url])
        self.worker.output_received.connect(self.log)
        self.worker.finished.connect(self.scan_complete)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.btn_stop.setEnabled(False)
            self.btn_start.setEnabled(True)

    def scan_complete(self, data):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("✅ Pemindaian selesai sepenuhnya.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = AntiWareGUI()
    gui.show()
    sys.exit(app.exec_())
