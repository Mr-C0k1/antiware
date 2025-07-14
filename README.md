# 🕷️ AntiWare - Website Threat & Malware Scanner
📌 Ringkasan
AntiWare adalah sebuah alat keamanan siber otomatis yang digunakan untuk melakukan website vulnerability scanning dan mendeteksi skrip berbahaya (seperti malware, ransomware, dan backdoor) pada:
Website/URL online File lokal (HTML, JS, PHP, dll). File yang terindikasi malware atau obfuscation File hasil upload pengguna (CTF/web pentest) tool ini memiliki 3 mode utama:
1. CLI (Command Line Interface)
2. API Mode (RESTful)
3.GUI Mode (User Interface visual)

🛠️ Tujuan & Kegunaan
AntiWare diciptakan untuk:
✅ Mempermudah pengujian keamanan website secara otomatis & cepat
✅ Membantu pentester dan sysadmin mengidentifikasi celah web yang umum dan berbahaya
✅ Mengedukasi pengguna tentang tanda-tanda serangan siber berbasis web
✅ Menjadi alat alternatif lightweight selain scanner besar seperti BurpSuite atau OWASP ZAP
✅ Bisa diintegrasikan ke CI/CD atau scan otomatis website client

🔎 Ancaman yang Dapat Dideteksi
AntiWare tidak hanya memeriksa bug klasik, tapi juga ancaman modern dan terkini, seperti:

Tipe Ancaman	Deskripsi
🛑 Malware Injection	Deteksi <script> asing dari domain mencurigakan
🔐 Ransomware Behavior	Mendeteksi file encrypt.php atau pola enkripsi massal
🐚 Backdoor Upload	Waspadai file shell.php, cmd.php, r57.php yang sering dipakai attacker
⛏️ Cryptojacking	Deteksi mining script seperti coinhive, mining.js
🧊 iFrame Phishing	iFrame dari domain luar yang menyematkan konten tidak aman
🚨 0-Day Pattern Match	Pola eval(base64_decode...), unauthorized_access, debug, dll

⚙️ Cara Kerja Teknologi
Input URL atau File Scan halaman HTML/JS target Ekstrak seluruh isi konten Pattern Matching (Regex), Mencocokkan konten terhadap daftar threat signatures (regex) Hasil ScanJika cocok: data disimpan → log → dashboard → laporan JSON/TXT. VirusTotal Integration Mengecek URL terhadap database global VirusTotal (opsional) Laporan & Upload Laporan disimpan lokal (antiware_reports/) dan bisa dikirim ke dashboard eksternal.

🧠 Keunggulan AntiWare
Fitur	Keterangan
✅ CLI/GUI/API Mode	Bisa digunakan dari terminal, REST API, atau antarmuka grafis
🚀 Fast Lightweight	Lebih cepat dari tools besar karena tidak membuat DOM atau overhead berat
🌐 Integrasi VirusTotal	Cek reputasi domain atau URL target secara real-time
📄 Output JSON + TXT	Bisa diintegrasikan dengan script lain atau CI/CD
🔐 Konfigurasi Mudah	API Key, token, dan endpoint dapat diatur langsung lewat CLI
🎨 Logo & Branding	Menampilkan logo visual di CLI (segi enam + laba-laba)
**AntiWare** adalah alat keamanan siber open-source untuk mendeteksi ancaman berbasis web secara otomatis, termasuk:
- malware injection,
- ransomware script,
- backdoor shell,
- cryptojacking,
- serta pola eksploitasi 0-day.

AntiWare dapat dijalankan dalam mode CLI (Command Line) dan GUI, serta dapat diinstal sebagai aplikasi `.deb` seperti tools resmi di Kali Linux.

Scan result for https://vulnerable-site.com:
Time: 2025-07-14T12:00:00Z

- Malware Injection (CVE: CVE-2023-28546)
  Description: Indikasi injeksi script malware obfuscated.
  Solution: Hapus script, update CMS, dan audit server.

- Cryptojacking Script (CVE: CVE-2018-1000402)
  Description: Script mining crypto ilegal ditemukan.
  Solution: Blokir domain mining, hapus script, dan update patch.

  AntiWare dilengkapi **antarmuka CLI dan GUI**, mendukung integrasi **VirusTotal**, serta kompatibel dijalankan di sistem operasi Linux (termasuk Kali Linux).

---

## 🎯 Fitur Utama

- 🔍 Scan otomatis terhadap URL dan file lokal
- 📄 Output dalam format teks & JSON
- 🌐 Dukungan API Server & GUI
- 🛡️ Integrasi VirusTotal (API Key opsional)
- ☁️ Upload hasil ke dashboard eksternal (jika disetel)
- 🎨 Tampilan logo saat tools dijalankan
- 🖥️ File `.desktop` untuk launcher GUI
- 📦 Installer `.deb` (opsional)

---

## 🧰 Kebutuhan Sistem

- Python 3.6+
- Modul: `requests`, `flask`, `bs4`, `PIL`, `dotenv`
```bash
pip install -r requirements.txt --break-system-pakages ( jika pip anda bermasalah di GNU kali linux atau ubuntu. )

#sistematika instalasi github debian
git clone https://github.com/Mr-C0k1/antiware.git
cd antiware
chmod +x install_antiware.sh
./install_antiware.sh >> or bash command
pip install -r requirements.txt --break-system-pakages ( jika pip anda bermasalah di GNU kali linux atau ubuntu. )
antiware https://targetwebsite.com >>> running command

#FILE SCAN MODE
antiware -f suspicious_file.html
antiware -l list_url.txt

#API Mode
antiware --api
Endpoint aktif di: http://localhost:5000/api/scan

#Gunakan header:
(pgsql)
Authorization: Bearer <token>
Content-Type: application/json

#GUI Interface (Opsional)
Jika ingin menggunakan GUI:
python3 antiware_gui.py

# GUI Mode
python3 /opt/antiware/antiware_gui.py

#contoh output
{
  "url": "http://example.com",
  "scan_time": "2025-07-14T12:20:00Z",
  "vulnerabilities": [
    {
      "type": "Backdoor Upload",
      "cve": "CVE-2023-23924",
      "description": "File backdoor populer ditemukan di path web.",
      "solution": "Hapus file, audit akses file, dan pasang Web Application Firewall."
    }
  ]
}





  
