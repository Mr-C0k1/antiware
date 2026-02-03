AntiWare Pro: Advanced Security Research & Evasion Engine
AntiWare Pro adalah framework pengujian keamanan (Penetration Testing) berbasis Python yang dirancang khusus untuk melakukan audit kerentanan pada infrastruktur web berskala besar. Alat ini mengintegrasikan teknik evasion tingkat tinggi untuk melewati proteksi WAF (Web Application Firewall) modern dan melakukan validasi eksploitasi secara Out-of-Band (OOB).

🛡️ Fitur Utama
Advanced Evasion Engine: Melakukan transformasi payload secara dinamis (Double Encoding, Case Flipping, Null Byte Injection) untuk meminimalisir deteksi signature-based pada WAF.

Adaptive Timing Control: Algoritma jeda cerdas (Jittering) untuk meniru perilaku navigasi manusia, efektif melewati sistem anti-bot dan rate-limiting.

Asynchronous High-Performance: Dibangun di atas asyncio dan aiohttp untuk pemindaian massal yang cepat tanpa mengorbankan stabilitas sistem.

Out-of-Band (OOB) Validation: Integrasi dengan server kolaborator eksternal untuk memverifikasi kerentanan (RCE/SSRF) saat respons in-band diblokir oleh firewall.

Identity Spoofing: Rotasi otomatis pada User-Agent, X-Forwarded-For, dan headers lainnya untuk menjaga anonimitas fingerprint.

🚀 Instalasi
Pastikan sistem Anda telah terinstal Python 3.9+ dan pengelola paket pip.

Clone Repositori:

Bash
git clone https://github.com/username/antiware-pro.git
cd antiware-pro
Instal Dependensi:

Bash
pip install -r requirements.txt
(Library utama: aiohttp, beautifulsoup4, fake-useragent, PyQt5)

Berikan Izin Eksekusi:

Bash
chmod +x antiware.py
🛠️ Panduan Penggunaan
1. Penggunaan CLI (Mode Cepat)
Gunakan CLI untuk pemindaian langsung dari terminal dengan output real-time.

Bash
python3 antiware.py https://target-enterprise.com
2. Penggunaan GUI (Mode Dashboard)
Jalankan antarmuka grafis untuk pemantauan hasil yang lebih visual dan manajemen kontrol (Start/Stop).

Bash
python3 antiware_gui.py
3. Konfigurasi Research Engine
Untuk riset mendalam pada website dengan firewall ketat, Anda dapat memodifikasi parameter pada config.py atau langsung di dalam class AntiWarePro:

Set Proxy: Aktifkan use_proxy=True untuk menggunakan rotasi IP.

Set OOB Server: Masukkan domain Interact.sh Anda pada variabel oob_domain.

Adjust Timing: Atur min_delay dan max_delay sesuai dengan agresivitas WAF target.

🔬 Arsitektur Teknis
Proses kerja AntiWare mengikuti siklus Recon-Evasion-Validation:

Recon: Melakukan fingerprinting teknologi target dan identifikasi parameter input.

Evasion: Membungkus payload eksploitasi ke dalam berbagai lapisan encoding.

Transmission: Mengirimkan trafik melalui rotasi proxy dengan jeda waktu adaptif.

OOB Validation: Menunggu interaksi dari server target ke infrastruktur kolaborator peneliti untuk mengonfirmasi celah keamanan.

⚠️ Pernyataan Hukum (Disclaimer)
Alat ini dibuat hanya untuk tujuan Riset Keamanan dan Edukasi. Penggunaan alat ini terhadap target tanpa izin tertulis yang sah adalah ilegal. Pengembang tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang diakibatkan oleh penggunaan alat ini.
