# 🕷️ AntiWare - Website Threat & Malware Scanner

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
  
