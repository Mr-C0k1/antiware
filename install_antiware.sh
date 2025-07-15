#!/bin/bash

echo "🔧 Memulai instalasi AntiWare..."

# --- Cek dan instal CLI ---
if [ -f "antiware.py" ]; then
    echo "📦 Menyalin antiware.py ke /usr/local/bin/antiware..."
    sudo cp antiware.py /usr/local/bin/antiware
    sudo chmod +x /usr/local/bin/antiware
else
    echo "❌ File 'antiware.py' tidak ditemukan. Pastikan ada di direktori ini."
    exit 1
fi

# --- Cek dan instal GUI ---
if [ -f "antiware_gui.py" ]; then
    echo "📦 Menyalin antiware_gui.py ke /opt/antiware/"
    sudo mkdir -p /opt/antiware/
    sudo cp antiware_gui.py /opt/antiware/
else
    echo "⚠️ File 'antiware_gui.py' tidak ditemukan. GUI tidak akan tersedia."
fi

# --- Salin logo jika ada ---
if [ -f "antiware_logo.png" ]; then
    echo "🖼️ Menyalin logo ke /usr/share/antiware/"
    sudo mkdir -p /usr/share/antiware
    sudo cp antiware_logo.png /usr/share/antiware/
else
    echo "⚠️ Logo tidak ditemukan. Ikon GUI akan kosong."
fi

# --- Buat file .desktop untuk menu aplikasi ---
echo "🧩 Membuat shortcut aplikasi AntiWare di menu desktop..."
sudo tee /usr/share/applications/antiware.desktop > /dev/null <<EOF
[Desktop Entry]
Name=AntiWare GUI
Exec=python3 /opt/antiware/antiware_gui.py
Icon=/usr/share/antiware/antiware_logo.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF

sudo chmod +x /usr/share/applications/antiware.desktop

echo -e "\n✅ Instalasi selesai!"
echo "💡 Jalankan dari terminal dengan perintah: antiware"
echo "📁 Atau cari 'AntiWare GUI' di menu aplikasi."
