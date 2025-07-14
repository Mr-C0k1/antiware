#!/bin/bash

echo "==> Menginstal AntiWare..."

# Salin CLI
sudo cp antiware.py /usr/local/bin/antiware
sudo chmod +x /usr/local/bin/antiware

# Salin GUI (opsional)
sudo mkdir -p /opt/antiware/
sudo cp antiware_gui.py /opt/antiware/

# Salin logo
sudo mkdir -p /usr/share/antiware
sudo cp antiware_logo.png /usr/share/antiware/

# Buat launcher
cat <<EOF | sudo tee /usr/share/applications/antiware.desktop > /dev/null
[Desktop Entry]
Name=AntiWare GUI
Exec=python3 /opt/antiware/antiware_gui.py
Icon=/usr/share/antiware/antiware_logo.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF

sudo chmod +x /usr/share/applications/antiware.desktop

echo "[✔] Instalasi selesai. Gunakan 'antiware' di terminal atau cari 'AntiWare GUI' di menu aplikasi."
