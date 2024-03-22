#!/bin/bash

# Memperbarui paket sistem
apt update && apt upgrade -y

# Menginstal Squid
apt install squid -y

# Konfigurasi Squid untuk mengizinkan semua akses
sed -i 's/http_access deny all/http_access allow all/' /etc/squid/squid.conf

# Restart Squid untuk menerapkan konfigurasi
systemctl restart squid

# Mengatur UFW untuk mengizinkan port Squid
ufw allow 3128/tcp
ufw reload

echo "Squid dan UFW telah dikonfigurasi!"
