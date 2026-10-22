#!/usr/bin/env bash
# ==============================================================================
# AnonVoid — Debian / Ubuntu (.deb) Paket Üretim Betiği
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build_deb"
PKG_ROOT="$BUILD_DIR/anonvoid_1.0.0_all"
OUTPUT_DIR="$PROJECT_ROOT/dist"

echo "===================================================================="
echo "  🛡️  ANONVOID — DEBIAN (.DEB) PAKET ÜRETİCİSİ"
echo "===================================================================="
echo "[*] Proje Dizini: $PROJECT_ROOT"
echo "[*] Paket Ağacı : $PKG_ROOT"
echo "[*] Çıktı Dizini: $OUTPUT_DIR"

# 1. Hazırlık ve Temizlik
rm -rf "$BUILD_DIR"
mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/opt/anonvoid"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/lib/systemd/system"
mkdir -p "$PKG_ROOT/usr/share/applications"
mkdir -p "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$OUTPUT_DIR"

# 2. Debian Kontrol ve Kanca Dosyaları
cp "$PROJECT_ROOT/packaging/debian/control" "$PKG_ROOT/DEBIAN/"
cp "$PROJECT_ROOT/packaging/debian/postinst" "$PKG_ROOT/DEBIAN/"
cp "$PROJECT_ROOT/packaging/debian/prerm" "$PKG_ROOT/DEBIAN/"
cp "$PROJECT_ROOT/packaging/debian/postrm" "$PKG_ROOT/DEBIAN/"

chmod 0644 "$PKG_ROOT/DEBIAN/control"
chmod 0755 "$PKG_ROOT/DEBIAN/postinst"
chmod 0755 "$PKG_ROOT/DEBIAN/prerm"
chmod 0755 "$PKG_ROOT/DEBIAN/postrm"

# 3. Uygulama Dosyaları
echo "[*] Uygulama dosyaları yerleştiriliyor..."
cp -r "$PROJECT_ROOT/core" "$PKG_ROOT/opt/anonvoid/"
cp -r "$PROJECT_ROOT/gui" "$PKG_ROOT/opt/anonvoid/"
cp "$PROJECT_ROOT/main.py" "$PKG_ROOT/opt/anonvoid/"

# Bytecode temizliği (Zero-footprint kuralı)
find "$PKG_ROOT" -name "*.pyc" -delete 2>/dev/null || true
find "$PKG_ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Dosya izinleri
find "$PKG_ROOT/opt/anonvoid" -type d -exec chmod 0755 {} +
find "$PKG_ROOT/opt/anonvoid" -type f -exec chmod 0644 {} +
chmod 0755 "$PKG_ROOT/opt/anonvoid/main.py"

# 4. Çalıştırıcı Wrapper (/usr/bin/anonvoid ve geriye dönük link)
cat << 'EOF' > "$PKG_ROOT/usr/bin/anonvoid"
#!/bin/sh
export PYTHONDONTWRITEBYTECODE=1
exec python3 /opt/anonvoid/main.py "$@"
EOF
chmod 0755 "$PKG_ROOT/usr/bin/anonvoid"
# Eski adla (fp-cleaner) çağırma geriye dönük uyumluluk sembolik bağı
ln -sf anonvoid "$PKG_ROOT/usr/bin/fp-cleaner"

# 5. Systemd ve Masaüstü Dosyaları
cp "$PROJECT_ROOT/packaging/systemd/anonvoid.service" "$PKG_ROOT/lib/systemd/system/anonvoid.service"
chmod 0644 "$PKG_ROOT/lib/systemd/system/anonvoid.service"

cp "$PROJECT_ROOT/packaging/desktop/anonvoid.desktop" "$PKG_ROOT/usr/share/applications/anonvoid.desktop"
chmod 0644 "$PKG_ROOT/usr/share/applications/anonvoid.desktop"

cp "$PROJECT_ROOT/packaging/desktop/anonvoid.svg" "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/anonvoid.svg"
chmod 0644 "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/anonvoid.svg"

# 6. dpkg-deb ile Paketleme
if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "[HATA] 'dpkg-deb' komutu sistemde bulunamadı. Lütfen 'dpkg' paketini kurun." >&2
    exit 1
fi

echo "[*] dpkg-deb ile .deb paketi inşa ediliyor..."
DEB_FILE="$OUTPUT_DIR/anonvoid_1.0.0_all.deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_FILE"

echo "===================================================================="
echo "  🎉  DEBIAN PAKETİ BAŞARIYLA OLUŞTURULDU!"
echo "===================================================================="
echo "[+] Paket Dosyası: $DEB_FILE"
echo "[+] Kurulum Komutu: sudo dpkg -i $DEB_FILE || sudo apt-get install -f"
