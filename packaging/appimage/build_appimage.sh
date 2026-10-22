#!/usr/bin/env bash
# ==============================================================================
# AnonVoid — Taşınabilir AppImage Derleme Betiği
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build_appimage"
APP_DIR="$BUILD_DIR/AppDir"
OUTPUT_DIR="$PROJECT_ROOT/dist"

echo "===================================================================="
echo "  🛡️  ANONVOID — APPIMAGE DERLEME YÖNETİCİSİ"
echo "===================================================================="
echo "[*] Proje Dizini : $PROJECT_ROOT"
echo "[*] AppDir Dizini: $APP_DIR"
echo "[*] Çıktı Dizini : $OUTPUT_DIR"

# 1. Temizlik ve Dizin Hazırlığı
rm -rf "$BUILD_DIR"
mkdir -p "$APP_DIR/usr/bin"
mkdir -p "$APP_DIR/usr/share/anonvoid"
mkdir -p "$APP_DIR/usr/share/applications"
mkdir -p "$APP_DIR/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$OUTPUT_DIR"

# 2. Kod Dosyalarını Kopyalama
echo "[*] Uygulama kaynak dosyaları AppDir içerisine kopyalanıyor..."
cp -r "$PROJECT_ROOT/core" "$APP_DIR/usr/share/anonvoid/"
cp -r "$PROJECT_ROOT/gui" "$APP_DIR/usr/share/anonvoid/"
cp "$PROJECT_ROOT/main.py" "$APP_DIR/usr/share/anonvoid/"

# Bytecode temizliği (Zero-footprint kuralı)
find "$APP_DIR" -name "*.pyc" -delete 2>/dev/null || true
find "$APP_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# 3. İkon ve Masaüstü Kısayolu Entegrasyonu
echo "[*] Masaüstü ve ikon metaverileri yerleştiriliyor..."
DESKTOP_SRC="$PROJECT_ROOT/packaging/desktop/anonvoid.desktop"
SVG_SRC="$PROJECT_ROOT/packaging/desktop/anonvoid.svg"

[ ! -f "$DESKTOP_SRC" ] && { echo "[HATA] $DESKTOP_SRC bulunamadı." >&2; exit 1; }
[ ! -f "$SVG_SRC" ] && { echo "[HATA] $SVG_SRC bulunamadı." >&2; exit 1; }

cp "$DESKTOP_SRC" "$APP_DIR/usr/share/applications/anonvoid.desktop"
cp "$DESKTOP_SRC" "$APP_DIR/anonvoid.desktop"
cp "$SVG_SRC" "$APP_DIR/usr/share/icons/hicolor/scalable/apps/anonvoid.svg"
cp "$SVG_SRC" "$APP_DIR/anonvoid.svg"
cp "$SVG_SRC" "$APP_DIR/.DirIcon"

# 4. AppRun Betiği Entegrasyonu
cp "$PROJECT_ROOT/packaging/appimage/AppRun" "$APP_DIR/AppRun"
chmod +x "$APP_DIR/AppRun"

# 5. Nuitka ile derlenmiş ikili varsa ekle
if [ -f "$OUTPUT_DIR/anonvoid" ]; then
    echo "[+] Önceden derlenmiş C++ ikilisi tespit edildi, AppDir/usr/bin içine kopyalanıyor..."
    cp "$OUTPUT_DIR/anonvoid" "$APP_DIR/usr/bin/anonvoid"
    chmod +x "$APP_DIR/usr/bin/anonvoid"
fi

# 6. appimagetool İndir ve Çalıştır
echo "[*] AppImage paketi oluşturuluyor..."
APPIMAGETOOL=""

if command -v appimagetool >/dev/null 2>&1; then
    APPIMAGETOOL="appimagetool"
elif [ -f "$BUILD_DIR/appimagetool" ]; then
    APPIMAGETOOL="$BUILD_DIR/appimagetool"
else
    echo "[*] appimagetool indiriliyor..."
    APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    curl -fsSL -L "$APPIMAGETOOL_URL" -o "$BUILD_DIR/appimagetool" || wget -q "$APPIMAGETOOL_URL" -O "$BUILD_DIR/appimagetool"
    chmod +x "$BUILD_DIR/appimagetool"
    APPIMAGETOOL="$BUILD_DIR/appimagetool"
fi

OUTPUT_FILE="$OUTPUT_DIR/AnonVoid-x86_64.AppImage"
ARCH=x86_64 "$APPIMAGETOOL" "$APP_DIR" "$OUTPUT_FILE"

echo "===================================================================="
echo "  🎉  APPIMAGE PAKETİ BAŞARIYLA OLUŞTURULDU!"
echo "===================================================================="
echo "[+] Çıktı: $OUTPUT_FILE"
echo "[+] Çalıştırmak için: chmod +x $OUTPUT_FILE && $OUTPUT_FILE"
