#!/bin/sh
# ==============================================================================
# AnonVoid — kullanıcı düzeyi kurulum (sudo gerektirmez)
# ==============================================================================
# Yalnızca çalıştırıcıyı ~/.local/bin/anonvoid olarak yerleştirir ve uygulama
# dizinini $ANONVOID_HOME_OVERRIDE ile sabitler. Sistem geni kurulum (root
# daemon, systemd servisi, /opt kopyası) için install.sh kullanılmalıdır.
#
#   sh packaging/launcher/install-user.sh
# ==============================================================================

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)
TEMPLATE="${SCRIPT_DIR}/anonvoid"
TARGET_DIR="${XDG_BIN_HOME:-${HOME}/.local/bin}"
TARGET="${TARGET_DIR}/anonvoid"

if [ ! -f "${TEMPLATE}" ]; then
    echo "AnonVoid: çalıştırıcı şablonu bulunamadı: ${TEMPLATE}" >&2
    exit 1
fi

if [ ! -f "${PROJECT_DIR}/main.py" ]; then
    echo "AnonVoid: uygulama giriş noktası bulunamadı: ${PROJECT_DIR}/main.py" >&2
    exit 1
fi

mkdir -p "${TARGET_DIR}"

# @PREFIX@ yer tutucusunu gerçek uygulama diziniyle değiştir
sed "s|@PREFIX@|${PROJECT_DIR}|g" "${TEMPLATE}" > "${TARGET}"
chmod 0755 "${TARGET}"

echo "AnonVoid çalıştırıcısı kuruldu: ${TARGET}"
echo "  Uygulama dizini: ${PROJECT_DIR}"

# PATH kontrolü
case ":${PATH}:" in
    *":${TARGET_DIR}:"*)
        echo "  PATH: tamam"
        ;;
    *)
        echo ""
        echo "  [UYARI] ${TARGET_DIR} PATH içinde değil. Eklemek için:"
        echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "    exec bash"
        ;;
esac

echo ""
echo "Artık şu komutla başlatabilirsiniz:"
echo "  anonvoid              → arayüz"
echo "  anonvoid --leak-test  → canlı sızıntı testi"
echo ""
echo "Not: Arayüz root çalıştırılamaz; yetkili işlemler için root daemon gerekir."
echo "     Daemon kurulu değilse arayüz çevrimdışı uyarısı gösterir (bu beklenen davranıştır)."
