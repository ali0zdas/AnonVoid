#!/usr/bin/env bash
# ==============================================================================
# AnonVoid — Evrensel Çoklu Dağıtım Kurulum ve Yönetim Betiği
# Desteklenen Dağıtımlar: Debian, Ubuntu, Kali, Arch Linux, Fedora, openSUSE, NixOS
# ==============================================================================

set -euo pipefail

INSTALL_DIR="/opt/anonvoid"
BIN_LINK="/usr/local/bin/anonvoid"
LEGACY_BIN_LINK="/usr/local/bin/fp-cleaner"
SERVICE_NAME="anonvoid.service"
GROUP_NAME="anonvoid"
DESKTOP_FILE="/usr/share/applications/anonvoid.desktop"
ICON_FILE="/usr/share/icons/hicolor/scalable/apps/anonvoid.svg"

# Betiğin bulunduğu dizin (şablon ve paket dosyalarını bulmak için gerekli)
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================================${NC}"
echo -e "${CYAN}  🛡️  ANONVOID — KURULUM VE DAĞITIM YÖNETİCİSİ                     ${NC}"
echo -e "${CYAN}====================================================================${NC}"

# Root yetkisi kontrolü
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[HATA] Bu kurulum betiği root veya sudo yetkisiyle çalıştırılmalıdır.${NC}"
    echo -e "Lütfen şu şekilde çalıştırın: ${YELLOW}sudo bash install.sh${NC}"
    exit 1
fi

# Gerçek kullanıcıyı tespit et (SUDO_USER)
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
if [ -z "$REAL_USER" ] || [ "$REAL_USER" = "root" ]; then
    # Alternatif oturum kullanıcısı tespiti
    REAL_USER=$(who | awk '{print $1}' | head -n 1)
fi

# ------------------------------------------------------------------------------
# Kaldırma (Uninstall) Rutini
# ------------------------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "-u" ]; then
    echo -e "${YELLOW}[BİLGİ] AnonVoid sistemden kaldırılıyor...${NC}"

    # 1. Systemd servisini durdur ve devreden çıkar
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME" || true
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        systemctl disable "$SERVICE_NAME" || true
    fi
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    rm -f "/etc/systemd/system/fp-cleaner.service"
    systemctl daemon-reload || true

    # 2. Çalıştırıcı ve dizinleri sil
    rm -f "$BIN_LINK"
    rm -f "$LEGACY_BIN_LINK"
    rm -rf "$INSTALL_DIR"
    rm -rf "/opt/fp-cleaner"
    rm -rf "/run/anonvoid"
    rm -rf "/run/fp-cleaner"

    # 3. Masaüstü kısayollarını sil
    rm -f "$DESKTOP_FILE"
    rm -f "/usr/share/applications/fp-cleaner.desktop"
    rm -f "$ICON_FILE"
    rm -f "/usr/share/icons/hicolor/scalable/apps/fp-cleaner.svg"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications || true
    fi

    echo -e "${GREEN}[BAŞARILI] AnonVoid tüm bileşenleriyle sistemden başarıyla kaldırıldı.${NC}"
    exit 0
fi

# ------------------------------------------------------------------------------
# Dağıtım Tespiti ve Paket Yöneticisi
# ------------------------------------------------------------------------------
DISTRO="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
fi

echo -e "${BLUE}[BİLGİ] Tespit edilen işletim sistemi dağıtımı: ${YELLOW}$DISTRO${NC}"

install_dependencies() {
    echo -e "${BLUE}[BİLGİ] Sistem bağımlılıkları kuruluyor...${NC}"

    case "$DISTRO" in
        debian|ubuntu|kali|linuxmint|pop)
            apt-get update -y
            apt-get install -y python3 python3-pip python3-pyqt6 tor dnscrypt-proxy nftables util-linux
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm python python-pip python-pyqt6 tor dnscrypt-proxy nftables util-linux
            ;;
        fedora|rhel|centos)
            dnf install -y python3 python3-pip python3-pyqt6 tor dnscrypt-proxy nftables util-linux
            ;;
        opensuse*|suse)
            zypper refresh
            zypper install -y python3 python3-pip python3-qt6 tor dnscrypt-proxy nftables util-linux
            ;;
        *)
            if [[ "$DISTRO_LIKE" == *"debian"* ]] || [[ "$DISTRO_LIKE" == *"ubuntu"* ]]; then
                apt-get update -y && apt-get install -y python3 python3-pip python3-pyqt6 tor dnscrypt-proxy nftables util-linux
            elif [[ "$DISTRO_LIKE" == *"arch"* ]]; then
                pacman -Sy --noconfirm python python-pip python-pyqt6 tor dnscrypt-proxy nftables util-linux
            elif [[ "$DISTRO_LIKE" == *"fedora"* ]]; then
                dnf install -y python3 python3-pip python3-pyqt6 tor dnscrypt-proxy nftables util-linux
            else
                echo -e "${YELLOW}[UYARI] Dağıtımınız otomatik paket kurulumunda tanınamadı. Lütfen Tor, DNSCrypt ve PyQt6 paketlerinin kurulu olduğundan emin olun.${NC}"
            fi
            ;;
    esac
}

# ------------------------------------------------------------------------------
# 1. Kullanıcı Grubu Oluşturma ve Yetkilendirme
# ------------------------------------------------------------------------------
setup_user_group() {
    echo -e "${BLUE}[BİLGİ] Kullanıcı grubu (${GROUP_NAME}) yapılandırılıyor...${NC}"

    if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
        groupadd -r "$GROUP_NAME"
        echo -e "${GREEN}[+] '${GROUP_NAME}' grubu başarıyla oluşturuldu.${NC}"
    else
        echo -e "${CYAN}[*] '${GROUP_NAME}' grubu zaten mevcut.${NC}"
    fi

    if [ -n "$REAL_USER" ]; then
        usermod -aG "$GROUP_NAME" "$REAL_USER"
        echo -e "${GREEN}[+] '${REAL_USER}' kullanıcısı '${GROUP_NAME}' grubuna eklendi.${NC}"
    else
        echo -e "${YELLOW}[UYARI] Oturum kullanıcısı tespit edilemedi. Lütfen elle şu komutu çalıştırın: usermod -aG anonvoid <kullanici_adiniz>${NC}"
    fi
}

# ------------------------------------------------------------------------------
# 2. Dosyaları /opt/anonvoid Dizinine Kopyalama
# ------------------------------------------------------------------------------
install_files() {
    echo -e "${BLUE}[BİLGİ] Uygulama dosyaları ${INSTALL_DIR} dizinine kopyalanıyor...${NC}"

    mkdir -p "$INSTALL_DIR"

    # Python bytecode önbelleğini asla kopyalama (AGENTS.md: sıfır kendi izi)
    find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find . -name '*.pyc' -type f -delete 2>/dev/null || true

    # packaging/ de kopyalanır: çalıştırıcı şablonu ve systemd ünitesi
    # kurulum sonrasında /opt/anonvoid altından da erişilebilir olmalıdır.
    cp -r core gui docs tests packaging main.py "$INSTALL_DIR/" 2>/dev/null \
        || cp -r core gui docs tests main.py "$INSTALL_DIR/"

    # Kopyalama sonrasıda bytecode kalıntısı olmadığını doğrula
    find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find "$INSTALL_DIR" -name '*.pyc' -type f -delete 2>/dev/null || true

    # Dosya sahipliğini ve izinlerini sertleştir
    chown -R root:"$GROUP_NAME" "$INSTALL_DIR"
    find "$INSTALL_DIR" -type d -exec chmod 0755 {} +
    find "$INSTALL_DIR" -type f -exec chmod 0644 {} +
    chmod 0755 "$INSTALL_DIR/main.py"

    # /usr/local/bin/anonvoid çalıştırıcı wrapper scripti oluştur
    # Ortak şablon kullanılır; böylece root koruması ve bağımlılık kontrolleri
    # hem sistem geneli hem kullanıcı düzeyi kurulumda birebir aynıdır.
    LAUNCHER_TEMPLATE=""
    for candidate in \
        "$PWD/packaging/launcher/anonvoid" \
        "$INSTALL_DIR/packaging/launcher/anonvoid" \
        "$SCRIPT_DIR/packaging/launcher/anonvoid"; do
        if [ -f "$candidate" ]; then
            LAUNCHER_TEMPLATE="$candidate"
            break
        fi
    done

    if [ -z "$LAUNCHER_TEMPLATE" ]; then
        echo -e "${RED}[HATA] packaging/launcher/anonvoid şablonu bulunamadı.${NC}"
        exit 1
    fi

    sed "s|@PREFIX@|${INSTALL_DIR}|g" "$LAUNCHER_TEMPLATE" > "$BIN_LINK"
    chmod 0755 "$BIN_LINK"
    ln -sf "$BIN_LINK" "$LEGACY_BIN_LINK" 2>/dev/null || true
    echo -e "${GREEN}[+] Çalıştırıcı oluşturuldu: ${BIN_LINK}${NC}"
}

# ------------------------------------------------------------------------------
# 3. Systemd Servis Ünitesini Kurma ve Başlatma
# ------------------------------------------------------------------------------
setup_systemd_service() {
    echo -e "${BLUE}[BİLGİ] Systemd root daemon servisi kuruluyor...${NC}"

    if [ -f "packaging/systemd/anonvoid.service" ]; then
        cp packaging/systemd/anonvoid.service "/etc/systemd/system/$SERVICE_NAME"
    elif [ -f "packaging/systemd/fp-cleaner.service" ]; then
        cp packaging/systemd/fp-cleaner.service "/etc/systemd/system/$SERVICE_NAME"
    elif [ -f "$INSTALL_DIR/packaging/systemd/anonvoid.service" ]; then
        cp "$INSTALL_DIR/packaging/systemd/anonvoid.service" "/etc/systemd/system/$SERVICE_NAME"
    else
        # Yedek oluştur
        cat << EOF > "/etc/systemd/system/$SERVICE_NAME"
[Unit]
Description=AnonVoid Root IPC Daemon
After=network.target network-online.target tor.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$BIN_LINK --service
RuntimeDirectory=anonvoid
RuntimeDirectoryMode=0755
KillMode=mixed
TimeoutStopSec=10
Restart=on-failure
RestartSec=3s
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    fi

    chmod 0644 "/etc/systemd/system/$SERVICE_NAME"
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
    echo -e "${GREEN}[+] ${SERVICE_NAME} servisi etkinleştirildi ve başlatıldı.${NC}"
}

# ------------------------------------------------------------------------------
# 4. Masaüstü Kısayolu ve İkon Kurulumu
# ------------------------------------------------------------------------------
setup_desktop_entry() {
    echo -e "${BLUE}[BİLGİ] XDG Masaüstü menü entegrasyonu yapılıyor...${NC}"

    mkdir -p "$(dirname "$DESKTOP_FILE")"
    mkdir -p "$(dirname "$ICON_FILE")"

    if [ -f "packaging/desktop/anonvoid.desktop" ]; then
        cp packaging/desktop/anonvoid.desktop "$DESKTOP_FILE"
    elif [ -f "packaging/desktop/fp-cleaner.desktop" ]; then
        cp packaging/desktop/fp-cleaner.desktop "$DESKTOP_FILE"
    fi

    if [ -f "packaging/desktop/anonvoid.svg" ]; then
        cp packaging/desktop/anonvoid.svg "$ICON_FILE"
    elif [ -f "packaging/desktop/fp-cleaner.svg" ]; then
        cp packaging/desktop/fp-cleaner.svg "$ICON_FILE"
    fi

    chmod 0644 "$DESKTOP_FILE" || true
    chmod 0644 "$ICON_FILE" || true

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications || true
    fi
    echo -e "${GREEN}[+] Masaüstü başlatıcısı ve SVG simgesi kuruldu.${NC}"
}

# ------------------------------------------------------------------------------
# Ana Yürütme Akışı
# ------------------------------------------------------------------------------
install_dependencies
setup_user_group
install_files
setup_systemd_service
setup_desktop_entry

echo -e "\n${CYAN}====================================================================${NC}"
echo -e "${GREEN}  🎉  KURULUM EKSİKSİZ TAMAMLANDI!                                 ${NC}"
echo -e "${CYAN}====================================================================${NC}"
echo -e "Uygulamayı başlatmak için:"
echo -e "  • Masaüstü menüsünden: ${YELLOW}AnonVoid${NC}"
echo -e "  • Terminalden (GUI):   ${YELLOW}anonvoid${NC}"
echo -e "  • Anlık adli temizlik: ${YELLOW}anonvoid --wipe${NC}"
echo -e "  • Canlı sızıntı testi: ${YELLOW}anonvoid --leak-test${NC}"
echo -e "  • Acil panik butonu:   ${YELLOW}anonvoid --panic${NC}"
echo -e "\n${YELLOW}[ÖNEMLİ NOT] Grup yetkilerinin geçerli olması için lütfen oturumunuzu kapatıp tekrar açın!${NC}\n"
