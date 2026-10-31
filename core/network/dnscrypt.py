"""AnonVoid - DNSCrypt-Proxy ve systemd-resolved Entegrasyon Modülü.

Bu modül; DNS sorgularını şifreleyen dnscrypt-proxy servisini yönetir,
resolvectl aracı ile sistemin tüm DNS isteklerini 127.0.0.1:5380 soketine kilitler
ve bağlantı kesildiğinde resolvectl revert ile orijinal DNS çözümleyicisini geri yükler.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.config import cfg_port

logger = logging.getLogger("AnonVoidDNSCrypt")

DEFAULT_DNSCRYPT_PORT = 5380
RESOLV_CONF_PATH = "/etc/resolv.conf"
RESOLV_CONF_BACKUP = "/etc/resolv.conf.anonvoid.bak"
# Eski proje adından ("fp-cleaner") kalan yedekler. Üst üste yazılmaması için
# varlıkları kontrol edilir; aksi halde orijinal resolv.conf kalıcı olarak kaybolur.
RESOLV_CONF_LEGACY_BACKUPS = ("/etc/resolv.conf.fp-cleaner.bak",)


def existing_resolv_backup() -> str:
    """Geri yüklenecek geçerli resolv.conf yedeğinin yolunu döndürür (yoksa boş dize)."""
    for path in (RESOLV_CONF_BACKUP, *RESOLV_CONF_LEGACY_BACKUPS):
        if os.path.exists(path):
            return path
    return ""


def is_dnscrypt_running() -> bool:
    """DNSCrypt-proxy sürecinin aktif olup olmadığını denetler."""
    try:
        proc = subprocess.run(["pgrep", "-f", "dnscrypt-proxy"], capture_output=True, timeout=3, check=False)
        return proc.returncode == 0
    except Exception:
        return False


def get_active_network_interfaces() -> List[str]:
    """Sanal (loop, docker, veth, wg vb.) olmayan aktif ağ arayüzlerini listeler."""
    interfaces: List[str] = []
    try:
        proc = subprocess.run(["ip", "-o", "link", "show", "up"], capture_output=True, text=True, timeout=5, check=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    iface = parts[1].strip()
                    if iface and not iface.startswith(("lo", "docker", "veth", "virbr", "wg", "tun", "tap", "cni")):
                        interfaces.append(iface)
    except Exception as err:
        logger.warning("Ağ arayüzleri taranamadı: %s", err)

    return interfaces


class DNSCryptManager:
    """DNSCrypt ve systemd-resolved yapılandırma yöneticisi."""

    def __init__(self, port: int = DEFAULT_DNSCRYPT_PORT) -> None:
        self.port = cfg_port(port, DEFAULT_DNSCRYPT_PORT)
        self.has_resolvectl = shutil.which("resolvectl") is not None
        self._configured_interfaces: List[str] = []

    def apply_dns_lock(self, ifaces: Optional[List[str]] = None) -> Dict[str, Any]:
        """Tüm sistem DNS trafiğini yerel şifreli DNSCrypt soketine (127.0.0.1:5380) kilitler.

        Args:
            ifaces: Kilitlenecek ağ arayüzleri listesi (None ise tüm aktif arayüzler).

        Returns:
            Dict[str, Any]: Yapılandırma sonuç raporu.
        """
        target_ifaces = ifaces or get_active_network_interfaces()
        logger.info("DNSCrypt yönlendirmesi uygulanıyor (Hedef Arayüzler: %s)...", ", ".join(target_ifaces))

        result: Dict[str, Any] = {
            "success": False,
            "interfaces": target_ifaces,
            "used_resolvectl": self.has_resolvectl,
            "errors": [],
        }

        # 1. resolvectl ile her arayüz için DNSCrypt ayarla
        if self.has_resolvectl:
            for iface in target_ifaces:
                try:
                    # DNS sunucusunu 127.0.0.1:5380 yap
                    cmd1 = ["resolvectl", "dns", iface, f"127.0.0.1:{self.port}"]
                    subprocess.run(cmd1, capture_output=True, timeout=5, check=False)

                    # Tüm alan adlarını (~.) bu arayüze zorla
                    cmd2 = ["resolvectl", "domain", iface, "~."]
                    subprocess.run(cmd2, capture_output=True, timeout=5, check=False)

                    # Varsayılan rota olarak işaretle
                    cmd3 = ["resolvectl", "default-route", iface, "true"]
                    subprocess.run(cmd3, capture_output=True, timeout=5, check=False)

                    self._configured_interfaces.append(iface)
                    logger.info("%s arayüzü DNSCrypt soketine başarıyla kilitlendi.", iface)
                except Exception as err:
                    result["errors"].append(f"{iface} resolvectl hatası: {err}")

            result["success"] = len(self._configured_interfaces) > 0
            return result

        # 2. Fallback: /etc/resolv.conf dosyasını yedekle ve 127.0.0.1 yaz
        try:
            if os.path.exists(RESOLV_CONF_PATH):
                if not existing_resolv_backup():
                    # Sembolik bağ olsa dahi orijinal içeriği koru
                    shutil.copy2(RESOLV_CONF_PATH, RESOLV_CONF_BACKUP)

                # Standart resolv.conf formatı: 'port' direktifi glibc tarafından tanınmadığından
                # açıklayıcı yorum satırı olarak eklenir ve nameserver 127.0.0.1 atanır.
                content = (
                    "# AnonVoid DNSCrypt Kilidi - Otomatik Yapılandırma\n"
                    f"# DNSCrypt-Proxy Dinleme Soketi: 127.0.0.1:{self.port}\n"
                    "nameserver 127.0.0.1\n"
                    "options edns0 trust-ad\n"
                )
                with open(RESOLV_CONF_PATH, "w", encoding="utf-8") as f:
                    f.write(content)

                result["success"] = True
                logger.info("/etc/resolv.conf fallback üzerinden DNSCrypt soketine yönlendirildi.")
        except Exception as err:
            result["errors"].append(f"/etc/resolv.conf yazılamadı: {err}")

        return result

    def revert_dns_lock(self) -> bool:
        """Tüm arayüzlerin DNS ayarlarını orijinal durumuna döndürür."""
        logger.info("DNSCrypt kilidi kaldırılıyor ve sistem DNS'i geri yükleniyor...")
        success = True

        # 1. resolvectl revert
        if self.has_resolvectl:
            target_ifaces = self._configured_interfaces or get_active_network_interfaces()
            for iface in target_ifaces:
                try:
                    subprocess.run(["resolvectl", "revert", iface], capture_output=True, timeout=5, check=False)
                    logger.info("%s arayüzü DNS ayarları eski haline döndürüldü.", iface)
                except Exception as err:
                    logger.warning("%s revert edilemedi: %s", iface, err)
                    success = False
            self._configured_interfaces.clear()

        # 2. /etc/resolv.conf yedeğini geri yükle
        backup = existing_resolv_backup()
        if backup:
            try:
                shutil.copy2(backup, RESOLV_CONF_PATH)
                try:
                    os.remove(backup)
                except OSError:
                    pass
                logger.info("Orijinal /etc/resolv.conf geri yüklendi.")
            except Exception as err:
                logger.warning("/etc/resolv.conf geri yüklenemedi: %s", err)
        else:
            logger.warning(
                "Geri yüklenecek /etc/resolv.conf yedeği bulunamadı; "
                "sistem DNS yapılandırması elle düzeltilmelidir."
            )

        return success
