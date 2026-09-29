"""AnonVoid - Tor Orkestrasyonu ve Devre Yenileme Modülü.

Bu modül; torrc dosyasını güvenle şablonlar, TransPort (9040), DNSPort (5300)
ve .onion sanal IP aralıklarını (10.192.0.0/10) yapılandırır, izinleri 0640 olarak
sertleştirir ve Tor Control Port (9051) üzerinden devre yenilemesi (SIGNAL NEWNYM) yapar.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.config import cfg_port

logger = logging.getLogger("FPCleanerTor")

DEFAULT_TORRC_PATH = "/etc/tor/torrc"
TORRC_BACKUP_PATH = "/etc/tor/torrc.fp-cleaner.bak"
TOR_CONTROL_PORT = 9051


def is_tor_running() -> bool:
    """Tor servisinin veya sürecinin sistemde çalışıp çalışmadığını denetler."""
    try:
        # systemctl ile kontrol et
        proc = subprocess.run(
            ["systemctl", "is-active", "tor"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and "active" in proc.stdout:
            return True
    except Exception:
        pass

    # Process bazlı fallback kontrolü (pgrep)
    try:
        proc = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, timeout=3, check=False)
        return proc.returncode == 0
    except Exception:
        return False


def renew_tor_circuit(control_port: int = TOR_CONTROL_PORT, password: str = "") -> Dict[str, Any]:
    """Tor Control Port üzerinden kimlik (Exit Node) rotasyonunu (SIGNAL NEWNYM) tetikler.

    Args:
        control_port: Tor kontrol portu (varsayılan: 9051).
        password: Varsa kontrol portu parolası.

    Returns:
        Dict[str, Any]: İşlem sonuç bilgisi.
    """
    control_port = cfg_port(control_port, 9051)
    logger.info("Tor devre yenileme sinyali gönderiliyor (Port: %d)...", control_port)

    result: Dict[str, Any] = {
        "success": False,
        "message": "",
        "timestamp": time.time(),
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        sock.connect(("127.0.0.1", control_port))

        # Kimlik doğrulama isteği
        auth_cmd = f'AUTHENTICATE "{password}"\r\n' if password else "AUTHENTICATE\r\n"
        sock.sendall(auth_cmd.encode("utf-8"))

        resp = sock.recv(1024).decode("utf-8")
        if not resp.startswith("250"):
            result["message"] = f"Tor kimlik doğrulaması başarısız: {resp.strip()}"
            return result

        # Devre yenileme sinyali gönder
        sock.sendall(b"SIGNAL NEWNYM\r\n")
        resp = sock.recv(1024).decode("utf-8")

        if resp.startswith("250"):
            result["success"] = True
            result["message"] = "Tor devresi başarıyla yenilendi (Yeni IP atandı)."
            logger.info("Tor Exit Node başarıyla yenilendi.")
        else:
            result["message"] = f"SIGNAL NEWNYM reddedildi: {resp.strip()}"

        sock.sendall(b"QUIT\r\n")
    except ConnectionRefusedError:
        result["message"] = f"Tor kontrol portuna ({control_port}) bağlanılamadı. Tor çalışıyor mu?"
    except socket.timeout:
        result["message"] = "Tor kontrol portundan yanıt alınamadı (Zaman aşımı)."
    except Exception as err:
        result["message"] = f"Devre yenilenirken hata oluştu: {err}"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


class TorManager:
    """Tor yapılandırması (torrc) ve servis yaşam döngüsü yöneticisi."""

    def __init__(
        self,
        torrc_path: str = DEFAULT_TORRC_PATH,
        backup_path: str = TORRC_BACKUP_PATH,
    ) -> None:
        self.torrc_path = torrc_path
        self.backup_path = backup_path

    def generate_torrc_content(
        self,
        trans_port: int = 9040,
        dns_port: int = 5300,
        socks_port: int = 9050,
        control_port: int = 9051,
    ) -> str:
        """Şeffaf proxy için güvenli ve optimize torrc yapılandırması üretir."""
        return (
            "# Linux FP Cleaner - Otomatik Yapılandırılmış torrc\n"
            f"SocksPort {cfg_port(socks_port, 9050)} IsolateDestAddr\n"
            f"TransPort {cfg_port(trans_port, 9040)}\n"
            f"DNSPort {cfg_port(dns_port, 5300)}\n"
            f"ControlPort {cfg_port(control_port, 9051)}\n"
            "VirtualAddrNetworkIPv4 10.192.0.0/10\n"
            "AutomapHostsOnResolve 1\n"
            "AutomapHostsSuffixes .onion,.exit\n"
            "AvoidDiskWrites 1\n"
            "Log notice stdout\n"
        )

    def backup_torrc(self) -> bool:
        """Orijinal torrc dosyasını yedekler."""
        if os.path.exists(self.torrc_path) and not os.path.exists(self.backup_path):
            try:
                shutil.copy2(self.torrc_path, self.backup_path)
                logger.info("Orijinal torrc yedeklendi: %s", self.backup_path)
                return True
            except Exception as err:
                logger.error("torrc yedeklenemedi: %s", err)
                return False
        return True

    def configure_and_reload(
        self,
        trans_port: int = 9040,
        dns_port: int = 5300,
        socks_port: int = 9050,
        control_port: int = 9051,
    ) -> bool:
        """torrc dosyasını günceller ve Tor servisini yeniden yükler."""
        self.backup_torrc()

        content = self.generate_torrc_content(trans_port, dns_port, socks_port, control_port)

        try:
            parent_dir = os.path.dirname(self.torrc_path)
            if parent_dir:
                os.makedirs(parent_dir, mode=0o755, exist_ok=True)

            with open(self.torrc_path, "w", encoding="utf-8") as f:
                f.write(content)

            # İzinleri 0640 yap (hassas köprü veya ayarlar için güvenlik standardı)
            try:
                os.chmod(self.torrc_path, 0o640)
            except OSError:
                pass

            logger.info("Yeni torrc başarıyla yazıldı: %s", self.torrc_path)

            # Tor servisini yeniden yükle
            return self.reload_service()
        except Exception as err:
            logger.error("torrc yazılamadı: %s", err)
            return False

    def reload_service(self) -> bool:
        """Tor servisine yeniden yükleme (reload veya restart) sinyali gönderir."""
        logger.info("Tor servisi yeniden başlatılıyor/yükleniyor...")
        for cmd in [["systemctl", "reload-or-restart", "tor"], ["systemctl", "restart", "tor"]]:
            try:
                proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15, check=False)
                if proc.returncode == 0:
                    return True
            except Exception:
                pass
        return is_tor_running()

    def restore_torrc(self) -> bool:
        """Yedeklenen orijinal torrc dosyasını geri yükler."""
        if os.path.exists(self.backup_path):
            try:
                shutil.move(self.backup_path, self.torrc_path)
                logger.info("Orijinal torrc geri yüklendi.")
                self.reload_service()
                return True
            except Exception as err:
                logger.error("Orijinal torrc geri yüklenemedi: %s", err)
                return False
        return True
