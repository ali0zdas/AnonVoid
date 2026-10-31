"""AnonVoid - Donanım ve MAC Adresi Sahteleme (MAC Randomizer) Modülü.

Bu modül; sanal arayüzleri filtreleyerek gerçek Ethernet ve Wi-Fi bağdaştırıcılarını bulur,
NetworkManager ile yarış durumuna (race condition) girmemek için öncelikle yerinde (in-place)
MAC değişimi dener; donanım izin vermezse kontrollü down/up döngüsü uygular.
Orijinal MAC adreslerini saklayarak çıkışta veya talep edildiğinde geri yükler.
"""

from __future__ import annotations

import logging
import os
import random
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.config import cfg_interface_name

logger = logging.getLogger("AnonVoidMAC")

# Hariç Tutulacak Sanal ve Konteyner Arayüz Desenleri
EXCLUDED_IFACE_PATTERNS = [
    r"^lo$",
    r"^docker.*",
    r"^veth.*",
    r"^virbr.*",
    r"^wg.*",
    r"^tun.*",
    r"^tap.*",
    r"^cni.*",
    r"^flannel.*",
    r"^dummy.*",
    r"^vmnet.*",
    r"^vboxnet.*",
]


def generate_random_mac() -> str:
    """Geçerli, yerel olarak yönetilen (unicast/locally-administered) rastgele bir MAC adresi üretir.

    Standart gereği ilk baytın son iki biti '10' olmalıdır (0x02).
    """
    first_byte = random.choice([0x02, 0x06, 0x0A, 0x0E])
    remaining_bytes = [random.randint(0x00, 0xFF) for _ in range(5)]
    mac_parts = [first_byte] + remaining_bytes
    return ":".join(f"{b:02x}" for b in mac_parts)


def get_current_mac(iface: str) -> Optional[str]:
    """Verilen arayüzün mevcut MAC adresini /sys/class/net üzerinden okur."""
    try:
        clean_iface = cfg_interface_name(iface)
        addr_path = f"/sys/class/net/{clean_iface}/address"
        if os.path.exists(addr_path):
            with open(addr_path, "r", encoding="utf-8") as f:
                mac = f.read().strip().lower()
                if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                    return mac
    except Exception as err:
        logger.warning("%s MAC adresi okunamadı: %s", iface, err)
    return None


def get_permanent_mac(iface: str) -> Optional[str]:
    """Arayüzün fabrika çıkışlı kalıcı (permanent) donanım MAC adresini tespit eder.

    Öncelikle /sys/class/net/<iface>/permaddr dosyasını ve ardından `ethtool -P <iface>`
    komutunu sorgular. Donanım seviyesinde kalıcı adres bulunamazsa mevcut adres değerine düşer.
    """
    clean_iface = cfg_interface_name(iface)
    mac_regex = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

    # 1. /sys/class/net/<iface>/permaddr denetimi
    perm_path = f"/sys/class/net/{clean_iface}/permaddr"
    if os.path.exists(perm_path):
        try:
            with open(perm_path, "r", encoding="utf-8") as f:
                mac = f.read().strip().lower()
                if mac_regex.match(mac) and mac != "00:00:00:00:00:00":
                    return mac
        except OSError:
            pass

    # 2. ethtool -P <iface> sorgulaması
    try:
        proc = subprocess.run(
            ["ethtool", "-P", clean_iface],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0:
            match = re.search(r"Permanent address:\s*(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", proc.stdout)
            if match:
                mac = match.group(1).lower()
                if mac_regex.match(mac) and mac != "00:00:00:00:00:00":
                    return mac
    except Exception:
        pass

    # 3. Fallback: Mevcut MAC adresine dön
    return get_current_mac(clean_iface)


def get_physical_interfaces() -> List[str]:
    """Yalnızca fiziksel ve Wi-Fi ağ bağdaştırıcılarını listeler (Sanal olanlar hariç tutulur)."""
    interfaces: List[str] = []
    sys_net = "/sys/class/net"

    if not os.path.exists(sys_net):
        return interfaces

    try:
        for iface in os.listdir(sys_net):
            # Sanal desen filtreleme
            is_excluded = any(re.match(pat, iface) for pat in EXCLUDED_IFACE_PATTERNS)
            if is_excluded:
                continue

            # MAC adresi kontrolü (00:00:00:00:00:00 olmayanlar)
            mac = get_current_mac(iface)
            if mac and mac != "00:00:00:00:00:00":
                interfaces.append(iface)
    except Exception as err:
        logger.warning("Fiziksel arayüzler taranamadı: %s", err)

    return interfaces


class MACManager:
    """Ağ arayüzü MAC adresi sahteleme ve geri yükleme yöneticisi."""

    def __init__(self) -> None:
        # {iface: original_mac}
        self.original_macs: Dict[str, str] = {}

    def randomize_interface_mac(self, iface: str, in_place: bool = True) -> Dict[str, Any]:
        """Belirtilen arayüzün MAC adresini rastgele bir adresle değiştirir.

        NetworkManager yarış durumunu engellemek için önce in-place yöntem denenir.

        Args:
            iface: MAC adresi değiştirilecek arayüz adı (örn: eth0).
            in_place: Arayüzü down yapmadan yerinde değiştirmeyi dene.

        Returns:
            Dict[str, Any]: İşlem sonucu.
        """
        clean_iface = cfg_interface_name(iface)
        old_mac = get_current_mac(clean_iface)
        new_mac = generate_random_mac()

        result: Dict[str, Any] = {
            "interface": clean_iface,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "success": False,
            "method": "in_place" if in_place else "down_up",
            "error": None,
        }

        if not old_mac:
            result["error"] = f"Arayüzün mevcut MAC adresi tespit edilemedi: {clean_iface}"
            return result

        # Orijinal MAC daha önce kaydedilmemişse hafızaya al (Kalıcı fabrika adresi tercih edilir)
        if clean_iface not in self.original_macs:
            perm_mac = get_permanent_mac(clean_iface)
            self.original_macs[clean_iface] = perm_mac or old_mac

        # 1. Yöntem: In-place (Arayüzü düşürmeden yerinde değiştirme)
        if in_place:
            try:
                cmd = ["ip", "link", "set", "dev", clean_iface, "address", new_mac]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
                if proc.returncode == 0:
                    current = get_current_mac(clean_iface)
                    if current == new_mac:
                        result["success"] = True
                        logger.info("%s MAC adresi yerinde (in-place) başarıyla değiştirildi: %s", clean_iface, new_mac)
                        return result
            except Exception as err:
                logger.debug("In-place MAC değişimi desteklenmiyor (%s): %s", clean_iface, err)

        # 2. Yöntem: Geçici down / up döngüsü
        logger.info("%s için down/up yöntemiyle MAC değiştiriliyor...", clean_iface)
        try:
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "down"], timeout=5, check=False)
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "address", new_mac], timeout=5, check=False)
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "up"], timeout=5, check=False)

            current = get_current_mac(clean_iface)
            if current == new_mac:
                result["success"] = True
                result["method"] = "down_up"
                logger.info("%s MAC adresi down/up ile değiştirildi: %s", clean_iface, new_mac)
            else:
                result["error"] = f"MAC adresi değişimi uygulanamadı (Mevcut: {current})"
        except Exception as err:
            result["error"] = f"MAC değiştirilirken hata oluştu: {err}"

        return result

    def randomize_all_physical_interfaces(self, in_place: bool = True) -> Dict[str, Any]:
        """Sistemdeki tüm fiziksel arayüzlerin MAC adreslerini randomize eder."""
        interfaces = get_physical_interfaces()
        results = {}
        for iface in interfaces:
            results[iface] = self.randomize_interface_mac(iface, in_place=in_place)
        return results

    def restore_interface_mac(self, iface: str) -> bool:
        """Arayüzün orijinal donanım MAC adresini geri yükler."""
        clean_iface = cfg_interface_name(iface)
        original_mac = self.original_macs.get(clean_iface) or get_permanent_mac(clean_iface)
        if not original_mac:
            return True

        logger.info("%s orijinal MAC adresi geri yükleniyor: %s", clean_iface, original_mac)

        # 1. Yöntem: In-place (Arayüzü düşürmeden yerinde geri yüklemeyi dene)
        try:
            cmd = ["ip", "link", "set", "dev", clean_iface, "address", original_mac]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            if proc.returncode == 0:
                current = get_current_mac(clean_iface)
                if current == original_mac:
                    logger.info("%s orijinal MAC adresi yerinde (in-place) başarıyla geri yüklendi.", clean_iface)
                    return True
        except Exception as err:
            logger.debug("%s yerinde geri yükleme başarısız, down/up deneniyor: %s", clean_iface, err)

        # 2. Yöntem: Geçici down / up döngüsü
        try:
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "down"], timeout=5, check=False)
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "address", original_mac], timeout=5, check=False)
            subprocess.run(["ip", "link", "set", "dev", clean_iface, "up"], timeout=5, check=False)

            current = get_current_mac(clean_iface)
            if current == original_mac:
                logger.info("%s orijinal MAC adresi down/up ile geri yüklendi.", clean_iface)
                return True
            else:
                logger.warning("%s MAC adresi doğrulanamadı (Mevcut: %s, Hedef: %s)", clean_iface, current, original_mac)
                return False
        except Exception as err:
            logger.error("%s orijinal MAC geri yüklenemedi: %s", clean_iface, err)
            return False

    def restore_all(self) -> None:
        """Tüm değiştirilmiş arayüzlerin orijinal MAC adreslerini geri yükler."""
        for iface in list(self.original_macs.keys()):
            self.restore_interface_mac(iface)
        self.original_macs.clear()
