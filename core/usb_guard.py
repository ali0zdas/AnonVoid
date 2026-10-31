"""AnonVoid - USB Kill-Switch ve Donanımsal Acil Durum Monitörü (Dead Man's Switch).

Bu modül; Linux sistemlerde /sys/bus/usb/devices arayüzü üzerinden sisteme bağlı
tüm USB cihazlarını listeler ve eşleştirilmiş bir güvenlik anahtarının (USB dongle /
flash bellek) fiziksel olarak çıkarılması veya sisteme yetkisiz yeni bir USB aygıtının
takılması durumunda acil durum panik protokolünü (nuke/wipe/shutdown) anında tetikler.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("AnonVoidUSBGuard")

# Linux USB sistem veri yolu dizini
SYS_USB_BUS_PATH = "/sys/bus/usb/devices"

# Vendor/Product ID doğrulama deseni (4 haneli onaltılık sayı)
HEX4_REGEX = re.compile(r"^[0-9a-fA-F]{4}$")


def _read_sys_file(filepath: str) -> str:
    """Linux sysfs dosyasını güvenle okur ve içeriğini döndürür."""
    try:
        if os.path.isfile(filepath):
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip()
    except (OSError, UnicodeDecodeError):
        pass
    return ""


def list_usb_devices(sys_usb_path: str = SYS_USB_BUS_PATH) -> List[Dict[str, Any]]:
    """Sisteme bağlı fiziksel USB cihazlarını sysfs üzerinden listeler.

    Args:
        sys_usb_path: USB cihazlarının sysfs üzerindeki dizin yolu.

    Returns:
        List[Dict[str, Any]]: Tespit edilen her bir USB aygıtının bilgilerini içeren liste.
    """
    devices: List[Dict[str, Any]] = []

    if not os.path.exists(sys_usb_path) or not os.path.isdir(sys_usb_path):
        return devices

    try:
        entries = os.listdir(sys_usb_path)
    except OSError as err:
        logger.warning("USB sistem yolu listelenemedi (%s): %s", sys_usb_path, err)
        return devices

    for entry in sorted(entries):
        # Arayüz alt dizinlerini (örn. 1-1:1.0) ele, sadece ana cihazları tara
        if ":" in entry:
            continue

        entry_path = os.path.join(sys_usb_path, entry)
        vendor_file = os.path.join(entry_path, "idVendor")
        product_file = os.path.join(entry_path, "idProduct")

        if not (os.path.exists(vendor_file) and os.path.exists(product_file)):
            continue

        vendor_id = _read_sys_file(vendor_file).lower()
        product_id = _read_sys_file(product_file).lower()

        if not (HEX4_REGEX.match(vendor_id) and HEX4_REGEX.match(product_id)):
            continue

        device_id = f"{vendor_id}:{product_id}"
        manufacturer = _read_sys_file(os.path.join(entry_path, "manufacturer"))
        product_name = _read_sys_file(os.path.join(entry_path, "product"))
        serial = _read_sys_file(os.path.join(entry_path, "serial"))
        busnum = _read_sys_file(os.path.join(entry_path, "busnum"))
        devnum = _read_sys_file(os.path.join(entry_path, "devnum"))

        # Linux kök hub'ları (1d6b) genellikle anakart dahili USB kontrolcüleridir
        is_root_hub = (vendor_id == "1d6b")

        devices.append({
            "device_id": device_id,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "manufacturer": manufacturer,
            "product": product_name,
            "serial": serial,
            "busnum": busnum,
            "devnum": devnum,
            "is_root_hub": is_root_hub,
            "sys_path": entry_path,
        })

    return devices


class USBKillSwitchMonitor:
    """Arka planda USB donanım değişikliklerini takip eden Dead Man's Switch monitörü."""

    def __init__(
        self,
        authorized_device_id: str,
        on_trigger: Callable[[], Any],
        poll_interval: float = 1.0,
        trigger_on_removal: bool = True,
        trigger_on_unauthorized_insert: bool = False,
        sys_usb_path: str = SYS_USB_BUS_PATH,
    ) -> None:
        """USB Kill-Switch Monitörünü yapılandırır.

        Args:
            authorized_device_id: Güvenlik anahtarı olarak yetkilendirilmiş aygıt (örn: '0781:5583').
            on_trigger: Anahtar çekildiğinde veya yetkisiz aygıt takıldığında çağrılacak acil durum fonksiyonu.
            poll_interval: Sysfs tarama sıklığı (saniye).
            trigger_on_removal: Eşleşen USB anahtarı çıkarıldığında panik tetiklensin mi.
            trigger_on_unauthorized_insert: Beyaz liste harici yeni bir aygıt takıldığında tetiklensin mi.
            sys_usb_path: Linux sysfs USB cihazları yolu.
        """
        self.authorized_device_id = authorized_device_id.strip().lower()
        self.on_trigger = on_trigger
        self.poll_interval = max(0.2, float(poll_interval))
        self.trigger_on_removal = trigger_on_removal
        self.trigger_on_unauthorized_insert = trigger_on_unauthorized_insert
        self.sys_usb_path = sys_usb_path

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._triggered = False
        self._lock = threading.Lock()
        self._baseline_device_ids: Optional[Set[str]] = None

    def is_active(self) -> bool:
        """Monitörün aktif olarak çalışıp çalışmadığını döndürür."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive() and not self._triggered

    def start(self) -> bool:
        """USB takip iş parçacığını başlatır."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("USB Kill-Switch monitörü zaten çalışıyor.")
                return True

            self._stop_event.clear()
            self._triggered = False

            # Başlangıç cihaz tabanını (baseline) çıkar
            current_devices = list_usb_devices(self.sys_usb_path)
            self._baseline_device_ids = {d["device_id"] for d in current_devices}

            logger.info(
                "USB Kill-Switch monitörü başlatılıyor (Yetkili Cihaz: %s, Çekilme Takibi: %s, İzinsiz Giriş Takibi: %s).",
                self.authorized_device_id or "Tanımsız",
                self.trigger_on_removal,
                self.trigger_on_unauthorized_insert,
            )

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="AnonVoidUSBGuardThread",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self) -> None:
        """USB takip monitörünü güvenle durdurur."""
        self._stop_event.set()
        with self._lock:
            thread = self._thread
            self._thread = None

        if thread and thread.is_alive() and threading.current_thread() != thread:
            thread.join(timeout=3.0)
        logger.info("USB Kill-Switch monitörü durduruldu.")

    def _monitor_loop(self) -> None:
        """Periyodik sysfs tarama döngüsü."""
        # İlk kontrol: Eğer çıkarılma takibi açıksa ve yetkili aygıt hiç takılı değilse kullanıcıyı uyar
        if self.trigger_on_removal and self.authorized_device_id:
            if self.authorized_device_id not in (self._baseline_device_ids or set()):
                logger.warning(
                    "USB Kill-Switch Uyarısı: Belirtilen yetkili aygıt (%s) sistemde takılı görünmüyor! "
                    "Aygıt takılana kadar 3 saniye tolerans tanınıyor...",
                    self.authorized_device_id,
                )
                # 3 saniyelik başlangıç toleransı
                for _ in range(6):
                    if self._stop_event.wait(0.5):
                        return
                    devs = list_usb_devices(self.sys_usb_path)
                    if any(d["device_id"] == self.authorized_device_id for d in devs):
                        logger.info("Yetkili USB aygıtı (%s) algılandı.", self.authorized_device_id)
                        if self._baseline_device_ids is not None:
                            self._baseline_device_ids.add(self.authorized_device_id)
                        break

        while not self._stop_event.is_set():
            if self._stop_event.wait(self.poll_interval):
                break

            current_devices = list_usb_devices(self.sys_usb_path)
            current_ids = {d["device_id"] for d in current_devices}

            # 1. Çekilme (Removal / Dead Man's Switch) Denetimi
            if self.trigger_on_removal and self.authorized_device_id:
                if self.authorized_device_id not in current_ids:
                    logger.critical(
                        "KRİTİK GÜVENLİK ALARMI: Yetkili USB Güvenlik Anahtarı (%s) ÇEKİLDİ! "
                        "Panik imha protokolü tetikleniyor!",
                        self.authorized_device_id,
                    )
                    self._fire_trigger()
                    break

            # 2. Yetkisiz Yeni Cihaz Takılma Denetimi
            if self.trigger_on_unauthorized_insert and self._baseline_device_ids is not None:
                new_devices = current_ids - self._baseline_device_ids
                # Eğer yeni takılan cihaz yetkili aygıt ise alarm verme
                if self.authorized_device_id:
                    new_devices.discard(self.authorized_device_id)

                if new_devices:
                    logger.critical(
                        "KRİTİK GÜVENLİK ALARMI: Sisteme yetkisiz yeni USB aygıtı takıldı: %s! "
                        "Panik imha protokolü tetikleniyor!",
                        list(new_devices),
                    )
                    self._fire_trigger()
                    break

    def _fire_trigger(self) -> None:
        """Acil durum tetiğini anında ateşler."""
        with self._lock:
            self._triggered = True
        try:
            self.on_trigger()
        except Exception as err:
            logger.exception("USB Kill-Switch tetikleyici fonksiyon hatası: %s", err)
