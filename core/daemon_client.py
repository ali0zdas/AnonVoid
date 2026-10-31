"""AnonVoid - Asenkron GUI ve CLI Daemon İstemcisi.

Bu modül; PyQt6 kullanıcı arayüzünün veya bağımsız komut satırı araçlarının
root yetkili arka plan servisiyle (/run/anonvoid/daemon.sock) güvenle haberleşmesini sağlar.
Asenkron iş parçacığı (threading ve opsiyonel QThread) desteği sunar.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("AnonVoidClient")

# Varsayılan Soket Yolu
DEFAULT_SOCKET_PATH = "/run/anonvoid/daemon.sock"


# -----------------------------------------------------------------------------
# GUI İş Parçacığına Geri Çağrı Taşıma Köprüsü
# -----------------------------------------------------------------------------
# Qt, her QObject'in ait olduğu tek bir iş parçacığı vardır. Bir QWidget'e
# başka bir iş parçacığından erişmek "Cannot create children for a parent that
# is in a different thread" uyarısı üretir ve uygulamayı çökertir. Bu köprü,
# arka plan iş parçacığından gelen geri çağrıları GUI iş parçacığına kuyruklu
# (queued) sinyal ile aktarır.
_GUI_INVOKER: Optional["_QtGuiInvoker"] = None

try:
    from PyQt6.QtCore import QObject, Qt, pyqtSignal

    class _QtGuiInvoker(QObject):
        """Arka plan iş parçacığından GUI iş parçacığına çağrı aktarır."""

        _invoke = pyqtSignal(object)

        def __init__(self) -> None:
            super().__init__()
            self._invoke.connect(self._run, Qt.ConnectionType.QueuedConnection)

        def _run(self, fn: Callable[[], None]) -> None:
            try:
                fn()
            except Exception as err:
                logger.exception("GUI iş parçacığına aktarılan geri çağrı başarısız: %s", err)

        def post(self, fn: Callable[[], None]) -> None:
            self._invoke.emit(fn)

    def _get_gui_invoker() -> Optional["_QtGuiInvoker"]:
        """GUI iş parçacığında yaşayan köprüyü döndürür (Qt yoksa None).

        Köprü, ana (GUI) iş parçacığında oluşturulmalıdır; bu yüzden ilk çağrı
        AsyncDaemonWorker.__init__ içinden, yani iş parçacığı başlatılmadan
        önce yapılır.
        """
        global _GUI_INVOKER
        if _GUI_INVOKER is not None:
            return _GUI_INVOKER
        try:
            from PyQt6.QtWidgets import QApplication

            if QApplication.instance() is None:
                return None
            _GUI_INVOKER = _QtGuiInvoker()
        except ImportError:
            return None
        return _GUI_INVOKER

except ImportError:
    # PyQt6 kurulu değilse (CLI kullanımı) doğrudan çağırma yoluna düşülür
    _QtGuiInvoker = None  # type: ignore

    def _get_gui_invoker() -> None:  # type: ignore[misc]
        return None


class DaemonError(Exception):
    """Daemon istemcisi temel istisna sınıfı."""


class DaemonConnectionError(DaemonError):
    """Sokete bağlanılamadığında veya daemon kapalı olduğunda fırlatılır."""


class DaemonPermissionError(DaemonError):
    """Kullanıcının sokete erişim yetkisi (grup üyeliği) olmadığında fırlatılır."""


class DaemonResponseError(DaemonError):
    """Daemon geçersiz bir yanıt veya hata kodu döndüğünde fırlatılır."""


class DaemonClient:
    """Ayrıcalıklı Root Daemon ile haberleşen Unix Domain Socket İstemcisi."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH) -> None:
        self.socket_path = socket_path

    def is_daemon_alive(self, timeout: float = 1.5) -> bool:
        """Daemon'ın aktif ve yanıt verir durumda olup olmadığını kontrol eder.

        Args:
            timeout: Yanıt bekleme zaman aşımı (saniye).

        Returns:
            bool: Daemon çalışıyor ve pong yanıtı verdiyse True.
        """
        try:
            resp = self.send_request("ping", timeout=timeout)
            return resp.get("status") == "ok" and resp.get("data", {}).get("message") == "pong"
        except Exception:
            return False

    def send_request(
        self,
        action: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """Daemon'a tekil bir JSON komutu gönderir ve yanıtı bekler.

        Args:
            action: Tetiklenecek eylem adı (ping, connect, clean_forensics vb.).
            params: Eyleme gönderilecek parametreler.
            timeout: Maksimum bekleme süresi (saniye).

        Returns:
            Dict[str, Any]: Daemon tarafından döndürülen JSON yanıtı.

        Raises:
            DaemonConnectionError: Soket dosyası yoksa veya bağlantı reddedilirse.
            DaemonPermissionError: Soket okuma/yazma izni yetersizse.
            DaemonResponseError: Daemon hata döndürürse veya yanıt bozuksa.
        """
        if not os.path.exists(self.socket_path):
            raise DaemonConnectionError(
                f"Daemon soketi bulunamadı: {self.socket_path}. "
                "Lütfen anonvoid daemon servisinin çalıştığından emin olun."
            )

        req_id = str(uuid.uuid4())
        payload = {
            "action": str(action).strip().lower(),
            "params": params or {},
            "req_id": req_id,
        }

        try:
            req_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as err:
            raise DaemonResponseError(f"İstek JSON'a dönüştürülemedi: {err}") from err

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect(self.socket_path)
            sock.sendall(req_bytes)

            # Yanıtı oku
            buffer = bytearray()
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\n" in buffer:
                    break

            if not buffer:
                raise DaemonResponseError("Daemon'dan boş yanıt alındı (bağlantı aniden kapandı).")

            response_text = buffer.decode("utf-8").strip()
            response_data = json.loads(response_text)

            if not isinstance(response_data, dict):
                raise DaemonResponseError("Daemon'dan geçersiz biçimli yanıt alındı.")

            if response_data.get("status") != "ok":
                err_msg = response_data.get("error", "Bilinmeyen daemon hatası")
                raise DaemonResponseError(f"Daemon hatası: {err_msg}")

            return response_data

        except PermissionError as err:
            raise DaemonPermissionError(
                f"Soket erişim izni reddedildi: {self.socket_path}. "
                "Kullanıcınızın 'anonvoid' grubuna dahil olduğundan emin olun."
            ) from err
        except (ConnectionRefusedError, FileNotFoundError) as err:
            raise DaemonConnectionError(
                f"Daemon bağlantısı kurulamadı ({self.socket_path}): {err}"
            ) from err
        except socket.timeout as err:
            raise DaemonResponseError(
                f"Daemon yanıt vermedi (Zaman aşımı: {timeout}s)."
            ) from err
        except json.JSONDecodeError as err:
            raise DaemonResponseError(
                f"Daemon yanıtı geçerli bir JSON değil: {err}"
            ) from err
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # -------------------------------------------------------------------------
    # Kolaylaştırıcı Yüksek Düzey API Metotları
    # -------------------------------------------------------------------------
    def ping(self) -> Dict[str, Any]:
        """Canlılık testi gerçekleştirir."""
        return self.send_request("ping", timeout=3.0)

    def get_status(self) -> Dict[str, Any]:
        """Mevcut servislerin ve koruma durumunun özetini alır."""
        return self.send_request("status", timeout=5.0)

    def connect_network(self, network_config: Dict[str, Any], timeout: float = 120.0) -> Dict[str, Any]:
        """Ağ kalkanını verilen yapılandırmayla aktifleştirir."""
        return self.send_request("connect", params={"network": network_config}, timeout=timeout)

    def disconnect_network(self) -> Dict[str, Any]:
        """Ağ kalkanını devreden çıkarır ve sistemi normale döndürür."""
        return self.send_request("disconnect", timeout=15.0)

    def new_tor_circuit(self) -> Dict[str, Any]:
        """Tor devre yenilemesini tetikler (Yeni kimlik)."""
        return self.send_request("new_circuit", timeout=10.0)

    def clean_forensics(self, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Seçilen adli iz temizleme modüllerini çalıştırır."""
        return self.send_request("clean_forensics", params={"targets": targets}, timeout=60.0)

    def run_leak_test(self) -> Dict[str, Any]:
        """Ağ sızıntı testini yürütür."""
        return self.send_request("leak_test", timeout=30.0)

    def emergency_panic(self) -> Dict[str, Any]:
        """Acil durum panik mekanizmasını tetikler."""
        return self.send_request("panic", timeout=10.0)

    def scan_forensic_exposure(self, timeout: float = 30.0) -> Dict[str, Any]:
        """Kullanıcının adli iz maruziyet skorunu tarar."""
        return self.send_request("scan_exposure", timeout=timeout)

    def sanitize_metadata(self, filepath: str, timeout: float = 30.0) -> Dict[str, Any]:
        """Belirtilen dosyanın meta verilerini adli standartlarda temizler."""
        return self.send_request("sanitize_metadata", params={"filepath": filepath}, timeout=timeout)

    def list_usb_devices(self, timeout: float = 10.0) -> Dict[str, Any]:
        """Sisteme bağlı USB cihazlarının listesini alır."""
        return self.send_request("usb_devices", timeout=timeout)

    def configure_usb_guard(
        self,
        enabled: bool,
        device_id: str = "",
        panic_shutdown: bool = False,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """USB Kill-Switch ve Dead Man's Switch monitörünü yapılandırır."""
        return self.send_request(
            "usb_guard_configure",
            params={
                "enabled": enabled,
                "device_id": device_id,
                "panic_shutdown": panic_shutdown,
            },
            timeout=timeout,
        )


# -----------------------------------------------------------------------------
# Asenkron Worker (GUI Arayüzünü Kilitlemeyen İş Parçacığı)
# -----------------------------------------------------------------------------
class AsyncDaemonWorker(threading.Thread):
    """GUI'yi dondurmadan arka planda daemon istekleri yürüten iş parçacığı."""

    def __init__(
        self,
        client: DaemonClient,
        action: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
        on_success: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_finished: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.client = client
        self.action = action
        self.params = params
        self.timeout = timeout
        self.on_success = on_success
        self.on_error = on_error
        self.on_finished = on_finished
        # Köprü, bu satır GUI iş parçacığında çalıştığı için doğru iş parçacığına
        # ait olacak biçimde oluşturulur.
        self._invoker = _get_gui_invoker()

    def _dispatch(self, fn: Optional[Callable[[], None]]) -> None:
        """Geri çağrıyı GUI iş parçacığında çalıştırır.

        Köprü yoksa (Qt bulunmayan CLI ortamı) doğrudan çağrılır.
        """
        if fn is None:
            return
        if self._invoker is not None:
            self._invoker.post(fn)
        else:
            fn()

    def run(self) -> None:
        """İsteği arka planda yürütür ve geri çağırma (callback) fonksiyonlarını tetikler.

        NOT: Geri çağrılar doğrudan bu iş parçacığında değil, GUI iş parçacığında
        çalıştırılır. Aksi halde arayüz bileşenlerine yanlış iş parçacığından
        erişilir ve Qt uygulamayı çökertir.
        """
        try:
            result = self.client.send_request(
                self.action,
                params=self.params,
                timeout=self.timeout,
            )
            if self.on_success:
                data = result.get("data", {})
                self._dispatch(lambda: self.on_success(data))  # type: ignore[misc]
        except Exception as err:
            logger.error("Arka plan iş parçacığında istek başarısız (%s): %s", self.action, err)
            if self.on_error:
                message = str(err)
                self._dispatch(lambda: self.on_error(message))  # type: ignore[misc]
        finally:
            self._dispatch(self.on_finished)


# -----------------------------------------------------------------------------
# PyQt6 Kurulu İse QThread Tabanlı Worker Sınıfı
# -----------------------------------------------------------------------------
try:
    from PyQt6.QtCore import QThread, pyqtSignal

    class QtDaemonWorker(QThread):
        """PyQt6 olay döngüsü ile doğrudan sinyal-yuva (signal-slot) uyumlu worker."""

        succeeded = pyqtSignal(dict)
        failed = pyqtSignal(str)
        finished_task = pyqtSignal()

        def __init__(
            self,
            client: DaemonClient,
            action: str,
            params: Optional[Dict[str, Any]] = None,
            timeout: float = 30.0,
            parent: Any = None,
        ) -> None:
            super().__init__(parent)
            self.client = client
            self.action = action
            self.params = params
            self.timeout = timeout

        def run(self) -> None:
            """Arka planda çalışır ve Qt sinyalleri üretir."""
            try:
                result = self.client.send_request(
                    self.action,
                    params=self.params,
                    timeout=self.timeout,
                )
                self.succeeded.emit(result.get("data", {}))
            except Exception as err:
                self.failed.emit(str(err))
            finally:
                self.finished_task.emit()

except ImportError:
    # PyQt6 henüz kurulu değilse sessizce geç
    QtDaemonWorker = None  # type: ignore
