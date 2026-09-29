"""AnonVoid - Ayrıcalıklı Root IPC Daemon Servisi.

Bu modül; sistem seviyesinde (root) çalışarak /run/anonvoid/daemon.sock üzerinde dinler,
SO_PEERCRED ile bağlanan istemcinin gerçek Linux çekirdek UID/GID kimliğini doğrular,
katı komut beyaz listesi (whitelisting) uygular ve başlangıçta kendini iyileştirir (_startup_heal).
"""

from __future__ import annotations

try:
    import grp
except ImportError:
    grp = None  # type: ignore

try:
    import pwd
except ImportError:
    pwd = None  # type: ignore

import json
import logging
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.config import (
    DEFAULT_CONFIG,
    MAX_CONFIG_FILE_SIZE,
    cfg_port,
    cfg_uid,
    safe_load_config,
    validate_forensics_config,
    validate_network_config,
)
from core.forensics.manager import ForensicsManager
from core.network.dnscrypt import DNSCryptManager
from core.network.firewall import FirewallEngine
from core.network.leak_test import run_full_leak_test
from core.network.mac import MACManager
from core.network.panic import execute_panic_nuke
from core.network.tor import TorManager, renew_tor_circuit

# Linux üzerinde SO_PEERCRED soket seçeneği sabiti
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

# Sabit Değerler
SOCKET_DIR = "/run/anonvoid"
SOCKET_PATH = "/run/anonvoid/daemon.sock"
SOCKET_PERM = 0o660
SOCKET_GROUP = "anonvoid"
MAX_PAYLOAD_SIZE = 65536  # 64 Kilobayt
DAEMON_VERSION = "1.0.0"

# Günlük Kaydı Yapılandırması
logger = logging.getLogger("AnonVoidDaemon")


def get_peer_credentials(sock: socket.socket) -> Tuple[int, int, int]:
    """Linux çekirdeğinden bağlanan istemcinin gerçek (PID, UID, GID) bilgilerini okur.

    SO_PEERCRED soket seçeneği kullanılarak kimlik sahteciliği (spoofing) engellenir.

    Args:
        sock: İstemci bağlantı soketi.

    Returns:
        Tuple[int, int, int]: (pid, uid, gid) üçlüsü.

    Raises:
        PermissionError: Çekirdek kimlik bilgisi alınamazsa veya platform desteklemiyorsa.
    """
    try:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; } -> 3 adet 32-bit signed int
        cred_bytes = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", cred_bytes)
        return pid, uid, gid
    except Exception as err:
        # Linux dışı veya kısıtlı geliştirme ortamları için kontrollü hata
        if sys.platform != "linux":
            # Geliştirme/test ortamı için kontrollü simülasyon
            return os.getpid(), os.getuid() if hasattr(os, "getuid") else 1000, 1000
        raise PermissionError(f"SO_PEERCRED çekirdek kimliği okunamadı: {err}") from err


class RootDaemon:
    """AnonVoid Ayrıcalıklı Root IPC Sunucusu."""

    def __init__(
        self,
        socket_path: str = SOCKET_PATH,
        socket_group: str = SOCKET_GROUP,
        config_path: Optional[str] = None,
    ) -> None:
        self.socket_path = socket_path
        self.socket_group = socket_group
        self.config_path = config_path or f"{SOCKET_DIR}/active_config.json"
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

        # Sistem Durum Göstergeleri
        self.state: Dict[str, Any] = {
            "daemon_version": DAEMON_VERSION,
            "started_at": time.time(),
            "network_shield_active": False,
            "tor_active": False,
            "dnscrypt_active": False,
            "i2p_active": False,
            "last_circuit_renewal": 0.0,
            "last_forensics_cleanup": 0.0,
            "active_clients": 0,
        }

        # Ağ ve Güvenlik Motorları
        self.firewall = FirewallEngine()
        self.tor_manager = TorManager()
        self.dnscrypt_manager = DNSCryptManager()
        self.mac_manager = MACManager()

        # Katı Komut Beyaz Listesi (Whitelisted Dispatch Table)
        self._handlers: Dict[str, Callable[[Dict[str, Any], int, int], Dict[str, Any]]] = {
            "ping": self._handle_ping,
            "status": self._handle_status,
            "connect": self._handle_connect,
            "disconnect": self._handle_disconnect,
            "new_circuit": self._handle_new_circuit,
            "clean_forensics": self._handle_clean_forensics,
            "leak_test": self._handle_leak_test,
            "panic": self._handle_panic,
        }

    # -------------------------------------------------------------------------
    # Açılışta Kendi Kendini İyileştirme (Startup Self-Heal)
    # -------------------------------------------------------------------------
    def startup_heal(self) -> None:
        """Beklenmedik kapanmalarda askıda kalan firewall, DNS ve kilitleri temizler.

        Adımlar:
          1. Askıda kalan nftables ve iptables kurallarını sıfırlar.
          2. DNS yapılandırmasını orijinal haline döndürür.
          3. Yetim Tor kilit dosyalarını ve çalışma soketlerini temizler.
        """
        logger.info("Başlangıç kendi kendini iyileştirme (_startup_heal) süreci başlatıldı.")

        # 1. nftables temizliği (anonvoid ve fp-cleaner tabloları)
        tables_to_delete = [
            ("inet", "anonvoid"),
            ("ip6", "anonvoid"),
            ("inet", "fp-cleaner"),
            ("ip6", "fp-cleaner"),
        ]
        for family, table_name in tables_to_delete:
            try:
                subprocess.run(
                    ["nft", "delete", "table", family, table_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # 2. DNS yapılandırmasını geri alma (systemd-resolved revert)
        try:
            # Sistemdeki aktif ağ arayüzlerini al ve revert dene
            result = subprocess.run(
                ["ip", "-o", "link", "show", "up"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
                check=False,
            )
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    iface = parts[1].strip()
                    if iface and not iface.startswith(("lo", "docker", "veth", "virbr")):
                        subprocess.run(
                            ["resolvectl", "revert", iface],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=2,
                            check=False,
                        )
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        # 3. /run/fp-cleaner altındaki yetim kilit ve geçici dosyaları süpür
        if os.path.exists(SOCKET_DIR):
            try:
                for fname in os.listdir(SOCKET_DIR):
                    if fname.endswith((".lock", ".pid", ".tmp")):
                        fpath = os.path.join(SOCKET_DIR, fname)
                        try:
                            if not os.path.islink(fpath):
                                os.unlink(fpath)
                        except OSError:
                            pass
            except OSError:
                pass

        logger.info("Başlangıç kendi kendini iyileştirme adımları tamamlandı.")

    # -------------------------------------------------------------------------
    # Soket ve İzin Yaşam Döngüsü
    # -------------------------------------------------------------------------
    def _setup_socket(self) -> socket.socket:
        """Unix Domain Socket dosyasını güvenli izinlerle açar."""
        # /run/fp-cleaner dizinini oluştur (İzin: 0755 root:root)
        os.makedirs(SOCKET_DIR, mode=0o755, exist_ok=True)

        # Eski soket dosyası varsa güvenle kaldır
        if os.path.exists(self.socket_path):
            try:
                if os.path.islink(self.socket_path):
                    os.unlink(self.socket_path)
                else:
                    # Başka aktif bir daemon var mı kontrol et
                    test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    try:
                        test_sock.connect(self.socket_path)
                        test_sock.close()
                        raise RuntimeError(
                            f"Aktif bir daemon zaten çalışıyor: {self.socket_path}"
                        )
                    except (ConnectionRefusedError, OSError):
                        os.unlink(self.socket_path)
            except OSError as err:
                raise RuntimeError(f"Eski soket dosyası temizlenemedi: {err}") from err

        # Soket oluştur
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(self.socket_path)

        # İzinleri ayarla: 0660 (root ve grup okuyup yazabilir, diğerleri erişemez)
        try:
            os.chmod(self.socket_path, SOCKET_PERM)
        except OSError as err:
            logger.warning("Soket izinleri 0660 olarak ayarlanamadı: %s", err)

        # Grup sahipliğini ayarla: root:fp-cleaner
        if hasattr(os, "chown") and grp is not None and hasattr(grp, "getgrnam"):
            try:
                group_info = grp.getgrnam(self.socket_group)
                gid = group_info.gr_gid
                os.chown(self.socket_path, 0, gid)
                logger.info(
                    "Soket grubu başarıyla '%s' (GID: %d) olarak atandı.",
                    self.socket_group,
                    gid,
                )
            except KeyError:
                logger.warning(
                    "'%s' kullanıcı grubu sistemde bulunamadı. "
                    "Soket yalnızca root erişimine açık kalacak.",
                    self.socket_group,
                )
            except PermissionError as err:
                logger.warning("Soket grup sahipliği atanamadı: %s", err)

        server_sock.listen(10)
        return server_sock

    def _verify_client_access(self, uid: int, gid: int) -> bool:
        """İstemcinin yetkili olup olmadığını doğrular (Root veya grup üyesi)."""
        # Root her zaman yetkilidir
        if uid == 0:
            return True

        if grp is not None and hasattr(grp, "getgrnam"):
            try:
                group_info = grp.getgrnam(self.socket_group)
                # İstemcinin birincil grubu eşleşiyor mu
                if gid == group_info.gr_gid:
                    return True
                # İstemci kullanıcısının ek grupları kontrol edilir
                if pwd is not None and hasattr(pwd, "getpwuid"):
                    user_info = pwd.getpwuid(uid)
                    if user_info.pw_name in group_info.gr_mem:
                        return True
            except (KeyError, Exception):
                pass

        # Geliştirme veya tek kullanıcılı sistemlerde geçerli kullanıcı izinli
        return False

    # -------------------------------------------------------------------------
    # İstek Yönlendirme ve Komut Beyaz Listesi
    # -------------------------------------------------------------------------
    def _dispatch_request(self, raw_data: bytes, uid: int, gid: int) -> Dict[str, Any]:
        """Gelen JSON isteğini doğrular ve ilgili beyaz liste işleyicisine yönlendirir."""
        req_id = ""
        try:
            if len(raw_data) > MAX_PAYLOAD_SIZE:
                return {
                    "status": "error",
                    "req_id": req_id,
                    "error": f"İstek boyutu izin verilen {MAX_PAYLOAD_SIZE} bayt sınırını aştı.",
                }

            text = raw_data.decode("utf-8").strip()
            payload = json.loads(text)

            if not isinstance(payload, dict):
                return {
                    "status": "error",
                    "req_id": req_id,
                    "error": "İstek bir JSON nesnesi olmalıdır.",
                }

            req_id = str(payload.get("req_id", ""))
            action = str(payload.get("action", "")).strip().lower()
            params = payload.get("params", {})

            if not isinstance(params, dict):
                params = {}

            # Katı Beyaz Liste Kontrolü
            handler = self._handlers.get(action)
            if not handler:
                logger.warning(
                    "Yetkilendirilmemiş veya geçersiz eylem reddedildi: %r (UID: %d)",
                    action,
                    uid,
                )
                return {
                    "status": "error",
                    "req_id": req_id,
                    "action": action,
                    "error": f"Yetkilendirilmemiş veya geçersiz eylem: {action!r}",
                }

            # İlgili işleyiciyi çalıştır
            result_data = handler(params, uid, gid)
            return {
                "status": "ok",
                "req_id": req_id,
                "action": action,
                "data": result_data,
            }

        except json.JSONDecodeError as err:
            return {
                "status": "error",
                "req_id": req_id,
                "error": f"Geçersiz JSON biçimi: {err}",
            }
        except Exception as err:
            logger.exception("İstek işlenirken beklenmeyen bir hata oluştu: %s", err)
            return {
                "status": "error",
                "req_id": req_id,
                "error": f"Sunucu dahili hatası: {err}",
            }

    # -------------------------------------------------------------------------
    # Beyaz Listedeki Komut İşleyicileri (Handlers)
    # -------------------------------------------------------------------------
    def _handle_ping(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Canlılık kontrolü."""
        return {
            "message": "pong",
            "version": DAEMON_VERSION,
            "server_time": time.time(),
        }

    def _handle_status(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Mevcut daemon ve koruma durumu özetini döner."""
        with self._lock:
            status_copy = dict(self.state)
            status_copy["uptime_sec"] = time.time() - self.state["started_at"]
            status_copy["requester_uid"] = uid
            return status_copy

    def _handle_connect(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Ağ kalkanını (Tor, DNSCrypt, nftables, MAC) aktifleştirir."""
        validated_net = validate_network_config(params.get("network", {}))
        
        # 1. MAC Adresi Sahteleme (İsteğe bağlı)
        mac_results = {}
        if validated_net.get("mac_randomize", True):
            mac_results = self.mac_manager.randomize_all_physical_interfaces(
                in_place=validated_net.get("mac_in_place", True)
            )

        # 2. Tor Yapılandırması ve Yeniden Yükleme
        tor_success = True
        if validated_net.get("tor_enabled", True):
            tor_success = self.tor_manager.configure_and_reload(
                trans_port=validated_net["tor_trans_port"],
                dns_port=validated_net["tor_dns_port"],
                socks_port=validated_net["tor_socks_port"],
                control_port=validated_net["tor_control_port"],
            )

        # 3. DNSCrypt ve systemd-resolved Kilidi
        dns_success = True
        if validated_net.get("dnscrypt_enabled", True):
            dns_res = self.dnscrypt_manager.apply_dns_lock()
            dns_success = dns_res.get("success", True)

        # 4. nftables / iptables Güvenlik Duvarı Kuralları
        fw_success = self.firewall.apply_rules(
            trans_port=validated_net["tor_trans_port"],
            dns_port=validated_net["tor_dns_port"],
            block_doh=validated_net["block_doh"],
            drop_ipv6=validated_net["drop_ipv6"],
        )

        with self._lock:
            self.state["network_shield_active"] = fw_success
            self.state["tor_active"] = tor_success
            self.state["dnscrypt_active"] = dns_success
            self.state["i2p_active"] = validated_net.get("i2p_enabled", False)
            logger.info("Ağ kalkanı aktifleştirildi (İstemci UID: %d).", uid)

        return {
            "connected": fw_success,
            "network_config": validated_net,
            "firewall_active": fw_success,
            "tor_active": tor_success,
            "dnscrypt_active": dns_success,
            "mac_randomized": mac_results,
            "timestamp": time.time(),
        }

    def _handle_disconnect(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Ağ kalkanını güvenle devreden çıkarır ve sistemi normale döndürür."""
        # 1. Güvenlik duvarını sıfırla
        self.firewall.flush_rules()

        # 2. DNS kilidini kaldır
        self.dnscrypt_manager.revert_dns_lock()

        # 3. MAC adreslerini geri yükle
        self.mac_manager.restore_all()

        # 4. torrc yedeğini geri yükle
        self.tor_manager.restore_torrc()

        with self._lock:
            self.state["network_shield_active"] = False
            self.state["tor_active"] = False
            self.state["dnscrypt_active"] = False
            self.state["i2p_active"] = False
            logger.info("Ağ kalkanı kapatıldı (İstemci UID: %d).", uid)

        return {
            "connected": False,
            "timestamp": time.time(),
        }

    def _handle_new_circuit(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Tor Exit node kimliğini yeniler (SIGNAL NEWNYM)."""
        renew_res = renew_tor_circuit()
        with self._lock:
            if renew_res.get("success"):
                self.state["last_circuit_renewal"] = time.time()
        logger.info("Tor devre yenileme sinyali işlendi (İstemci UID: %d).", uid)
        return renew_res

    def _handle_clean_forensics(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Adli iz temizleme modüllerini tetikler."""
        validated_targets = validate_forensics_config(params.get("targets", {}))
        with self._lock:
            self.state["last_forensics_cleanup"] = time.time()

        # Kullanıcının kimliğinden ev dizini tespit edilir
        user_home = ""
        try:
            if pwd is not None and hasattr(pwd, "getpwuid"):
                user_info = pwd.getpwuid(uid)
                user_home = user_info.pw_dir
            else:
                user_home = os.environ.get("HOME", "") or os.path.expanduser("~")
        except Exception:
            user_home = os.environ.get("HOME", "") or os.path.expanduser("~")

        logger.info(
            "Adli temizlik talebi onaylandı (İstemci UID: %d, Ev: %s).",
            uid,
            user_home,
        )

        # Adli temizlik yöneticisini çalıştır
        manager = ForensicsManager()
        cleanup_report = manager.run_cleanup(
            targets=validated_targets,
            target_home=user_home,
        )

        return {
            "started": True,
            "completed": cleanup_report.get("completed", True),
            "targets": validated_targets,
            "target_home": user_home,
            "report": cleanup_report,
            "timestamp": time.time(),
        }

    def _handle_leak_test(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Canlı adli ağ sızıntı testini yürütür."""
        logger.info("Sızıntı testi başlatılıyor (İstemci UID: %d)...", uid)
        return run_full_leak_test()

    def _handle_panic(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Acil durum: Tüm açık soketleri keser, belleği ve komut geçmişini yok eder."""
        logger.critical("PANİK BUTONU TETİKLENDİ! (İstemci UID: %d)", uid)
        with self._lock:
            self.state["network_shield_active"] = False
            self.state["tor_active"] = False
            self.state["dnscrypt_active"] = False

        user_home = ""
        try:
            if pwd is not None and hasattr(pwd, "getpwuid"):
                user_info = pwd.getpwuid(uid)
                user_home = user_info.pw_dir
            else:
                user_home = os.environ.get("HOME", "") or os.path.expanduser("~")
        except Exception:
            user_home = os.environ.get("HOME", "") or os.path.expanduser("~")

        shutdown_sys = bool(params.get("shutdown_system", False))
        return execute_panic_nuke(
            target_home=user_home,
            wipe_shell=True,
            clear_ram=True,
            shutdown_system=shutdown_sys,
        )

    # -------------------------------------------------------------------------
    # İstemci İletişim Döngüsü
    # -------------------------------------------------------------------------
    def _client_worker(self, client_sock: socket.socket) -> None:
        """Her istemci bağlantısını ayrı bir iş parçacığında güvenle işler."""
        try:
            client_sock.settimeout(15.0)

            # 1. SO_PEERCRED ile gerçek istemci kimliğini çekirdekten doğrula
            try:
                pid, uid, gid = get_peer_credentials(client_sock)
            except Exception as err:
                logger.error("İstemci kimliği doğrulanamadı, bağlantı kesiliyor: %s", err)
                client_sock.close()
                return

            # 2. Yetki denetimi
            if not self._verify_client_access(uid, gid):
                logger.warning(
                    "Yetkisiz istemci erişimi engellendi (PID: %d, UID: %d, GID: %d).",
                    pid,
                    uid,
                    gid,
                )
                err_resp = {
                    "status": "error",
                    "error": f"Erişim reddedildi: UID {uid} '{self.socket_group}' grubunda değil.",
                }
                client_sock.sendall(json.dumps(err_resp).encode("utf-8") + b"\n")
                client_sock.close()
                return

            with self._lock:
                self.state["active_clients"] += 1

            # 3. İsteği oku (Maksimum MAX_PAYLOAD_SIZE)
            buffer = bytearray()
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\n" in buffer or len(buffer) >= MAX_PAYLOAD_SIZE:
                    break

            if buffer:
                # İsteği yönlendir ve yanıt üret
                response = self._dispatch_request(bytes(buffer), uid, gid)
                resp_bytes = json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
                client_sock.sendall(resp_bytes)

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as err:
            logger.exception("İstemci işlenirken hata: %s", err)
        finally:
            with self._lock:
                self.state["active_clients"] = max(0, self.state["active_clients"] - 1)
            try:
                client_sock.close()
            except OSError:
                pass

    # -------------------------------------------------------------------------
    # Ana Sunucu Yaşam Döngüsü
    # -------------------------------------------------------------------------
    def start(self) -> None:
        """Daemon sunucusunu başlatır ve bağlantıları dinlemeye başlar."""
        logger.info("Linux FP Cleaner Root Daemon başlatılıyor (Sürüm: %s)...", DAEMON_VERSION)

        # 1. Başlangıçta kendini iyileştir
        self.startup_heal()

        # 2. Soketi hazırla
        self._server_sock = self._setup_socket()
        self._running = True

        logger.info(
            "Daemon soketi başarıyla açıldı: %s (İzin: 0%o, Grup: %s)",
            self.socket_path,
            SOCKET_PERM,
            self.socket_group,
        )

        # 3. Ana kabul döngüsü
        while self._running:
            try:
                readable, _, _ = select.select([self._server_sock], [], [], 1.0)
                if not readable:
                    continue

                client_sock, _ = self._server_sock.accept()
                thread = threading.Thread(
                    target=self._client_worker,
                    args=(client_sock,),
                    daemon=True,
                )
                thread.start()
            except select.error:
                break
            except Exception as err:
                if self._running:
                    logger.error("Soket kabul hatası: %s", err)

        self.stop()

    def stop(self) -> None:
        """Daemon'ı düzgün şekilde durdurur ve soketi temizler."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        if os.path.exists(self.socket_path):
            try:
                if not os.path.islink(self.socket_path):
                    os.unlink(self.socket_path)
            except OSError:
                pass

        logger.info("Daemon servisi güvenle durduruldu ve soket temizlendi.")


def run_daemon() -> None:
    """Daemon çalıştırma giriş noktası ve sinyal yöneticileri."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] [Daemon] %(message)s",
    )

    daemon = RootDaemon()

    def _signal_handler(signum: int, frame: Any) -> None:
        logger.info("Kapanma sinyali alındı (%d), kapatılıyor...", signum)
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        daemon.start()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    run_daemon()
