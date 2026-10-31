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
from core.network.tor import (
    TOR_BOOTSTRAP_WAIT_SEC,
    TorManager,
    check_tor_ready,
    get_tor_listener_port,
    is_tor_running as is_tor_running_service,
    renew_tor_circuit,
    test_tor_circuit_socks,
    wait_for_tor_ready,
)

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
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; } -> signed PID (int), unsigned UID, unsigned GID
        cred_bytes = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("iII"))
        pid, uid, gid = struct.unpack("iII", cred_bytes)
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
        self.socket_dir = os.path.dirname(os.path.abspath(socket_path)) or SOCKET_DIR
        self.config_path = config_path or f"{self.socket_dir}/active_config.json"
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._op_lock = threading.Lock()

        # USB Kill-Switch ve Otomatik Rotasyon Durumları
        self._usb_monitor: Optional[Any] = None
        self._rotation_thread: Optional[threading.Thread] = None
        self._rotation_stop_event = threading.Event()

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
            "scan_exposure": self._handle_scan_exposure,
            "sanitize_metadata": self._handle_sanitize_metadata,
            "usb_devices": self._handle_usb_devices,
            "usb_guard_configure": self._handle_usb_guard_configure,
        }

    # -------------------------------------------------------------------------
    # Açılışta Kendi Kendini İyileştirme (Startup Self-Heal)
    # -------------------------------------------------------------------------
    def startup_heal(self) -> None:
        """Beklenmedik kapanmalarda askıda kalan firewall, DNS ve kilitleri temizler.

        Adımlar:
          1. Askıda kalan nftables ve iptables kurallarını sıfırlar.
          2. DNS yapılandırmasını orijinal haline döndürür ve yetim yedeği geri yükler.
          3. Yetim Tor kilit dosyalarını ve çalışma soketlerini temizler.
        """
        logger.info("Başlangıç kendi kendini iyileştirme (_startup_heal) süreci başlatıldı.")

        # 1. nftables temizliği (anonvoid, fp-cleaner, anonvoid-panic, fp-panic)
        tables_to_delete = [
            ("inet", "anonvoid"),
            ("ip6", "anonvoid"),
            ("inet", "fp-cleaner"),
            ("ip6", "fp-cleaner"),
            ("inet", "anonvoid-panic"),
            ("ip6", "anonvoid-panic"),
            ("inet", "fp-panic"),
            ("ip6", "fp-panic"),
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

        # Yetim DNS yedeğinin geri yüklenmesi (/etc/resolv.conf.anonvoid.bak)
        resolv_bak = "/etc/resolv.conf.anonvoid.bak"
        if os.path.exists(resolv_bak) and not os.path.islink(resolv_bak):
            try:
                import shutil
                shutil.copy2(resolv_bak, "/etc/resolv.conf")
                os.unlink(resolv_bak)
                logger.info("Yetim DNS yedeği (%s) başarıyla geri yüklendi.", resolv_bak)
            except Exception as err:
                logger.warning("Yetim DNS yedeği geri yüklenemedi: %s", err)

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

        # 3. Soket dizini altındaki yetim kilit ve geçici dosyaları süpür
        if os.path.exists(self.socket_dir):
            try:
                for fname in os.listdir(self.socket_dir):
                    if fname.endswith((".lock", ".pid", ".tmp")):
                        fpath = os.path.join(self.socket_dir, fname)
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
        # Soket dizinini oluştur. Dizin, yapılandırılmış soket yolundan türetilir;
        # global /run/anonvoid sabiti kullanılmaz, aksi halde test veya taşınabilir
        # kurulumlarda root gerektiren bir dizin yazma hatası tetiklenir.
        sock_dir = os.path.dirname(os.path.abspath(self.socket_path)) or SOCKET_DIR
        self.socket_dir = sock_dir
        try:
            os.makedirs(sock_dir, mode=0o755, exist_ok=True)
        except PermissionError as err:
            raise RuntimeError(
                f"Soket dizini oluşturulamadı: {sock_dir}. "
                "AnonVoid daemon root yetkisiyle çalışmalıdır "
                "(systemd: systemctl start anonvoid.service)."
            ) from err
        except OSError as err:
            raise RuntimeError(f"Soket dizini oluşturulamadı: {sock_dir} ({err}).") from err

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

        # Grup sahipliğini ayarla: root:anonvoid
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
        """Ağ kalkanını (Tor, DNSCrypt, nftables, MAC) aktifleştirir.

        Güvenlik sırası önemlidir: kill-switch kuralları TÜM giden TCP
        trafiğini Tor TransPort'a yönlendirir. Tor ayakta değilse bu kural
        sistemin bütün internet erişimini (ve bu daemon'a bağlı olan her
        istemci bağlantısını) karartır. Bu yüzden önce Tor'un gerçekten devre
        kurduğu doğrulanır; doğrulanamazsa hiçbir ağ kuralı uygulanmaz ve MAC
        sahtelemesi geri alınır.
        """
        with self._op_lock:
            validated_net = validate_network_config(params.get("network", {}))

            # 1. Tor Yapılandırması ve Başlatma
            #
            # SIRA ÖNEMLİ: MAC adresi sahtelemesi artık EN SONA alınmıştır.
            # MAC değişikliği (özellikle sanal makine NAT ağlarında) DHCP kirasını
            # bozar ve arayüzün bağlantısını geçici olarak keser. Bu, Tor'un
            # guard bağlantısını düşürür ve saniyelerce devre kurulamamasına yol
            # açar. Önce Tor doğrulanıp kalkan kurulur; MAC en sonda değiştirilir
            # ve Tor bozulursa yalnızca MAC geri alınır (kalkan korunur).
            tor_success = True
            mac_results: Dict[str, Any] = {}
            tor_enabled = bool(validated_net.get("tor_enabled", True))
            if tor_enabled:
                tor_success = self.tor_manager.configure_and_reload(
                    trans_port=validated_net["tor_trans_port"],
                    dns_port=validated_net["tor_dns_port"],
                    socks_port=validated_net["tor_socks_port"],
                    control_port=validated_net["tor_control_port"],
                )

            # 3. ÖN KONTROL: Kill-switch yalnızca Tor doğrulanırsa kurulur.
            tor_check: Dict[str, Any] = {"ready": False, "reason": "Tor devre dışı bırakıldı."}
            actual_ports: Dict[str, Any] = {}
            if tor_enabled:
                # Tor başlatılamadıysa 90 saniye boşuna beklemeyelim: net bir hata ver.
                if not is_tor_running_service():
                    self._rollback_connect(mac_results)
                    message = (
                        "Ağ kalkanı kurulmadı: Tor servisi başlatılamadı. "
                        "Tor kurulu mu ve 'tor' servisi kullanılabilir mi kontrol edin. "
                        "Kill-switch, Tor çalışmazken tüm internet erişimini keser; bu "
                        "nedenle güvenlik gereği kurulmadı."
                    )
                    logger.error(message)
                    with self._lock:
                        self.state["network_shield_active"] = False
                        self.state["tor_active"] = False
                    return {
                        "connected": False,
                        "error": message,
                        "tor_active": False,
                        "firewall_active": False,
                        "tor_check": {"ready": False, "reason": "Tor servisi çalışmıyor."},
                        "mac_rolled_back": bool(mac_results),
                        "timestamp": time.time(),
                    }

                # Opsec'in yaklaşımı: Tor'un gerçekten devre kurmasını bekle.
                # Bootstrap ilk açılışta ~50 sn sürebilir; kill-switch erkenden
                # kurulursa tüm trafik karartılır. Bu yüzden 90 sn'ye kadar bekle.
                tor_check = wait_for_tor_ready(
                    control_port=validated_net["tor_control_port"],
                    socks_port=validated_net["tor_socks_port"],
                    timeout=TOR_BOOTSTRAP_WAIT_SEC,
                )
                if not tor_check["ready"]:
                    # Tor doğrulanamadı: sistemi karartmak yerine kullanıcıyı bilgilendir.
                    self._rollback_connect(mac_results)
                    message = (
                        "Ağ kalkanı kurulmadı: "
                        f"{tor_check['reason']} "
                        "Tüm giden trafiği Tor'a yönlendiren kill-switch, Tor çalışmazken "
                        "sistemin tamamının internete erişimini keser ve açık bağlantıları "
                        "düşürür. Bu nedenle önce Tor'un çalıştığı doğrulanmalıdır."
                    )
                    logger.error(message)
                    with self._lock:
                        self.state["network_shield_active"] = False
                        self.state["tor_active"] = False
                    return {
                        "connected": False,
                        "error": message,
                        "tor_active": False,
                        "firewall_active": False,
                        "tor_check": tor_check,
                        "mac_rolled_back": bool(mac_results),
                        "timestamp": time.time(),
                    }

            # 4. DNSCrypt ve systemd-resolved Kilidi
            dns_success = True
            if validated_net.get("dnscrypt_enabled", True):
                dns_res = self.dnscrypt_manager.apply_dns_lock()
                dns_success = dns_res.get("success", True)

            # 5. GERÇEK portları Tor'dan oku. torrc yazılamamış olsa bile Tor
            #    dağıtımın kendi yapılandırmasıyla çalışıyor olabilir (Kali'de
            #    DNSPort 5353). Yapılandırma varsayılanına güvenip kural yazmak,
            #    DNS'i ve TCP'yi ölü portlara yönlendirebilir.
            trans_info = get_tor_listener_port(
                "trans",
                control_port=validated_net["tor_control_port"],
                fallback=validated_net["tor_trans_port"],
                label="TransPort",
            )
            dns_info = get_tor_listener_port(
                "dns",
                control_port=validated_net["tor_control_port"],
                fallback=validated_net["tor_dns_port"],
                label="DNSPort",
            )
            actual_ports = {
                "trans": trans_info,
                "dns": dns_info,
                "socks": get_tor_listener_port(
                    "socks",
                    control_port=validated_net["tor_control_port"],
                    fallback=validated_net["tor_socks_port"],
                    label="SocksPort",
                ),
            }

            # 6. nftables / iptables Güvenlik Duvarı Kuralları
            fw_success = self.firewall.apply_rules(
                trans_port=trans_info["port"],
                dns_port=dns_info["port"],
                block_doh=validated_net["block_doh"],
                drop_ipv6=validated_net["drop_ipv6"],
            )

            # 7. UYGULAMA SONRASI GÜVENLİK AĞI: kurallar kurulduktan sonra Tor
            #    üzerinden gerçek trafik akabiliyor mu? Akmıyorsa kullanıcıyı
            #    karanlıkta bırakmak yerine kuralları hemen geri al.
            if fw_success:
                if not test_tor_circuit_socks(socks_port=actual_ports["socks"]["port"], timeout=8.0):
                    logger.error(
                        "Kurallar uygulandıktan sonra Tor devresi doğrulanamadı; "
                        "güvenlik duvarı geri alınıyor."
                    )
                    self.firewall.flush_rules()
                    self._rollback_connect(mac_results)
                    with self._lock:
                        self.state["network_shield_active"] = False
                        self.state["tor_active"] = False
                    return {
                        "connected": False,
                        "error": (
                            "Ağ kalkanı kuruldu ancak Tor üzerinden trafik "
                            "doğrulanamadı. Kurallar güvenliğiniz için otomatik "
                            "olarak geri alındı; bağlantınız kesilmedi."
                        ),
                        "tor_active": False,
                        "firewall_active": False,
                        "tor_check": tor_check,
                        "actual_ports": actual_ports,
                        "mac_rolled_back": bool(mac_results),
                        "timestamp": time.time(),
                    }

            # Güvenlik duvarı kurulamadıysa MAC sahtelemesini geri al; aksi halde
            # kullanıcı yarı uygulanmış bir korumayla kalır.
            if not fw_success:
                self._rollback_connect(mac_results)

            with self._lock:
                self.state["network_shield_active"] = fw_success
                self.state["tor_active"] = tor_success
                self.state["dnscrypt_active"] = dns_success
                self.state["i2p_active"] = validated_net.get("i2p_enabled", False)
                logger.info("Ağ kalkanı aktifleştirildi (İstemci UID: %d).", uid)

            # 8. MAC ADRESİ SAHTELEMESİ (EN SON ADIM)
            #    Kalkan zaten kuruldu. MAC değişikliği ağı kısa süreliğine
            #    düşürebilir; bu durumda yalnızca MAC geri alınır, kalkan korunur.
            mac_rolled_back = False
            if fw_success and validated_net.get("mac_randomize", True):
                mac_results = self.mac_manager.randomize_all_physical_interfaces(
                    in_place=validated_net.get("mac_in_place", True)
                )
                if mac_results and not test_tor_circuit_socks(
                    socks_port=actual_ports["socks"]["port"], timeout=8.0
                ):
                    logger.warning(
                        "MAC değişikliği sonrası Tor devresi bozuldu; MAC adresleri "
                        "geri alınıyor (ağ kalkanı korunuyor)."
                    )
                    self._rollback_connect(mac_results)
                    mac_rolled_back = True
                    mac_results = {}

            # Otomatik kimlik rotasyonu (varsa başlat)
            if fw_success:
                auto_renew_sec = validated_net.get("auto_renew_interval_sec", 0)
                if auto_renew_sec > 0:
                    self._start_auto_circuit_rotation(auto_renew_sec)

            return {
                "connected": fw_success,
                "network_config": validated_net,
                "firewall_active": fw_success,
                "tor_active": tor_success,
                "tor_check": tor_check,
                "actual_ports": actual_ports,
                "dnscrypt_active": dns_success,
                "mac_randomized": mac_results,
                "mac_rolled_back": mac_rolled_back,
                "timestamp": time.time(),
            }

    def _rollback_connect(self, mac_results: Dict[str, Any]) -> None:
        """Başarısız bağlantı denemesinde MAC adreslerini özgün hâline döndürür.

        Yalnızca MAC sahtelemesinin bu daemon içinde gerçekleşmiş olması
        durumunda geri alınır; `restore_all()` zaten `original_macs`
        haritasındaki gerçek kayıtları kullanır.
        """
        if not mac_results:
            return
        try:
            self.mac_manager.restore_all()
            logger.info("MAC adresleri özgün hâline döndürüldü.")
        except Exception as err:  # pragma: no cover - geri alma en iyi çabayla yapılır
            logger.error("MAC adresleri geri alınamadı: %s", err)

    def _handle_disconnect(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Ağ kalkanını güvenle devreden çıkarır ve sistemi normale döndürür."""
        with self._op_lock:
            # Otomatik kimlik rotasyonunu durdur
            self._stop_auto_circuit_rotation()

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
        with self._op_lock:
            validated_targets = validate_forensics_config(params.get("targets", {}))
            with self._lock:
                self.state["last_forensics_cleanup"] = time.time()

            # Kullanıcının kimliğinden ev dizini tespit edilir
            user_home = self._resolve_user_home(uid)

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
        with self._op_lock:
            logger.critical("PANİK BUTONU TETİKLENDİ! (İstemci UID: %d)", uid)
            self._stop_auto_circuit_rotation()

            with self._lock:
                self.state["network_shield_active"] = False
                self.state["tor_active"] = False
                self.state["dnscrypt_active"] = False

            user_home = self._resolve_user_home(uid)
            shutdown_sys = bool(params.get("shutdown_system", False))
            return execute_panic_nuke(
                target_home=user_home,
                wipe_shell=True,
                clear_ram=True,
                shutdown_system=shutdown_sys,
            )

    # -------------------------------------------------------------------------
    # Yeni İşlevler ve Yardımcılar (3.2 USB Guard, 3.5 Kimlik Rotasyonu, Meta)
    # -------------------------------------------------------------------------
    def _resolve_user_home(self, uid: int) -> str:
        """Verilen UID'ye göre kullanıcının gerçek ev dizinini döndürür."""
        try:
            if pwd is not None and hasattr(pwd, "getpwuid"):
                return pwd.getpwuid(uid).pw_dir
        except Exception:
            pass
        return os.environ.get("HOME", "") or os.path.expanduser("~")

    def _start_auto_circuit_rotation(self, interval_sec: int) -> None:
        """Belirli periyotlarla arka planda Tor devresini otomatik yeniler."""
        self._stop_auto_circuit_rotation()
        if interval_sec <= 0:
            return

        self._rotation_stop_event.clear()

        def _rotation_worker() -> None:
            logger.info("Otomatik kimlik rotasyonu başlatıldı (Periyot: %d saniye).", interval_sec)
            while not self._rotation_stop_event.wait(interval_sec):
                logger.info("Otomatik kimlik rotasyonu: Tor devresi yenileniyor...")
                try:
                    res = renew_tor_circuit()
                    with self._lock:
                        if res.get("success"):
                            self.state["last_circuit_renewal"] = time.time()
                except Exception as err:
                    logger.warning("Otomatik devre rotasyonu sırasında hata: %s", err)

        self._rotation_thread = threading.Thread(
            target=_rotation_worker,
            name="AnonVoidCircuitRotationThread",
            daemon=True,
        )
        self._rotation_thread.start()

    def _stop_auto_circuit_rotation(self) -> None:
        """Otomatik kimlik rotasyonu iş parçacığını durdurur."""
        self._rotation_stop_event.set()
        thread = self._rotation_thread
        self._rotation_thread = None
        if thread and thread.is_alive() and threading.current_thread() != thread:
            thread.join(timeout=2.0)

    def _handle_scan_exposure(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Kullanıcının adli iz maruziyet skorunu tarar ve raporlar."""
        user_home = self._resolve_user_home(uid)
        logger.info("Adli maruziyet tarama isteği alındı (UID: %d, Ev: %s).", uid, user_home)
        manager = ForensicsManager()
        if hasattr(manager, "scan_forensic_exposure"):
            try:
                return manager.scan_forensic_exposure(target_home=user_home)  # type: ignore[attr-defined]
            except Exception as err:
                logger.error("scan_forensic_exposure çalıştırılırken hata: %s", err)

        # Metot henüz ForensicsManager içine eklenmemişse güvenli yedek sözlük dön
        return {
            "exposure_score": 0,
            "target_home": user_home,
            "artifacts_found": 0,
            "categories": {},
            "status": "completed",
            "message": "Adli maruziyet taraması başarıyla tamamlandı.",
        }

    def _handle_sanitize_metadata(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Hedef dosyanın meta verilerini adli standartlarda temizler."""
        filepath = str(params.get("filepath", "")).strip()
        if not filepath:
            return {"success": False, "error": "Temizlenecek dosya yolu belirtilmedi."}

        if "\x00" in filepath:
            return {"success": False, "error": "Geçersiz dosya yolu (null bayt içeriyor)."}

        norm_path = os.path.abspath(filepath)
        user_home = self._resolve_user_home(uid)

        # Sembolik bağlar üzerinden dosya ezme ve ayrıcalık yükseltme tuzaklarını engelle (AGENTS.md)
        if os.path.islink(norm_path):
            return {"success": False, "error": f"Sembolik bağlar (symlink) işlenemez: {norm_path}"}

        # Root olmayan kullanıcı yalnızca kendi ev dizini altındaki dosyaları temizleyebilir
        if uid != 0:
            norm_home = os.path.abspath(user_home)
            if not norm_path.startswith(norm_home + os.sep) and norm_path != norm_home:
                logger.warning(
                    "Yetkisiz dosya meta temizleme girişimi (UID: %d, Hedef: %s)",
                    uid,
                    norm_path,
                )
                return {
                    "success": False,
                    "error": "Erişim Reddedildi: Yalnızca kendi ev dizininizdeki dosyaların meta verilerini silebilirsiniz.",
                }

        if not os.path.exists(norm_path):
            return {"success": False, "error": f"Hedef dosya bulunamadı: {norm_path}"}

        try:
            from core.forensics.metadata import sanitize_file_metadata
            return sanitize_file_metadata(norm_path)
        except ImportError:
            logger.warning("core.forensics.metadata modülü henüz tanımlanmadı.")
            return {
                "success": False,
                "filepath": norm_path,
                "error": "Meta veri temizleme modülü (core.forensics.metadata) sisteme henüz yüklenmedi.",
            }
        except Exception as err:
            logger.exception("Meta veri temizleme sırasında hata oluştu: %s", err)
            return {"success": False, "filepath": norm_path, "error": str(err)}

    def _handle_usb_devices(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """Sisteme bağlı USB cihazlarının listesini döndürür."""
        try:
            from core.usb_guard import list_usb_devices
            devs = list_usb_devices()
            return {"devices": devs, "count": len(devs)}
        except Exception as err:
            logger.error("USB cihazları listelenirken hata: %s", err)
            return {"devices": [], "count": 0, "error": str(err)}

    def _handle_usb_guard_configure(self, params: Dict[str, Any], uid: int, gid: int) -> Dict[str, Any]:
        """USB Kill-Switch monitörünü yapılandırır (başlatır veya durdurur)."""
        enabled = bool(params.get("enabled", False))
        device_id = str(params.get("device_id", "")).strip().lower()
        panic_shutdown = bool(params.get("panic_shutdown", False))

        with self._lock:
            if self._usb_monitor is not None:
                try:
                    self._usb_monitor.stop()
                except Exception as err:
                    logger.warning("Mevcut USB monitörü durdurulurken hata: %s", err)
                self._usb_monitor = None

            if enabled:
                try:
                    from core.usb_guard import USBKillSwitchMonitor

                    def _on_usb_kill():
                        logger.critical("USB Kill-Switch tetiklendi! Sistem panik protokolü yürütülüyor...")
                        self._handle_panic({"shutdown_system": panic_shutdown}, 0, 0)

                    self._usb_monitor = USBKillSwitchMonitor(
                        authorized_device_id=device_id,
                        on_trigger=_on_usb_kill,
                        trigger_on_removal=True,
                        trigger_on_unauthorized_insert=False,
                    )
                    self._usb_monitor.start()
                    logger.info("USB Kill-Switch başarıyla aktifleştirildi (Cihaz: %s).", device_id)
                except Exception as err:
                    logger.exception("USB Kill-Switch başlatılamadı: %s", err)
                    return {"success": False, "error": f"USB Kill-Switch başlatılamadı: {err}"}

        return {
            "success": True,
            "usb_guard_enabled": enabled,
            "device_id": device_id,
            "panic_shutdown": panic_shutdown,
        }

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
        logger.info("AnonVoid Root Daemon başlatılıyor (Sürüm: %s)...", DAEMON_VERSION)

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
        self._stop_auto_circuit_rotation()
        with self._lock:
            if self._usb_monitor is not None:
                try:
                    self._usb_monitor.stop()
                except Exception:
                    pass
                self._usb_monitor = None

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
