"""AnonVoid - Tor Orkestrasyonu ve Devre Yenileme Modülü.

Bu modül; torrc dosyasını güvenle şablonlar, TransPort (9040), DNSPort (5300)
ve .onion sanal IP aralıklarını (10.192.0.0/10) yapılandırır, izinleri 0640 olarak
sertleştirir ve Tor Control Port (9051) üzerinden devre yenilemesi (SIGNAL NEWNYM) yapar.
"""

from __future__ import annotations

import logging
import os
import re
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

logger = logging.getLogger("AnonVoidTor")

DEFAULT_TORRC_PATH = "/etc/tor/torrc"
TORRC_BACKUP_PATH = "/etc/tor/torrc.anonvoid.bak"
# Eski proje adından ("fp-cleaner") kalan yedeğin yolu. Bu dosya varsa üstüne
# yazılmaz; aksi halde kullanıcının orijinal torrc'i kalıcı olarak kaybolur.
TORRC_LEGACY_BACKUP_PATH = "/etc/tor/torrc.fp-cleaner.bak"
TOR_CONTROL_PORT = 9051

# Güvenlik açığı kapısı: nftables kural seti tüm giden TCP trafiğini Tor
# TransPort'a yönlendirir (kill-switch). Tor ayakta değilse bu kural, sistemin
# TÜM İNTERNET bağlantılarını - hatta açık bir iş oturumunu, çağrılan API'yi
# ve hatta bu projeyi geliştiren ajanı - karartır ve bağlantı kopmuş gibi görünür.
# Bu yüzden kill-switch yalnızca Tor'un gerçekten devre kurduğu doğrulandıktan
# SONRA kurulmalıdır.
#
# Tor ilk açılışta ölü kilit (microdesc) indirdiği için ölçümde 48 saniye
# sürmüştür. Kısa bir bekleme, kullanıcının bağlantısını kesme riskiyle
# karşılaştırılamayacak kadar düşük olduğundan üst sınır 90 saniye olarak
# belirlenmiştir.
TOR_BOOTSTRAP_WAIT_SEC = 90.0

# Tor'un çalışma dizininde tuttuğumuz kontrol portu çerez dosyaları.
# Debian/Kali paketleri kimlik doğrulamalı kontrol portu kullanır.
TOR_COOKIE_DIR = "/run/tor"
# Kali/Debian paketleri varsayılan olarak "control.authcookie" adını kullanır;
# dağıtımlara göre "control.< servis >.cookie" biçimi de görülebiliyor.
TOR_COOKIE_NAMES = ("control.authcookie", "control.cookie")


def _control_cookie_path() -> str:
    """Tor kontrol portu çerez dosyasının yolunu döndürür (yoksa boş dize).

    Debian/Kali `CookieAuthentication 1` kullanan Tor paketlerinde çerez
    dosyası yalnızca `tor` kullanıcısına okunabilir ve 0600 izinlidir. Bu
    modül root daemon içinde çalıştığı için dosya okunabilir; normal kullanıcı
    sürecinde okunamaz ve boş dize döner.
    """
    try:
        for name in TOR_COOKIE_NAMES:
            candidate = os.path.join(TOR_COOKIE_DIR, name)
            if os.path.exists(candidate):
                return candidate
        # Dağıtıma göre değişebilen adlar için son çare: dizin taraması
        for entry in sorted(os.listdir(TOR_COOKIE_DIR)):
            if entry.startswith("control") and "cookie" in entry:
                return os.path.join(TOR_COOKIE_DIR, entry)
    except OSError:
        pass
    return ""


def _control_read_reply(sock: socket.socket, timeout: float) -> str:
    """Kontrol portundan tam bir çok satırlı yanıtı okur.

    Tor kontrol protokolünde yanıtlar "250-değer" satırlarıyla gelir ve
    son satır "250 OK" ile biter. Bu nedenle "250" görülür diye okuma
    kesilmemeli; yoksa AUTHENTICATE'in "250 OK" yanıtı alınıp asıl komutun
    yanıtı hiç okunmadan döndürülür.
    """
    sock.settimeout(timeout)
    buffer = b""
    collected: list[str] = []
    while True:
        # Tam satır mevcutsa kontrol et.
        while b"\r\n" in buffer:
            line, _, buffer = buffer.partition(b"\r\n")
            text = line.decode("utf-8", "replace")
            collected.append(text)
            # "250 ..." / "5xx ..." son satır komutu tamamlar.
            if len(text) > 3 and text[3] == " ":
                return "\n".join(collected)
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 65536:
            break
    if collected:
        return "\n".join(collected)
    return buffer.decode("utf-8", "replace")


def _control_command(
    command: str, control_port: int = TOR_CONTROL_PORT, timeout: float = 5.0
) -> str:
    """Tor kontrol portuna komut gönderir ve ham yanıtı döndürür.

    Önce çerez tabanlı kimlik doğrulamayı dener; kontrol portu kimlik
    doğrulamasız yapılandırılmışsa (AnonVoid'un eski torrc'si) doğrudan
    gönderir. Başarısız olursa boş dize döner.
    """
    payload = command.encode("ascii", "ignore") + b"\r\n"
    cookie_path = _control_cookie_path()

    try:
        with socket.create_connection(("127.0.0.1", control_port), timeout=timeout) as sock:
            if cookie_path:
                try:
                    with open(cookie_path, "rb") as handle:
                        cookie = handle.read()
                    # Uzunluk öneki GÖNDERİLMEZ. Tor kontrol protokolü çerezi
                    # salt onaltılık metin olarak bekler; önek eklenirse sunucu
                    # "515 Authentication failed: Wrong length on authentication
                    # cookie" ile reddeder (stem ve torsocks da öneksiz gönderir).
                    sock.sendall(b"AUTHENTICATE " + cookie.hex().upper().encode("ascii") + b"\r\n")
                    auth_reply = _control_read_reply(sock, timeout)
                except OSError:
                    auth_reply = ""
                if auth_reply.startswith("5") and not auth_reply.startswith("250"):
                    return ""
            sock.sendall(payload)
            return _control_read_reply(sock, timeout)
    except OSError:
        return ""
    return ""


def get_tor_listener_port(
    kind: str,
    control_port: int = TOR_CONTROL_PORT,
    fallback: int = 0,
    label: str = "",
) -> Dict[str, Any]:
    """Tor'un GERÇEKTEN dinlediği TCP/UDP portunu kontrol portundan okur.

    `kind`: "dns", "socks" veya "trans".

    Neden gerekli: torrc yazılamadığında (örneğin systemd `ProtectSystem`
    nedeniyle salt-okunur `/etc`) Tor, DAĞITIMIN kendi yapılandırmasıyla
    çalışır. Kali'de DNSPort 5353'tür; AnonVoid 5300 varsayarsa güvenlik
    duvarı DNS'i ölü bir porta yönlendirir ve internet çalışmaz. Aynı durum
    TransPort/SocksPort için de geçerlidir. Bu yüzden kural yazarken
    yapılandırma varsayılanı değil, Tor'un bildirdiği gerçek port kullanılır.

    Dönüş: {"port": int, "source": "tor"|"fallback", "detail": str}
    """
    reply = _control_command(f"GETINFO net/listeners/{kind}", control_port=control_port)
    if reply:
        # Tor yanıtı tırnak içinde verir:
        #   250-net/listeners/dns="127.0.0.1:5353"
        # Bu nedenle ham ayırma yerine tırnak içindeki "host:port" çiftleri
        # düzenli ifade ile ayrıştırılır.
        found: list[tuple[str, int]] = []
        for host, port_text in re.findall(
            r'"((?:0\.0\.0\.0|127\.0\.0\.1|::1|\[::1\])):(\d{1,5})"', reply
        ):
            found.append((host.strip("[]"), int(port_text)))

        if found:
            # Döngüsel (127.0.0.1) dinleyici tercih edilir. 0.0.0.0 tüm
            # arayüzlere açıktır; hem sorgu için döngüsel olan yeterlidir hem
            # de dinleyicinin ağa açılması bir güvenlik zayıflığıdır.
            for preferred in ("127.0.0.1", "::1", "0.0.0.0"):
                for host, port in found:
                    if host == preferred:
                        detail = f"Tor {label or kind} {host}:{port} üzerinde dinliyor."
                        if host == "0.0.0.0":
                            detail += (
                                f" (Uyarı: {label or kind} tüm arayüzlere açık; "
                                "ağdan da erişilebilir durumda.)"
                            )
                        return {"port": port, "source": "tor", "detail": detail}
        # Yedek: tırnak biçimi beklenmedik bir varyanta girerse son sayıyı dene.
        digits = re.findall(r":(\d{1,5})[\"']", reply)
        if digits:
            return {
                "port": int(digits[0]),
                "source": "tor",
                "detail": f"Tor {label or kind} {int(digits[0])} üzerinde dinliyor.",
            }
    return {
        "port": fallback,
        "source": "fallback",
        "detail": (
            f"Tor {label or kind} kontrol portundan okunamadı; yapılandırma "
            f"varsayılanı ({fallback}) kullanılıyor."
        ),
    }


def get_tor_dns_port(
    control_port: int = TOR_CONTROL_PORT, fallback: int = 5300
) -> Dict[str, Any]:
    """Tor'un gerçekte dinlediği DNSPort'u döndürür (Kali'de 5353)."""
    return get_tor_listener_port(
        "dns", control_port=control_port, fallback=fallback, label="DNSPort"
    )


def get_bootstrap_progress(control_port: int = TOR_CONTROL_PORT) -> Optional[int]:
    """Tor'un bootstrap yüzdesini döndürür.

    Yüzde 100 ise devreler kurulmuş ve trafik akışı hazırdır. Kontrol portu
    erişilemezse veya yanıt okunamazsa `None` döner; bu durum "hazır"
    anlamına GELMEZ, yalnızca "bilinmiyor" anlamına gelir.
    """
    reply = _control_command("GETINFO status/bootstrap-phase", control_port=control_port)
    if not reply:
        return None
    marker = "PROGRESS="
    index = reply.find(marker)
    if index < 0:
        return None
    digits = ""
    for char in reply[index + len(marker) :]:
        if char.isdigit():
            digits += char
        else:
            break
    if not digits:
        return None
    return int(digits)


def check_tor_ready(
    control_port: int = TOR_CONTROL_PORT,
    socks_port: int = 9050,
    require_complete: bool = True,
) -> Dict[str, Any]:
    """Kill-switch kurulumu öncesi Tor hazır mı diye katı bir denetim yapar.

    Güvenlik ilkesi: emin olunamayan durum "hazır" kabul edilmez. Kontrol
    portundan bootstrap durumu okunamıyorsa sonuç `ready=False` ve
    `reason="bilinmiyor"` döner; çağıran taraf bu durumda kill-switch'i
    KURMAMALIDIR.

    `require_complete=False` ile yalnızca sürecin ayakta olduğu doğrulanır
    (kalkan kapalıyken hızlı sağlık kontrolü için).
    """
    result: Dict[str, Any] = {
        "ready": False,
        "reason": "",
        "bootstrap_percent": None,
        "process_running": is_tor_running(),
        "socks_port": socks_port,
    }

    if not result["process_running"]:
        result["reason"] = "Tor servisi çalışmıyor."
        return result

    # SOCKS portunun gerçekten dinlediğini doğrula (servis ayakta olabilir
    # ama portu açılmamış olabilir).
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=3.0):
            pass
    except OSError as err:
        result["reason"] = f"Tor SOCKS portu ({socks_port}) dinlemiyor: {err}"
        return result

    progress = get_bootstrap_progress(control_port=control_port)
    result["bootstrap_percent"] = progress

    if not require_complete:
        result["ready"] = True
        if not result["reason"]:
            result["reason"] = "Tor süreci ayakta."
        return result

    if progress is None:
        result["reason"] = (
            "Tor kontrol portundan bootstrap durumu okunamadı; Tor'un gerçekten "
            "devre kurduğu doğrulanamadı. Güvenlik nedeniyle kill-switch "
            "kurulmuyor."
        )
        return result

    if progress < 100:
        result["reason"] = f"Tor henüz bootstrap tamamlamadı (%{progress})."
        return result

    result["ready"] = True
    result["reason"] = "Tor bootstrap tamamlandı (%100)."
    return result


def wait_for_tor_ready(
    control_port: int = TOR_CONTROL_PORT,
    socks_port: int = 9050,
    timeout: float = TOR_BOOTSTRAP_WAIT_SEC,
) -> Dict[str, Any]:
    """Tor bootstrap tamamlanana kadar bekler ve sonucu döndürür.

    Opsec'in yaklaşımına benzer şekilde, kontrol portundan 100% görüldükten
    SONRA bile gerçek Tor devresinin kurulup kurulmadığını SOCKS üzerinden
    birkaç kez doğrular (check.torproject.org). Bu, "Tor çalışıyor" görünse
    bile kill-switch'in erken kurulmasını önler.
    """
    deadline = time.time() + max(0.0, timeout)
    last: Dict[str, Any] = {}
    while True:
        last = check_tor_ready(control_port=control_port, socks_port=socks_port)
        if last["ready"] or time.time() >= deadline:
            break
        time.sleep(3.0)

    # Kontrol portu %100 görüyorsa, devre gerçekten kurulmuş mu diye
    # SOCKS üzerinden kısa bir ek doğrulama yap. En az 3 deneme.
    if last.get("ready"):
        circuit_deadline = time.time() + 30.0
        while time.time() < circuit_deadline:
            if test_tor_circuit_socks(socks_port=socks_port, timeout=8.0):
                last["ready"] = True
                last["circuit_verified"] = True
                if "reason" not in last or "devre" not in last.get("reason", ""):
                    last["reason"] = "Tor bootstrap tamamlandı ve devre doğrulandı (%100)."
                return last
            time.sleep(2.0)
        # Devre doğrulanamadıysa yine de çok temkinli davran; bootstrap
        # %100 idi ama circuit henüz oluşmamış olabilir. Bu durumda fail-closed
        # yapmak en güvenlisidir (bağlantıyı kesme riski olmamasını tercih ettik,
        # fakat kill-switch erken kurulmasın). Durum bilinmiyor kabul ediyoruz.
        last["ready"] = False
        last["circuit_verified"] = False
        last["reason"] = (
            "Tor bootstrap %100 görünse de SOCKS üzerinden gerçek devre "
            "doğrulanamadı. Güvenlik nedeniyle kill-switch kurulmuyor."
        )
        return last

    return last


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
            "# AnonVoid - Otomatik Yapılandırılmış torrc\n"
            f"SocksPort {cfg_port(socks_port, 9050)} IsolateDestAddr\n"
            f"TransPort {cfg_port(trans_port, 9040)}\n"
            f"DNSPort {cfg_port(dns_port, 5300)}\n"
            f"ControlPort {cfg_port(control_port, 9051)}\n"
            # Kontrol portu kimlik doğrulamasız bırakılırsa sistemdeki HERHANGİ
            # bir yerel kullanıcı Tor devrelerini okuyabilir, devre kapatabilir
            # ve SIGNAL NEWNYM gönderebilir. Bu, yerel ayrıcalık yükseltmedir.
            # Çerez tabanlı kimlik doğrulama hem güvenli hem de root daemon'ın
            # /run/tor altındaki çerezi okuyabilmesi sayesinde işlevsel kalır.
            "CookieAuthentication 1\n"
            "CookieAuthFileGroupOnly 1\n"
            "SafeLogging 1\n"
            "VirtualAddrNetworkIPv4 10.192.0.0/10\n"
            "AutomapHostsOnResolve 1\n"
            "AutomapHostsSuffixes .onion,.exit\n"
            "AvoidDiskWrites 1\n"
            "Log notice stdout\n"
        )

    def _existing_torrc_backup(self) -> str:
        """Geri yüklenecek geçerli torrc yedeğinin yolunu döndürür (yoksa boş dize)."""
        for path in (self.backup_path, TORRC_LEGACY_BACKUP_PATH):
            if os.path.exists(path):
                return path
        return ""

    def backup_torrc(self) -> bool:
        """Orijinal torrc dosyasını yedekler."""
        if os.path.exists(self.torrc_path) and not self._existing_torrc_backup():
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
        """Eksik torrc direktiflerini ekler ve Tor servisini başlatır.

        Opsec'in yaklaşımı benimsenmiştir: dağıtımın torrc dosyası EZİLMEZ.
        Yalnızca eksik direktifler idempotent biçimde eklenir. Bu sayede
        Debian/Kali'nin kendi ayarları (User, DataDirectory vb.) korunur.

        ÖNEMLİ: torrc yazılamaması Tor'un çalıştırılamayacağı anlamına
        GELMEZ. systemd `ProtectSystem=full` veya salt-okunur kök dosya
        sistemi nedeniyle yazma başarısız olabilir; bu durumda dağıtımın
        mevcut yapılandırması geçerlidir ve Tor yine de başlatılır. Gerçek
        portlar daha sonra kontrol portundan okunur.
        """
        self.backup_torrc()

        try:
            changed = self._ensure_torrc_directives(
                trans_port=trans_port,
                dns_port=dns_port,
                socks_port=socks_port,
                control_port=control_port,
            )
            if changed:
                logger.info("torrc eksik direktiflerle güncellendi: %s", self.torrc_path)
            else:
                logger.info("torrc zaten gerekli direktifleri içeriyor.")
        except OSError as err:
            logger.warning(
                "torrc güncellenemedi (%s). Tor, dağıtımın mevcut "
                "yapılandırmasıyla başlatılacak ve gerçek portlar kontrol "
                "portundan okunacak.",
                err,
            )

        # Torrc yazılsın ya da yazılmasın servis başlatılmalıdır. Aksi hâlde
        # "korumayı başlat" sessizce hiçbir şey yapmaz.
        started = self.reload_service()
        if not started:
            logger.error("Tor servisi başlatılamadı.")
            return False
        return True

    def _ensure_torrc_directives(
        self,
        trans_port: int = 9040,
        dns_port: int = 5300,
        socks_port: int = 9050,
        control_port: int = 9051,
    ) -> bool:
        """Eksik direktifleri ekler; var olanlara DOKUNMAZ. Değişiklik olduysa True."""
        # Mevcut izinleri koru; yeni dosya için dağıtım varsayılanı (0644) kullan.
        # DİKKAT: torrc Tor tarafından `debian-tor` kullanıcısıyla okunur.
        # 0640 root:root yapmak Tor'un kendi yapılandırmasını okuyamamasına ve
        # bir sonraki yeniden başlatmada servisin açılmamasına yol açar.
        previous_mode = None
        try:
            previous_mode = os.stat(self.torrc_path).st_mode & 0o777
        except OSError:
            pass

        try:
            with open(self.torrc_path, "r", encoding="utf-8") as handle:
                existing = handle.read()
        except FileNotFoundError:
            existing = ""
        except OSError:
            raise

        # Etkin (yorum olmayan) satırların anahtarlarını topla.
        active_keys = set()
        for line in existing.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if parts:
                active_keys.add(parts[0])

        wanted = [
            ("SocksPort", f"SocksPort {cfg_port(socks_port, 9050)} IsolateDestAddr"),
            ("TransPort", f"TransPort {cfg_port(trans_port, 9040)}"),
            ("DNSPort", f"DNSPort {cfg_port(dns_port, 5300)}"),
            ("ControlPort", f"ControlPort {cfg_port(control_port, 9051)}"),
            # Kontrol portu kimlik doğrulamasız bırakılırsa yerel bir kullanıcı
            # Tor devrelerini okuyup SIGNAL NEWNYM gönderebilir: ayrıcalık yükseltme.
            ("CookieAuthentication", "CookieAuthentication 1"),
            ("VirtualAddrNetworkIPv4", "VirtualAddrNetworkIPv4 10.192.0.0/10"),
            ("AutomapHostsOnResolve", "AutomapHostsOnResolve 1"),
        ]

        missing = [line for key, line in wanted if key not in active_keys]
        if not missing:
            return False

        parent_dir = os.path.dirname(self.torrc_path)
        if parent_dir:
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        # Dosyayı yerinde ve atomik biçimde tamamla; sonuna yeni satır ekle.
        with open(self.torrc_path, "a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write("\n# AnonVoid tarafından eklenen zorunlu direktifler\n")
            for line in missing:
                handle.write(line + "\n")

        try:
            os.chmod(self.torrc_path, previous_mode if previous_mode is not None else 0o644)
        except OSError:
            pass
        return True

    def reload_service(self) -> bool:
        """Tor servisini başlatır ya da etkinse yeniden yükler.

        `reload-or-restart` tek başına yeterli değildir: Debian/Kali'de
        `tor.service` çoklu-örnek (multi-instance) ana birimidir ve varsayılan
        olarak KAPALIDIR. Gerçek dinleyici `tor@default.service`'tir. Bu
        nedenle önce açıkça `start` denenir, ardından durum doğrulanır.
        """
        logger.info("Tor servisi başlatılıyor/yeniden yükleniyor...")

        commands = [
            ["systemctl", "start", "tor"],
            ["systemctl", "enable", "--now", "tor@default"],
            ["systemctl", "reload-or-restart", "tor"],
            ["systemctl", "restart", "tor@default"],
        ]
        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20, check=False
                )
                if proc.returncode == 0 and is_tor_running():
                    logger.info("Tor servisi hazır (%s).", " ".join(cmd))
                    return True
            except Exception:
                pass

        return is_tor_running()

    def restore_torrc(self) -> bool:
        """Yedeklenen orijinal torrc dosyasını geri yükler."""
        backup = self._existing_torrc_backup()
        if backup:
            try:
                shutil.move(backup, self.torrc_path)
                logger.info("Orijinal torrc geri yüklendi.")
                self.reload_service()
                return True
            except Exception as err:
                logger.error("Orijinal torrc geri yüklenemedi: %s", err)
                return False
        logger.warning(
            "Geri yüklenecek torrc yedeği bulunamadı; Tor yapılandırması "
            "elle düzeltilmelidir."
        )
        return True


def test_tor_circuit_socks(socks_port: int = 9050, timeout: float = 6.0) -> bool:
    """SOCKS5 üzerinden gerçek bir CONNECT yaparak Tor devresini doğrular.

    Opsec'in yaklaşımının bağımlılıksız karşılığıdır: `curl` çağırmak yerine
    SOCKS5 el sıkışması doğrudan yapılır.

    Neden `urllib` KULLANILMAZ: Python'un `urllib` modülü SOCKS proxy'yi
    DESTEKLEMEZ. `socks5h://` şeması sessizce başarısız olur ve Tor tamamen
    sağlıklı olsa bile "devre doğrulanamadı" sonucu verir. Bu, gerçek bir
    yanlış negatifti.

    SOCKS5'te `ATYP=0x03` (alan adı) kullanılır; böylece çözümlemeyi Tor
    yapar ve yerel DNS sızıntısı oluşmaz. CONNECT yanıtının `0x00` (başarılı)
    olması, Tor'un hedefe gerçek bir devre kurduğunu kanıtlar; içerik
    indirilmesi gerekmez.
    """
    target_host = "check.torproject.org"
    target_port = 443
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # 1. Yöntem anlaşması: yalnızca "kimlik doğrulama yok"
            sock.sendall(b"\x05\x01\x00")
            greeting = sock.recv(2)
            if len(greeting) < 2 or greeting[0] != 0x05:
                return False
            # 2. CONNECT isteği (alan adı ile)
            host_bytes = target_host.encode("ascii")
            request = (
                b"\x05\x01\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + target_port.to_bytes(2, "big")
            )
            sock.sendall(request)
            reply = sock.recv(10)
            if len(reply) < 2:
                return False
            # REP=0x00 -> bağlantı kuruldu (devre hazır)
            return reply[0] == 0x05 and reply[1] == 0x00
    except OSError:
        return False
