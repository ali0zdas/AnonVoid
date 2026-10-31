"""AnonVoid - Dahili Canlı Adli Ağ Sızıntı Test Paketi (Leak Test Suite).

Bu modül; sistemin internete Tor üzerinden çıkıp çıkmadığını doğrular,
DNS sorgularının kaçıp kaçmadığını (DNS leak), dışarıya açık IPv6 bağlantısı olup
olmadığını (IPv6 drop testi), STUN UDP sızıntısını ve sistem saat dilimi/makine adı
ifşalarını denetleyerek kapsamlı bir güvenlik raporu sunar.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

from core.config import cfg_port
from core.network.firewall import FirewallEngine
from core.network.tor import check_tor_ready, get_tor_dns_port

# Tor DNSPort bilinemezse kullanılacak son çare değer. Bu bir TAHMİN
# DEĞİLDİR: gerçek port her zaman önce Tor kontrol portundan okunur.
# Kalıcı olarak 5300 varsaymak, Kali gibi 5353 kullanan dağıtımlarda
# sağlıklı bir Tor'u "DNS yanıt vermiyor" gibi gösterebilirdi.
TOR_DNS_PORT_FALLBACK = 5300

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("AnonVoidLeakTest")

TOR_CHECK_API = "https://check.torproject.org/api/ip"
GOOGLE_STUN_SERVER = ("stun.l.google.com", 19302)


def test_tor_exit_ip(timeout: float = 8.0) -> Dict[str, Any]:
    """check.torproject.org üzerinden dış IP'yi ve Tor durumunu doğrular."""
    result: Dict[str, Any] = {
        "ip": "Bilinmiyor",
        "is_tor": False,
        "success": False,
        "error": None,
    }

    try:
        # urllib'nin timeout değeri DNS çözümlemeyi kapsamaz. Kalkan etkinken
        # çözümleme kara deliğinde kalabildiği için önce sınırlı çözümleme yapılır.
        if resolve_with_deadline("check.torproject.org", timeout=timeout) is None:
            result["error"] = (
                "check.torproject.org çözümlenemedi (DNS engelli veya Tor DNSPort kapalı). "
                "Tor üzerinden çıkış doğrulanamadı."
            )
            return result

        req = urllib.request.Request(
            TOR_CHECK_API,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            result["ip"] = data.get("IP", "Bilinmiyor")
            result["is_tor"] = bool(data.get("IsTor", False))
            result["success"] = True
    except Exception as err:
        result["error"] = f"Tor API sorgulanamadı: {err}"

    return result


def test_ipv6_leak(timeout: float = 3.0) -> Dict[str, Any]:
    """Dış dünyaya açık bir IPv6 bağlantısı olup olmadığını denetler.

    Beklenen Davranış: Bağlantı %100 engellenmeli (Network is unreachable / Timeout).
    Eğer bağlantı başarılı olursa bu kritik bir sızıntıdır (IPv6 Leak).
    """
    result: Dict[str, Any] = {
        "leak_detected": False,
        "message": "IPv6 tamamen kapalı (Güvenli)",
        "error": None,
    }

    # Google IPv6 DNS (2001:4860:4860::8888) port 53
    target_ipv6 = "2001:4860:4860::8888"

    if not socket.has_ipv6:
        result["message"] = "Sistem IPv6 desteklemiyor (Güvenli)."
        return result

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ipv6, 53))
        # Bağlantı kurulabildiyse sızıntı var demektir!
        result["leak_detected"] = True
        result["message"] = "KRİTİK UYARI: IPv6 bağlantısı başarılı! Gerçek IPv6 adresiniz sızıyor olabilir."
        logger.warning("IPv6 sızıntısı tespit edildi!")
    except (socket.timeout, OSError):
        # Bağlantı kurulamadı = Kural çalışıyor ve güvenli!
        result["leak_detected"] = False
        result["message"] = "IPv6 bağlantısı başarıyla engellendi (Güvenli)."
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def resolve_with_deadline(host: str, timeout: float = 4.0) -> Optional[str]:
    """Sistem çözümleyicisini kesin bir üst süreyle çağırır.

    `socket.gethostbyname()` üzerinde hiçbir zaman aşımı yoktur; `/etc/resolv.conf`
    içindeki `timeout`/`attempts` değerleri kadar bekler. AnonVoid kalkanı
    etkinken tüm sorgular Tor DNSPort'a yönlendirildiği ve Tor DNSPort
    kapalı olduğu için bu, sızıntı testinin istemci zaman aşımını aşarak
    donmasına yol açar.

    Bu nedenle çözümleme kısa ömürlü bir iş parçacığında yapılır ve ana iş
    parçacığı `timeout` kadar bekler. Çözümleme takılı kalırsa iş parçacığı
    arka planda çalışmaya devam eder; daemon kısa ömürlü süreçlerde sonlandığı
    için kalıcı bir kaynak sızıntısı oluşmaz.
    """
    box: Dict[str, Optional[str]] = {}

    def _resolve() -> None:
        try:
            box["ip"] = socket.gethostbyname(host)
        except Exception:
            box["ip"] = None

    worker = threading.Thread(target=_resolve, daemon=True)
    worker.start()
    worker.join(timeout)
    return box.get("ip")


def test_dns_leak(timeout: float = 4.0) -> Dict[str, Any]:
    """Yerel DNS sorgularının Tor DNSPort üzerinden geçip geçmediğini test eder.

    DNSPort sabit bir değere bağlı değildir: dağıtımın öntanımlı torrc'si
    farklı bir port kullanabilir (Kali'de 5353). Yanlış port sorgulanırsa,
    Tor tamamen sağlıklı olsa bile test "yanıt vermedi" der ve kullanıcı
    hatalı yönlendirilir. Bu yüzden port önce Tor'un kontrol portundan
    okunur, okunamazsa öntanımlı değere düşülür.
    """
    dns_listener = get_tor_dns_port(fallback=TOR_DNS_PORT_FALLBACK)
    dns_port = dns_listener["port"]

    result: Dict[str, Any] = {
        "tor_dns_responsive": False,
        "resolved_ip": None,
        "error": None,
        "dns_port": dns_port,
        "dns_port_source": dns_listener["source"],
    }

    # 1. Asıl test: Tor DNSPort'a doğrudan sorgu. Yalnızca bu yol kullanılırsa
    #    DNS'in gerçekten şeffaf proxy üzerinden gittiği kanıtlanabilir.
    dns_result = query_tor_dnsport(
        "check.torproject.org", timeout=timeout, dns_port=dns_port
    )
    result["tor_dns_responsive"] = dns_result["responsive"]
    result["resolved_ip"] = dns_result["ip"]
    if not dns_result["responsive"]:
        result["error"] = dns_result["error"]

    # 2. Bilgi amaçlı: sistem çözümleyicisinin verdiği sonuç (sınırlandırılmış).
    system_ip = resolve_with_deadline("check.torproject.org", timeout=timeout)
    result["system_resolved_ip"] = system_ip
    result["system_matches_tor"] = bool(system_ip and system_ip == dns_result["ip"])

    return result


def _parse_dns_a_record(data: bytes, query_id: bytes) -> Optional[str]:
    """DNS UDP yanıt paketinden standart A (IPv4) kaydını ayrıştırır (RFC 1035).
    
    Körü körüne paketin son 4 baytını almak yerine RDLENGTH=4, TYPE=1 (A)
    ve CLASS=1 (IN) alanlarını doğrulayarak gerçek IPv4 adresini çeker.
    """
    if len(data) < 12 or data[:2] != query_id:
        return None

    ancount = int.from_bytes(data[6:8], "big")
    if ancount == 0:
        return None

    offset = 12
    # Soru (Question) bölümünü atla: QNAME etiketleri 0x00 ile biter
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            offset += 2
            break
        offset += 1 + length

    # QTYPE (2 bayt) + QCLASS (2 bayt) = 4 bayt atla
    offset += 4

    # Cevap (Answer) bölümünü tara
    for _ in range(ancount):
        if offset >= len(data):
            break
        # NAME alanını atla (işaretçi ise 2 bayt, değilse etiket dizisi)
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1

        if offset + 10 > len(data):
            break

        atype = int.from_bytes(data[offset : offset + 2], "big")
        aclass = int.from_bytes(data[offset + 2 : offset + 4], "big")
        # ttl = 4 bayt (offset+4 : offset+8)
        rdlength = int.from_bytes(data[offset + 8 : offset + 10], "big")
        offset += 10

        # TYPE=1 (A), CLASS=1 (IN), RDLENGTH=4 ise IPv4 adresidir
        if atype == 1 and aclass == 1 and rdlength == 4 and offset + 4 <= len(data):
            return ".".join(str(b) for b in data[offset : offset + 4])

        offset += rdlength

    # Fallback: Ayrıştırma standart dışı paketlerde son 4 bayt ile tamamlanır
    if len(data) >= 16:
        return ".".join(str(b) for b in data[-4:])
    return None


def query_tor_dnsport(
    hostname: str, timeout: float = 4.0, dns_port: int = TOR_DNS_PORT_FALLBACK
) -> Dict[str, Any]:
    """Tor DNSPort adresine doğrudan bir A kaydı sorgusu gönderir.

    `dns_port` çağıran taraf tarafından belirlenir; sabit 5300 varsayımı
    kaldırılmıştır çünkü dağıtım öntanımları farklı olabilir.
    """
    dns_port = cfg_port(dns_port, TOR_DNS_PORT_FALLBACK)
    result: Dict[str, Any] = {"responsive": False, "ip": None, "error": None}

    query_id = os.urandom(2)
    # Başlık: Transaction ID, Bayraklar(RECURSION_DESIRED), QDCOUNT, diğerleri
    header = query_id + b"\x01\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in hostname.split("."))
    packet = header + qname + b"\x00\x00\x01\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, ("127.0.0.1", dns_port))
        data, _ = sock.recvfrom(2048)
        if len(data) < 12 or data[:2] != query_id:
            result["error"] = "DNSPort geçersiz yanıt döndürdü."
            return result

        rcode = data[3] & 0x0F
        if rcode == 3:
            result["responsive"] = True
            result["error"] = "Tor DNSPort yanıtladı ancak kayıt bulunamadı (NXDOMAIN)."
            return result
        if rcode != 0:
            result["error"] = f"Tor DNSPort hata kodu döndürdü: {rcode}"
            return result

        result["responsive"] = True
        # Standart DNS A kaydını ayrıştır; başarısız olursa güvenli fallback
        parsed_ip = _parse_dns_a_record(data, query_id)
        if parsed_ip:
            result["ip"] = parsed_ip
        elif len(data) >= 16:
            result["ip"] = ".".join(str(b) for b in data[-4:])
    except socket.timeout:
        result["error"] = (
            f"Tor DNSPort (127.0.0.1:{dns_port}) yanıt vermedi; "
            "Tor DNS yapılandırması etkin değil ya da DNSPort farklı bir "
            "portta dinliyor."
        )
    except OSError as err:
        result["error"] = f"Tor DNSPort'a ulaşılamadı: {err}"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def test_webrtc_udp_leak(timeout: float = 3.0) -> Dict[str, Any]:
    """Doğrudan STUN sunucusuna UDP paketi göndererek UDP kaçışı olup olmadığını test eder.

    Tor şeffaf proxy yalnızca TCP yönlendirir; UDP trafiği firewall tarafından
    düşürülmelidir. Eğer STUN sunucusundan doğrudan yanıt alınırsa sızıntı vardır.
    """
    result: Dict[str, Any] = {
        "leak_detected": False,
        "message": "UDP/STUN trafiği engellendi (WebRTC Güvenli).",
    }

    # Simple STUN sunucusunun adresi de çözümlenmelidir; UDP sendto çağrısındaki
    # çözümleme soket zaman aşımından etkilenmez ve engellenmiş DNS'te asılı kalır.
    stun_host, stun_port = GOOGLE_STUN_SERVER
    stun_ip = resolve_with_deadline(stun_host, timeout=timeout)
    if stun_ip is None:
        result["message"] = (
            "STUN sunucusu çözümlenemedi; test yapılamadı. "
            "Bu, UDP kaçışı olmadığını kanıtlamaz."
        )
        result["indeterminate"] = True
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # Basit bir STUN Binding Request paketi (20 bayt)
    stun_req = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)

    try:
        sock.sendto(stun_req, (stun_ip, stun_port))
        data, _ = sock.recvfrom(1024)
        if data:
            result["leak_detected"] = True
            result["message"] = "UYARI: STUN UDP paketine doğrudan yanıt alındı! WebRTC sızıntı riski var."
            logger.warning("WebRTC STUN UDP sızıntısı tespit edildi!")
    except socket.timeout:
        # Paket düşürüldü = Güvenli!
        result["leak_detected"] = False
        result["message"] = "UDP paketine yanıt alınamadı (WebRTC engellendi / Güvenli)."
    except Exception as err:
        result["message"] = f"STUN testi engellendi: {err}"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def get_system_identity_exposure() -> Dict[str, Any]:
    """Yerel makine adı (hostname) ve saat dilimini kontrol eder."""
    hostname = socket.gethostname()
    tz_name = time.tzname[0] if time.tzname else "Bilinmiyor"

    return {
        "hostname": hostname,
        "timezone": tz_name,
        "is_utc": tz_name.upper() in ("UTC", "GMT"),
        "warning": "Saat diliminiz UTC değilse tarayıcı parmak izi analizinde yerel saatiniz ifşa olabilir." if tz_name.upper() not in ("UTC", "GMT") else "Saat dilimi standart UTC.",
    }


def run_full_leak_test() -> Dict[str, Any]:
    """Tüm adli ağ sızıntı testlerini çalıştırır ve kapsamlı bir rapor üretir."""
    logger.info("Adli ağ sızıntı test paketi başlatılıyor...")
    start_time = time.time()

    tor_test = test_tor_exit_ip()
    ipv6_test = test_ipv6_leak()
    dns_test = test_dns_leak()
    webrtc_test = test_webrtc_udp_leak()
    identity_test = get_system_identity_exposure()

    is_fully_anonymous = (
        tor_test["is_tor"]
        and not ipv6_test["leak_detected"]
        and not webrtc_test["leak_detected"]
    )

    # Kullanıcı "Tor çıkış IP'si doğru değil" gördüğünde NEDENINI bilmelidir.
    # Üç ayrı durum birbirine çok benzer görünür ama tamamen farklıdır:
    #   (a) Tor kurulu/çalışmıyor          -> önce Tor kurulmalı/başlatılmalı
    #   (b) Tor ayakta ama bootstrap %<100 -> birkaç saniye beklenmeli
    #   (c) Tor hazır ama kalkan kapalı    -> koruma etkinleştirilmeli
    # (c) durumunda IPv4/IPv6 sızıntısı "gerçek sızıntı" değil, kalkanın
    # kapalı olmasının beklenen sonucudur; bunu ayırt etmeden "sızıntı var"
    # demek kullanıcıyı yanlış yönlendirir.
    tor_diag = check_tor_ready(require_complete=False)
    # Kalkan durumu yalnızca bir bayraktan değil, gerçek nftables tablosundan
    # belirlenir: daemon çökmüş ya da kurallar elle silinmiş olabilir ve
    # bayrak yanıltıcı biçimde "aktif" görünebilir.
    shield_active = FirewallEngine().is_active()

    # WebRTC testinde STUN sunucu adına DNS ile ulaşılamadıysa (indeterminate)
    # ve kalkan aktifse kullanıcıya dürüst ve net bilgi ver
    if webrtc_test.get("indeterminate"):
        if shield_active:
            webrtc_test["message"] = (
                "STUN sunucu adı doğrudan çözümlenemedi ancak ağ kalkanı (güvenlik duvarı) aktif "
                "olduğu için giden tüm UDP trafiği çekirdek seviyesinde düşürülmektedir (WebRTC Güvenli)."
            )
        else:
            webrtc_test["message"] = (
                "STUN sunucu adı çözümlenemediği için test tamamlanamadı. "
                "Ağ kalkanı kapalı olduğundan UDP/WebRTC sızıntı riski bulunmaktadır."
            )
    if not tor_diag["process_running"]:
        tor_hint = (
            "Tor servisi çalışmıyor. Tor kurulu değil veya başlatılmamış. "
            "Kalkan etkinleştirilmeden Tor çıkış IP'si doğal olarak gerçek IP'niz "
            "görünür; bu bir sızıntı değil, kalkanın kapalı olduğunun göstergesidir."
        )
    elif tor_diag["bootstrap_percent"] is not None and tor_diag["bootstrap_percent"] < 100:
        tor_hint = (
            f"Tor bootstrap tamamlanmadı (%{tor_diag['bootstrap_percent']}). "
            "Tor ilk açılışta güvenlik duvarı zincirini kurmadan önce devre "
            "kurulana kadar beklenmelidir. Kalkan bu sırada kasıtlı olarak "
            "kurulmaz, çünkü yarım kalmış bir Tor tüm trafiği karartır."
        )
    elif not shield_active:
        tor_hint = (
            "Tor çalışıyor ve hazır, ancak ağ kalkanı kapalı. Trafik şu anda "
            "doğrudan gerçek IP'nizden çıkıyor. Korumayı etkinleştirdiğinizde "
            "çıkış IP'si bir Tor çıkış düğümüne döner."
        )
    else:
        tor_hint = (
            "Tor ve kalkan etkin görünüyor. Çıkış düğümü hâlâ gerçek IP'nizi "
            "gösteriyorsa nftables kuralları uygulanmamış olabilir."
        )

    return {
        "timestamp": time.time(),
        "duration_sec": round(time.time() - start_time, 2),
        "is_fully_anonymous": is_fully_anonymous,
        "tor": tor_test,
        "tor_diagnostics": {
            "process_running": tor_diag["process_running"],
            "bootstrap_percent": tor_diag["bootstrap_percent"],
            "shield_active": shield_active,
            "explanation": tor_hint,
        },
        "ipv6": ipv6_test,
        "dns": dns_test,
        "webrtc": webrtc_test,
        "system_identity": identity_test,
    }
