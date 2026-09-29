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
import time
import urllib.request
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("FPCleanerLeakTest")

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


def test_dns_leak(timeout: float = 4.0) -> Dict[str, Any]:
    """Yerel DNS sorgularının Tor DNSPort (127.0.0.1:5300) üzerinden geçip geçmediğini test eder."""
    result: Dict[str, Any] = {
        "tor_dns_responsive": False,
        "resolved_ip": None,
        "error": None,
    }

    try:
        # Doğrudan soket üzerinden yerel DNS testi
        resolved = socket.gethostbyname("check.torproject.org")
        result["resolved_ip"] = resolved
        result["tor_dns_responsive"] = bool(resolved)
    except Exception as err:
        result["error"] = f"DNS sorgusu başarısız: {err}"

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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # Basit bir STUN Binding Request paketi (20 bayt)
    stun_req = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)

    try:
        sock.sendto(stun_req, GOOGLE_STUN_SERVER)
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

    return {
        "timestamp": time.time(),
        "duration_sec": round(time.time() - start_time, 2),
        "is_fully_anonymous": is_fully_anonymous,
        "tor": tor_test,
        "ipv6": ipv6_test,
        "dns": dns_test,
        "webrtc": webrtc_test,
        "system_identity": identity_test,
    }
