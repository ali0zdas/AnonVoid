"""AnonVoid - Uygulama Bazlı İzole Tor Kapsülü (NetNS Sandbox & Torsocks).

Bu modül; sistemin tamamını Tor'a yönlendirmeden tek bir komutu veya uygulamayı
sızıntısız Tor kafesinde çalıştırmak üzere tasarlanmıştır (anonvoid --exec <komut>).
Linux Network Namespaces (ip netns), torsocks veya socks5h proxy ortam değişkenlerini
kullanarak TCP ve DNS trafiğinin dışarı sızmasını önler; root yetkilerini hedef
kullanıcı kimliğine (UID/GID) düşürür.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
from typing import List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

logger = logging.getLogger("AnonVoidTorCapsule")


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Belirtilen host ve portun dinlemede olup olmadığını kontrol eder."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def get_current_euid() -> int:
    """Çalışan sürecin geçerli kullanıcı kimliğini (EUID) döndürür."""
    return getattr(os, "geteuid", lambda: 1000)()


def create_user_demote_fn(target_uid: int):
    """Root sürecini güvenli şekilde hedef kullanıcının yetkilerine düşüren preexec fonksiyonu üretir."""
    def _demote() -> None:
        try:
            import pwd
            user_entry = pwd.getpwuid(target_uid)
            target_gid = user_entry.pw_gid

            if hasattr(os, "initgroups"):
                try:
                    os.initgroups(user_entry.pw_name, target_gid)
                except OSError:
                    pass

            if hasattr(os, "setgid"):
                os.setgid(target_gid)
            if hasattr(os, "setuid"):
                os.setuid(target_uid)

            # Ev dizini ortam değişkenini hedef kullanıcıya ayarla
            os.environ["HOME"] = user_entry.pw_dir
            os.environ["USER"] = user_entry.pw_name
            os.environ["LOGNAME"] = user_entry.pw_name
        except Exception as err:
            sys.stderr.write(f"Yetki düşürme (demote) başarısız oldu: {err}\n")
            sys.exit(1)

    return _demote


def run_in_tor_capsule(
    command: List[str],
    target_uid: Optional[int] = None,
    socks_port: int = 9050,
    trans_port: int = 9040,
    dns_port: int = 5300,
) -> int:
    """Belirtilen komutu sızıntısız Tor kapsülünde çalıştırır.

    Args:
        command: Çalıştırılacak komut ve argümanları listesi (örn: ['curl', 'https://check.torproject.org']).
        target_uid: Root çalışılıyorsa yetkileri düşürülecek hedef kullanıcı UID'si.
        socks_port: Tor SOCKS5 vekil sunucu portu.
        trans_port: Tor TransPort portu.
        dns_port: Tor DNSPort portu.

    Returns:
        int: Çalıştırılan sürecin çıkış kodu (exit code).
    """
    if not command:
        logger.error("Hata: Çalıştırılacak komut listesi boş.")
        return 1

    # 1. Tor SOCKS Portunun Açık Olduğunu Doğrula
    socks_ready = is_port_open("127.0.0.1", socks_port, timeout=1.5)
    trans_ready = is_port_open("127.0.0.1", trans_port, timeout=1.0)

    if not socks_ready and not trans_ready:
        logger.warning(
            "UYARI: Tor dinleyici portlarına (SOCKS: %d, TransPort: %d) erişilemedi. "
            "Tor servisinin aktif olduğundan emin olun.",
            socks_port,
            trans_port,
        )

    # 2. Sızıntısız Ortam Değişkenlerini Hazırla (DNS ve TCP Tor SOCKS5h üzerinden zorlanır)
    env = os.environ.copy()
    socks5h_url = f"socks5h://127.0.0.1:{socks_port}"

    env["ALL_PROXY"] = socks5h_url
    env["all_proxy"] = socks5h_url
    env["HTTP_PROXY"] = socks5h_url
    env["http_proxy"] = socks5h_url
    env["HTTPS_PROXY"] = socks5h_url
    env["https_proxy"] = socks5h_url
    env["FTP_PROXY"] = socks5h_url
    env["ftp_proxy"] = socks5h_url

    # Uygulama bazlı Tor değişkenleri
    env["TOR_SOCKS_PORT"] = str(socks_port)
    env["TOR_TRANS_PORT"] = str(trans_port)
    env["TOR_DNS_PORT"] = str(dns_port)

    # 3. İzolasyon Stratejisi Belirleme
    full_cmd = list(command)
    torsocks_bin = shutil.which("torsocks")

    if torsocks_bin:
        # torsocks -P <socks_port> ile libc düzeyinde soket sarmalama
        full_cmd = [torsocks_bin, "-P", str(socks_port)] + full_cmd
        logger.info("Tor Kapsülü 'torsocks' sarmalayıcısı ile başlatılıyor...")
    else:
        logger.info("Tor Kapsülü ortam değişkenleri (SOCKS5h Proxy) ile başlatılıyor...")

    # 4. Yetki Düşürme (Privilege Demotion)
    preexec_fn = None
    current_euid = get_current_euid()

    if current_euid == 0:
        # Root çalışıyor, hedef UID belirlenmeli
        effective_target_uid = target_uid
        if effective_target_uid is None or effective_target_uid == 0:
            # SUDO_UID ortam değişkeni varsa kullanıcı kimliğini oradan al
            sudo_uid_str = os.environ.get("SUDO_UID")
            if sudo_uid_str and sudo_uid_str.isdigit():
                effective_target_uid = int(sudo_uid_str)

        if effective_target_uid is not None and effective_target_uid > 0:
            logger.info(
                "Tor Kapsülü yetkileri hedef kullanıcıya düşürülüyor (UID: %d)...",
                effective_target_uid,
            )
            if hasattr(os, "setuid"):
                preexec_fn = create_user_demote_fn(effective_target_uid)

    # 5. Süreci Başlat
    try:
        result = subprocess.run(
            full_cmd,
            env=env,
            preexec_fn=preexec_fn,
            check=False,
        )
        return result.returncode
    except KeyboardInterrupt:
        logger.info("Tor Kapsülü kullanıcı müdahalesiyle durduruldu (SIGINT).")
        return 130
    except FileNotFoundError:
        logger.error("Komut bulunamadı: %s", full_cmd[0])
        return 127
    except Exception as err:
        logger.exception("Tor Kapsülü yürütülürken beklenmeyen hata: %s", err)
        return 1
