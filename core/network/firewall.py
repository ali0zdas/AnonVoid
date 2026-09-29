"""AnonVoid - nftables/iptables Güvenlik Duvarı ve Şeffaf Yönlendirme Motoru.

Bu modül; sistemin tüm TCP trafiğini Tor TransPort'a (9040), DNS trafiğini Tor DNSPort'a (5300)
yönlendirir. .onion sanal IP aralığını (10.192.0.0/10) LAN istisnalarından ayrıştırır,
DoH sunucularını engeller, giden tüm IPv6 trafiğini düşürür ve Tor UID döngüsünü (loop) engeller.
"""

from __future__ import annotations

try:
    import pwd
except ImportError:
    pwd = None  # type: ignore
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.config import cfg_port

logger = logging.getLogger("FPCleanerFirewall")

# Tor .onion Sanal IP Alanı (10.192.0.0/10) Hariç Tutularak Bölünen LAN Ağları
TOR_LOCAL_NETS: List[str] = [
    "127.0.0.0/8",
    "10.0.0.0/9",        # 10.0.0.0 – 10.127.255.255 (Gerçek LAN)
    "10.128.0.0/10",     # 10.128.0.0 – 10.191.255.255 (Gerçek LAN)
    # DİKKAT: 10.192.0.0/10 .onion sanal IP bloğudur, bilerek buraya eklenmez!
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",    # Link-local
]

# DoH (DNS-over-HTTPS) Baypas Engelleme IP Listesi (Port 443 DROP)
DOH_SERVER_IPS: List[str] = [
    "1.1.1.1", "1.0.0.1",                # Cloudflare
    "8.8.8.8", "8.8.4.4",                # Google
    "9.9.9.9", "149.112.112.112",        # Quad9
    "94.140.14.14", "94.140.15.15",      # AdGuard
    "208.67.222.222", "208.67.220.220",  # OpenDNS
]

TABLE_NAME = "fp-cleaner"


def get_tor_uid() -> Optional[int]:
    """Sistemdeki Tor kullanıcısının UID değerini tespit eder."""
    tor_user_candidates = ["debian-tor", "tor", "toranon", "_tor"]
    for username in tor_user_candidates:
        try:
            if hasattr(pwd, "getpwnam"):
                return pwd.getpwnam(username).pw_uid
        except (KeyError, Exception):
            pass
    return None


def is_nftables_available() -> bool:
    """Sistemde nftables (nft) aracının bulunup bulunmadığını kontrol eder."""
    return shutil.which("nft") is not None


class FirewallEngine:
    """nftables ve iptables güvenlik duvarı kural orkestratörü."""

    def __init__(self, table_name: str = TABLE_NAME) -> None:
        self.table_name = table_name
        self.use_nft = is_nftables_available()

    def build_nft_ruleset(
        self,
        trans_port: int = 9040,
        dns_port: int = 5300,
        tor_uid: Optional[int] = None,
        block_doh: bool = True,
        drop_ipv6: bool = True,
    ) -> str:
        """nftables için yapılandırılmış atomik kural kümesi oluşturur."""
        trans_port = cfg_port(trans_port, 9040)
        dns_port = cfg_port(dns_port, 5300)

        lines: List[str] = [
            f"table inet {self.table_name} {{",
            "    chain output {",
            "        type filter hook output priority 0; policy accept;",
        ]

        # 1. Tor sürecinin kendi trafiğini kabul et (Döngü önleme)
        if tor_uid is not None:
            lines.append(f"        meta skuid {tor_uid} accept")

        # 2. DoH bloklama (Port 443 doğrudan IP bağlantılarını düşür)
        if block_doh:
            doh_set = ", ".join(DOH_SERVER_IPS)
            lines.append(f"        ip daddr {{ {doh_set} }} tcp dport 443 drop")
            lines.append(f"        ip daddr {{ {doh_set} }} udp dport 443 drop")

        # 3. Yerel LAN istisnaları (Onion hariç)
        lan_set = ", ".join(TOR_LOCAL_NETS)
        lines.append(f"        ip daddr {{ {lan_set} }} accept")

        lines.extend([
            "    }",
            "    chain nat_output {",
            "        type nat hook output priority -100; policy accept;",
        ])

        # 4. NAT zincirinde Tor sürecini muaf tut
        if tor_uid is not None:
            lines.append(f"        meta skuid {tor_uid} return")

        # 5. LAN istisnalarını NAT'tan döndür
        lines.append(f"        ip daddr {{ {lan_set} }} return")

        # 6. DNS trafiğini Tor DNSPort'a yönlendir (UDP & TCP 53)
        lines.append(f"        udp dport 53 redirect to :{dns_port}")
        lines.append(f"        tcp dport 53 redirect to :{dns_port}")

        # 7. Tüm giden TCP trafiğini Tor TransPort'a yönlendir
        lines.append(f"        meta l4proto tcp redirect to :{trans_port}")

        lines.append("    }")
        lines.append("}")

        # 8. IPv6 Sızıntı Koruması (Tüm giden IPv6 trafiğini düşür)
        if drop_ipv6:
            lines.extend([
                f"table ip6 {self.table_name} {{",
                "    chain output {",
                "        type filter hook output priority 0; policy drop;",
                "    }",
                "}",
            ])

        return "\n".join(lines) + "\n"

    def apply_rules(
        self,
        trans_port: int = 9040,
        dns_port: int = 5300,
        tor_uid: Optional[int] = None,
        block_doh: bool = True,
        drop_ipv6: bool = True,
    ) -> bool:
        """Güvenlik duvarı kurallarını sisteme uygular."""
        if tor_uid is None:
            tor_uid = get_tor_uid()

        # Önce eski tabloları temizle
        self.flush_rules()

        if self.use_nft:
            ruleset = self.build_nft_ruleset(
                trans_port=trans_port,
                dns_port=dns_port,
                tor_uid=tor_uid,
                block_doh=block_doh,
                drop_ipv6=drop_ipv6,
            )
            try:
                proc = subprocess.run(
                    ["nft", "-f", "-"],
                    input=ruleset,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                if proc.returncode == 0:
                    logger.info("nftables güvenlik duvarı kuralları başarıyla uygulandı.")
                    return True
                logger.error("nftables kuralları yüklenemedi: %s", proc.stderr.strip())
            except Exception as err:
                logger.error("nftables çalıştırılırken hata: %s", err)

        # Fallback: iptables
        return self._apply_iptables_fallback(trans_port, dns_port, tor_uid, block_doh, drop_ipv6)

    def _apply_iptables_fallback(
        self,
        trans_port: int,
        dns_port: int,
        tor_uid: Optional[int],
        block_doh: bool,
        drop_ipv6: bool,
    ) -> bool:
        """iptables ve ip6tables fallback mekanizması."""
        logger.info("iptables fallback kuralları uygulanıyor...")
        try:
            # IPv6 kapatma
            if drop_ipv6:
                subprocess.run(["ip6tables", "-P", "OUTPUT", "DROP"], timeout=5, check=False)

            # DoH engelleme
            if block_doh:
                for ip in DOH_SERVER_IPS:
                    subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP"], timeout=5, check=False)

            # Tor UID muafiyeti
            if tor_uid is not None:
                subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(tor_uid), "-j", "RETURN"], timeout=5, check=False)

            # LAN istisnaları
            for net in TOR_LOCAL_NETS:
                subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"], timeout=5, check=False)

            # DNS yönlendirme
            subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port)], timeout=5, check=False)
            subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(dns_port)], timeout=5, check=False)

            # TCP yönlendirme
            subprocess.run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(trans_port)], timeout=5, check=False)

            logger.info("iptables fallback kuralları uygulandı.")
            return True
        except Exception as err:
            logger.error("iptables fallback başarısız: %s", err)
            return False

    def flush_rules(self) -> bool:
        """Tüm güvenlik duvarı kurallarını ve yönlendirmeleri sıfırlar."""
        logger.info("Güvenlik duvarı kuralları temizleniyor (flush)...")
        # 1. nftables tablolarını sil
        for family in ["inet", "ip6"]:
            try:
                subprocess.run(
                    ["nft", "delete", "table", family, self.table_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except Exception:
                pass

        # 2. iptables temizliği
        try:
            subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        except Exception:
            pass

        return True

    def is_active(self) -> bool:
        """Güvenlik duvarının aktif olup olmadığını denetler."""
        if self.use_nft:
            try:
                proc = subprocess.run(
                    ["nft", "list", "table", "inet", self.table_name],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                return proc.returncode == 0
            except Exception:
                return False
        return False
