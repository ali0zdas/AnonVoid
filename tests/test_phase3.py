"""AnonVoid - Faz 3 Ağ ve Gizlilik Çekirdeği Birim Testleri.

Bu dosya; nftables .onion sanal IP ayrımını, DoH engellemesini, IPv6 drop kurallarını,
torrc şablonlamasını, MAC sahteleme mantığını, sızıntı test paketini ve panik butonunu test eder.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.network.dnscrypt import DNSCryptManager, get_active_network_interfaces
from core.network.firewall import TOR_LOCAL_NETS, FirewallEngine
from core.network.leak_test import (
    get_system_identity_exposure,
    run_full_leak_test,
    test_ipv6_leak,
    test_webrtc_udp_leak,
)
from core.network.mac import generate_random_mac, get_physical_interfaces
from core.network.panic import execute_panic_nuke
from core.network.tor import TorManager, renew_tor_circuit


class TestFirewallEngine(unittest.TestCase):
    """core/network/firewall.py testleri."""

    def setUp(self):
        self.fw = FirewallEngine(table_name="fp-test")

    def test_onion_address_space_isolation(self):
        """10.192.0.0/10 .onion sanal IP alanının bilerek LAN istisnalarından hariç tutulduğunu test eder."""
        self.assertNotIn("10.192.0.0/10", TOR_LOCAL_NETS)
        self.assertIn("10.0.0.0/9", TOR_LOCAL_NETS)
        self.assertIn("10.128.0.0/10", TOR_LOCAL_NETS)

    def test_build_nft_ruleset_structure(self):
        """Üretilen nftables kural kümesinin güvenlik gereksinimlerini karşıladığını test eder."""
        ruleset = self.fw.build_nft_ruleset(
            trans_port=9040,
            dns_port=5300,
            tor_uid=110,
            block_doh=True,
            drop_ipv6=True,
        )

        # Temel kontroller
        self.assertIn("table inet fp-test", ruleset)
        self.assertIn("table ip6 fp-test", ruleset)
        self.assertIn("policy drop", ruleset)  # IPv6 drop
        self.assertIn("redirect to :9040", ruleset)  # TransPort
        self.assertIn("redirect to :5300", ruleset)  # DNSPort
        self.assertIn("meta skuid 110 accept", ruleset)  # Tor UID muafiyeti
        self.assertIn("1.1.1.1", ruleset)  # DoH engeli
        self.assertIn("8.8.8.8", ruleset)  # DoH engeli


class TestTorManager(unittest.TestCase):
    """core/network/tor.py testleri."""

    def test_generate_torrc_content(self):
        """torrc şablonunun doğru direktifleri ürettiğini test eder."""
        mgr = TorManager()
        content = mgr.generate_torrc_content(trans_port=9040, dns_port=5300, socks_port=9050, control_port=9051)

        self.assertIn("TransPort 9040", content)
        self.assertIn("DNSPort 5300", content)
        self.assertIn("ControlPort 9051", content)
        self.assertIn("VirtualAddrNetworkIPv4 10.192.0.0/10", content)
        self.assertIn("AutomapHostsOnResolve 1", content)
        self.assertIn("AvoidDiskWrites 1", content)

    def test_renew_circuit_offline_safety(self):
        """Tor çalışmıyorken devre yenilemenin kontrollü hata döndüğünü test eder."""
        # Olmayan port
        res = renew_tor_circuit(control_port=59999)
        self.assertFalse(res["success"])
        self.assertIn("bağlanılamadı", res["message"])


class TestMACRandomizer(unittest.TestCase):
    """core/network/mac.py testleri."""

    def test_generate_random_mac(self):
        """Üretilen MAC adresinin geçerli ve yerel unicast olduğunu test eder."""
        mac_regex = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
        for _ in range(20):
            mac = generate_random_mac()
            self.assertTrue(mac_regex.match(mac))

            # İlk bayt kontrolü (Unicast ve locally-administered: 0x02 biti 1, 0x01 biti 0)
            first_byte = int(mac.split(":")[0], 16)
            self.assertEqual(first_byte & 0x01, 0, "Multicast bit kapalı olmalıdır")
            self.assertEqual(first_byte & 0x02, 2, "Locally administered bit açık olmalıdır")


class TestLeakTestSuite(unittest.TestCase):
    """core/network/leak_test.py testleri."""

    def test_system_identity_exposure(self):
        """Hostname ve saat dilimi kontrollerini test eder."""
        ident = get_system_identity_exposure()
        self.assertIn("hostname", ident)
        self.assertIn("timezone", ident)
        self.assertIn("is_utc", ident)

    def test_ipv6_leak_safe(self):
        """IPv6 sızıntı denetiminin güvenle sonuç ürettiğini test eder."""
        res = test_ipv6_leak(timeout=1.0)
        self.assertIn("leak_detected", res)
        self.assertIn("message", res)

    def test_webrtc_udp_leak_safe(self):
        """WebRTC STUN testinin güvenle sonuç ürettiğini test eder."""
        res = test_webrtc_udp_leak(timeout=1.0)
        self.assertIn("leak_detected", res)

    def test_full_leak_test_report_structure(self):
        """Tam sızıntı testi raporunun tüm alanları içerdiğini test eder."""
        report = run_full_leak_test()
        self.assertIn("timestamp", report)
        self.assertIn("is_fully_anonymous", report)
        self.assertIn("tor", report)
        self.assertIn("ipv6", report)
        self.assertIn("dns", report)
        self.assertIn("webrtc", report)
        self.assertIn("system_identity", report)


class TestPanicModule(unittest.TestCase):
    """core/network/panic.py testleri."""

    def test_execute_panic_nuke_safe(self):
        """Panik butonu yürütümünün güvenli şekilde sonuçlandığını test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Fake shell file
            bash_file = os.path.join(fake_home, ".bash_history")
            with open(bash_file, "w") as f:
                f.write("gizli_komut_123\n")

            report = execute_panic_nuke(
                target_home=fake_home,
                wipe_shell=True,
                clear_ram=True,
                shutdown_system=False,  # Test ortamında sistemi kapatma
            )

            self.assertTrue(report["nuked"])
            self.assertTrue(report["shell_wiped"])
            self.assertFalse(os.path.exists(bash_file))


if __name__ == "__main__":
    unittest.main()
